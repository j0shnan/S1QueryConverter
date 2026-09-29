#!/usr/bin/env python3
"""
s1ql_convert.py

Shared conversion engine for translating SentinelOne S1QL v1 (Deep Visibility)
queries into S1QL v2 (Event Search / PowerQuery) syntax.

Imported by both S1QueryConverter_Single.py and S1QueryConverter_Multiple.py
so the two front-ends can never drift out of sync on the actual conversion
logic.

Design notes (see project discussion for full derivation):

  * Field names and operator keywords are matched only OUTSIDE of quoted
    string literals. Quoted literals are pulled out into placeholders before
    any mapping/rewriting happens, and restored (with the correct escaping
    for their context) at the very end. This is what prevents short mapping
    keys like "In"/"Name"/"Contains" from mangling string contents.

  * Field names and operators live in two SEPARATE tables. Several v1
    operators (StartsWith, EndsWith, Is Empty, Does Not Contain, Not In,
    between) are not 1:1 token substitutions -- they change the SHAPE of the
    predicate (need the field name, need anchors, need a NOT-wrapper, need
    to be split into two comparisons). Those are handled as rewrite rules,
    not dict lookups.

  * Two escaping pipelines, chosen per-literal by which operator ends up
    governing it:
      - PLAIN  (contains / in / equality): backslash -> \\\\, forward
        slash -> \\/. Verified against the "known good" sample queries.
      - REGEX  (matches, from an already-regex v1 RegExp source): double
        every literal backslash, nothing else. Verified against three
        independent examples (2 from SentinelOne's own docs, 1 from a
        validated sample query) that all show this exact behavior --
        including the "quadruple backslash" case for a literal directory
        separator, which is just two backslashes (regex-escaped) each
        independently doubled.
      - REGEX_FROM_PLAIN (matches, from StartsWith/EndsWith, whose v1 value
        is a plain string, not yet a regex at all): standard regex-escape
        of every metacharacter, then the same doubling rule on top. This
        reduces to the same quadruple-backslash result for literal
        backslashes, which is a nice internal consistency check.

  * Quoting is adaptive: default to double quotes (matches every validated
    sample). If a literal contains an embedded double-quote but no
    embedded single-quote, switch that one literal to single quotes
    instead, sidestepping the collision without introducing single quotes
    everywhere (PowerShell content commonly contains single quotes of its
    own, so always-single-quoting would trade one collision problem for a
    more common one). If a literal contains BOTH quote characters, that's
    genuinely unresolvable automatically -- this is flagged as a warning
    for the caller to act on (Single.py stops; Multiple.py flags the row
    and continues).
"""

import re
from dataclasses import dataclass, field as dc_field
from typing import Dict, List, Optional, Tuple


# ===========================================================================
# FIELD NAME MAPPING  (v1 identifier -> v2 dot-notation path)
#
# This is the original project's ~350-entry table, with operator words
# removed (they're handled as rewrite rules below) and the following
# corrections applied, per issue #1 on the repo:
#
#   - SrcProcImageCompletenessHints: restored to src.process.completeness.hints
#     (was being silently overwritten to src.process.image.size by a later
#     duplicate key -- a plain Python dict keeps only the last value for a
#     repeated key, so the second definition silently won the original file).
#   - SrcProcImageSize: added as its own correct entry (was missing --
#     its slot had been stolen by the collision above).
#   - driverProcessProcess -> renamed to driverDropperProcess (doubled word
#     in the original v1 key name; renamed to match the naming convention
#     of its siblings, e.g. driverInstallerProcess -> driver.installerProcess).
#   - GroupType -> tgt.file.signatureInvalidReason: the v1 key "GroupType"
#     doesn't correspond to this v2 field at all. Renamed to
#     TgtFileSignatureInvalidReason, which matches the naming convention of
#     its sibling TgtFileSignatureIsValid -> tgt.file.signature.isValid.
#   - OsSrcIndicatorGeneralCount -> corrected to osSrc.process.indicatorGeneralCount
#     (was osSrc.process.indicatorGeneral.count -- inconsistent with its
#     eleven sibling counters and with the src.* twin).
#   - LoginAccountDomain / LoginTgtDomainName / LogoutTgtDomainName:
#     restored from LoginAccountDoconvert_s1qlv1_to_s1qlv2 /
#     LoginTgtDoconvert_s1qlv1_to_s1qlv2Name /
#     LogoutTgtDoconvert_s1qlv1_to_s1qlv2Name -- an unbounded find/replace
#     of "main" -> "convert_s1qlv1_to_s1qlv2" during a refactor clobbered
#     "Domain" (which contains "main") inside these three keys/values.
#   - RegistryOwnerUserSID: the v1 key was accidentally written as
#     'registry.owner.userSid' (already v2-style dot notation), so it could
#     never match a v1 query. Renamed to match its sibling RegistryOwnerUser.
#
# NOTE ON "SrcProcImageSha" -> "src.process.image.sha1": this looks like a
# duplicate/truncated entry (SrcProcImageSha1 already covers this). Kept
# for input tolerance since removing it risks nothing (longest-match-first
# ordering means the correctly-named field always wins if both could
# apply), but flagged here in case it's actually a mistake worth removing.
# ===========================================================================

FIELD_MAP: Dict[str, str] = {
    # --- Event / process termination ---
    'ProcessTerminationExitCode': 'event.processtermination.exitCode',
    'ProcessTerminationSignal': 'event.processtermination.signal',
    'EventType': 'event.type',
    'eventType': 'event.type',
    'eventtype': 'event.type',

    # --- Kubernetes / container ---
    'ContainerId': 'k8sCluster.containerId',
    'ContainerImage': 'k8sCluster.containerImage',
    'ContainerImageId': 'k8sCluster.containerImage.id',
    'ContainerImageSha256': 'k8sCluster.containerImage.sha256',
    'ContainerLabels': 'k8sCluster.containerLabels',
    'ContainerName': 'k8sCluster.containerName',
    'K8sControllerLabels': 'k8sCluster.controllerLabels',
    'K8sControllerName': 'k8sCluster.controllerName',
    'K8sControllerType': 'k8sCluster.controllerType',
    'K8sClusterName': 'k8sCluster.name',
    'K8sNamespace': 'k8sCluster.namespace',
    'K8sNamespaceLabels': 'k8sCluster.namespaceLabels',
    'K8sNode': 'k8sCluster.nodeName',
    'K8sPodLabels': 'k8sCluster.podLabels',
    'K8sPodName': 'k8sCluster.podName',

    # --- OsSrc process ---
    'OsSrcProcActiveContentHash': 'osSrc.process.activeContent.hash',
    'OsSrcProcActiveContentFileId': 'osSrc.process.activeContent.id',
    'OsSrcProcActiveContentPath': 'osSrc.process.activeContent.path',
    'OsSrcProcActiveContentSignedStatus': 'osSrc.process.activeContent.signedStatus',
    'OsSrcProcActiveContentType': 'osSrc.process.activeContentType',
    'OsSrcChildProcCount': 'osSrc.process.childProcCount',
    'OsSrcProcCmdLine': 'osSrc.process.cmdline',
    'OsSrcCrossProcCount': 'osSrc.process.crossProcessCount',
    'OsSrcCrossProcDupRemoteProcHandleCount': 'osSrc.process.crossProcessDupRemoteProcessHandleCount',
    'OsSrcCrossProcDupThreadHandleCount': 'osSrc.process.crossProcessDupThreadHandleCount',
    'OsSrcCrossProcOpenProcCount': 'osSrc.process.crossProcessOpenProcessCount',
    'OsSrcCrossProcOutOfStorylineCount': 'osSrc.process.crossProcessOutOfStorylineCount',
    'OsSrcCrossProcThreadCreateCount': 'osSrc.process.crossProcessThreadCreateCount',
    'OsSrcProcDisplayName': 'osSrc.process.displayName',
    'OsSrcDnsCount': 'osSrc.process.dnsCount',
    'OsSrcProcBinaryisExecutable': 'osSrc.process.image.binaryIsExecutable',
    'OsSrcProcImageExtension': 'osSrc.process.image.extension',
    'OsSrcProcImageLocation': 'osSrc.process.image.location',
    'OsSrcProcImageMd5': 'osSrc.process.image.md5',
    'OsSrcProcImagePath': 'osSrc.process.image.path',
    'OsSrcProcImageSha1': 'osSrc.process.image.sha1',
    'OsSrcProcImageSha256': 'osSrc.process.image.sha256',
    'OsSrcProcImageSignatureIsValid': 'osSrc.process.image.signature.isValid',
    'OsSrcProcImageSize': 'osSrc.process.image.size',
    'OsSrcImageType': 'osSrc.process.image.type',
    'OsSrcProcImageUID': 'osSrc.process.image.uid',
    'OsSrcIndicatorBootConfigurationUpdateCount': 'osSrc.process.indicatorBootConfigurationUpdateCount',
    'OsSrcIndicatorEvasionCount': 'osSrc.process.indicatorEvasionCount',
    'OsSrcIndicatorExploitationCount': 'osSrc.process.indicatorExploitationCount',
    'OsSrcIndicatorGeneralCount': 'osSrc.process.indicatorGeneralCount',  # FIXED
    'OsSrcIndicatorInfostealerCount': 'osSrc.process.indicatorInfostealerCount',
    'OsSrcIndicatorInjectionCount': 'osSrc.process.indicatorInjectionCount',
    'OsSrcIndicatorPersistenceCount': 'osSrc.process.indicatorPersistenceCount',
    'OsSrcIndicatorPostExploitationCount': 'osSrc.process.indicatorPostExploitationCount',
    'OsSrcIndicatorRansomwareCount': 'osSrc.process.indicatorRansomwareCount',
    'OsSrcIndicatorReconnaissanceCount': 'osSrc.process.indicatorReconnaissanceCount',
    'OsSrcProcIntegrityLevel': 'osSrc.process.integrityLevel',
    'OsSrcProcIsNative64Bit': 'osSrc.process.isNative64Bit',
    'OsSrcProcIsRedirectCmdProcessor': 'osSrc.process.isRedirectCmdProcessor',
    'OsSrcProcIsStorylineRoot': 'osSrc.process.isStorylineRoot',
    'OsSrcModuleCount': 'osSrc.process.moduleCount',
    'OsSrcProcName': 'osSrc.process.name',
    'OsSrcNetConnCount': 'osSrc.process.netConnCount',
    'OsSrcNetConnInCount': 'osSrc.process.netConnInCount',
    'OsSrcNetConnOutCount': 'osSrc.process.netConnOutCount',
    'OsSrcProcParentActiveContentHash': 'osSrc.process.parent.activeContent.hash',
    'OsSrcProcParentActiveContentFileId': 'osSrc.process.parent.activeContent.id',
    'OsSrcProcParentActiveContentPath': 'osSrc.process.parent.activeContent.path',
    'OsSrcProcParentActiveContentSignedStatus': 'osSrc.process.parent.activeContent.signedStatus',
    'OsSrcProcParentActiveContentType': 'osSrc.process.parent.activeContentType',
    'OsSrcProcParentCmdLine': 'osSrc.process.parent.cmdline',
    'OsSrcProcParentDisplayName': 'osSrc.process.parent.displayName',
    'OsSrcProcParentImageBinaryIsExecutable': 'osSrc.process.parent.image.binaryIsExecutable',
    'OsSrcProcParentImageExtension': 'osSrc.process.parent.image.extension',
    'OsSrcProcParentImageLocation': 'osSrc.process.parent.image.location',
    'OsSrcProcParentImageMd5': 'osSrc.process.parent.image.md5',
    'OsSrcProcParentImagePath': 'osSrc.process.parent.image.path',
    'OsSrcProcParentImageSha1': 'osSrc.process.parent.image.sha1',
    'OsSrcProcParentImageSha256': 'osSrc.process.parent.image.sha256',
    'OsSrcProcParentImageSignatureIsValid': 'osSrc.process.parent.image.signature.isValid',
    'OsSrcProcParentImageSize': 'osSrc.process.parent.image.size',
    'OsSrcProcParentImageType': 'osSrc.process.parent.image.type',
    'OsSrcProcParentImageUID': 'osSrc.process.parent.image.uid',
    'OsSrcProcParentIntegrityLevel': 'osSrc.process.parent.integrityLevel',
    'OsSrcProcParentIsNative64Bit': 'osSrc.process.parent.isNative64Bit',
    'OsSrcProcParentIsRedirectCmdProcessor': 'osSrc.process.parent.isRedirectCmdProcessor',
    'OsSrcProcParentIsStorylineRoot': 'osSrc.process.parent.isStorylineRoot',
    'OsSrcProcParentName': 'osSrc.process.parent.name',
    'OsSrcProcParentPID': 'osSrc.process.parent.pid',
    'OsSrcProcParentPublisher': 'osSrc.process.parent.publisher',
    'OsSrcProcParentReasonSignatureInvalid': 'osSrc.process.parent.reasonSignatureInvalid',
    'OsSrcProcParentSessionId': 'osSrc.process.parent.sessionId',
    'OsSrcProcParentSignedStatus': 'osSrc.process.parent.signedStatus',
    'OsSrcProcParentStartTime': 'osSrc.process.parent.startTime',
    'OsSrcProcParentStorylineId': 'osSrc.process.parent.storyline.id',
    'OsSrcProcParentSubSystem': 'osSrc.process.parent.subsystem',
    'OsSrcProcParentUID': 'osSrc.process.parent.uid',
    'OsSrcProcParentUser': 'osSrc.process.parent.user',
    'OsSrcProcParentUserSID': 'osSrc.process.parent.userSid',
    'OsSrcProcPID': 'osSrc.process.pid',
    'OsSrcProcPublisher': 'osSrc.process.publisher',
    'OsSrcProcReasonSignatureInvalid': 'osSrc.process.reasonSignatureInvalid',
    'OsSrcRegistryChangeCount': 'osSrc.process.registryChangeCount',
    'OsSrcProcSessionId': 'osSrc.process.sessionId',
    'OsSrcProcSignedStatus': 'osSrc.process.signedStatus',
    'OsSrcProcStartTime': 'osSrc.process.startTime',
    'OsSrcProcStorylineId': 'osSrc.process.storyline.id',
    'OsSrcProcSubsystem': 'osSrc.process.subsystem',
    'OsSrcTgtFileCreationCount': 'osSrc.process.tgtFileCreationCount',
    'OsSrcTgtFileDeletionCount': 'osSrc.process.tgtFileDeletionCount',
    'OsSrcTgtFileModificationCount': 'osSrc.process.tgtFileModificationCount',
    'OsSrcProcUID': 'osSrc.process.uid',
    'OsSrcProcUser': 'osSrc.process.user',
    'OsSrcProcUserSID': 'osSrc.process.userSid',
    'OsSrcProcVerifiedStatus': 'osSrc.process.verifiedStatus',

    # --- Src process ---
    'SrcProcActiveContentHash': 'src.process.activeContent.hash',
    'SrcProcActiveContentFileId': 'src.process.activeContent.id',
    'SrcProcActiveContentPath': 'src.process.activeContent.path',
    'SrcProcActiveContentSignedStatus': 'src.process.activeContent.signedStatus',
    'SrcProcActiveContentType': 'src.process.activeContentType',
    'ChildProcCount': 'src.process.childProcCount',
    'SrcProcCmdLine': 'src.process.cmdline',
    'SrcProcImageCompletenessHints': 'src.process.completeness.hints',  # FIXED
    'CrossProcCount': 'src.process.crossProcessCount',
    'CrossProcDupRemoteProcHandleCount': 'src.process.crossProcessDupRemoteProcessHandleCount',
    'CrossProcDupThreadHandleCount': 'src.process.crossProcessDupThreadHandleCount',
    'CrossProcOpenProcCount': 'src.process.crossProcessOpenProcessCount',
    'CrossProcOutOfStorylineCount': 'src.process.crossProcessOutOfStorylineCount',
    'CrossProcThreadCreateCount': 'src.process.crossProcessThreadCreateCount',
    'SrcProcDisplayName': 'src.process.displayName',
    'DnsCount': 'src.process.dnsCount',
    'SrcProcEUserName': 'src.process.eUserName',
    'SrcProcEUserUid': 'src.process.eUserUid',
    'ExeModificationCount': 'src.process.exeModificationCount',
    'SrcProcImageExtension': 'src.process.image.extension',
    'SrcProcImageLocation': 'src.process.image.location',
    'SrcProcImageMd5': 'src.process.image.md5',
    'SrcProcImagePath': 'src.process.image.path',
    'SrcProcImageSha1': 'src.process.image.sha1',
    'SrcProcImageSha': 'src.process.image.sha1',  # NOTE: likely duplicate/truncated, kept for tolerance
    'SrcProcImageSha256': 'src.process.image.sha256',
    'SrcProcImageSize': 'src.process.image.size',  # FIXED (was missing)
    'SrcProcImageUID': 'src.process.image.uid',
    'SrcProcImageDescription': 'src.process.image.description',
    'SrcProcImageInternalName': 'src.process.image.internalName',
    'SrcProcImageOriginalFileName': 'src.process.image.originalFileName',
    'SrcProcImageProductName': 'src.process.image.productName',
    'SrcProcImageProductVersion': 'src.process.image.productVersion',
    'IndicatorBootConfigurationUpdateCount': 'src.process.indicatorBootConfigurationUpdateCount',
    'IndicatorEvasionCount': 'src.process.indicatorEvasionCount',
    'IndicatorExploitationCount': 'src.process.indicatorExploitationCount',
    'IndicatorGeneralCount': 'src.process.indicatorGeneralCount',
    'IndicatorInfostealerCount': 'src.process.indicatorInfostealerCount',
    'IndicatorInjectionCount': 'src.process.indicatorInjectionCount',
    'IndicatorPersistenceCount': 'src.process.indicatorPersistenceCount',
    'IndicatorPostExploitationCount': 'src.process.indicatorPostExploitationCount',
    'IndicatorRansomwareCount': 'src.process.indicatorRansomwareCount',
    'IndicatorReconnaissanceCount': 'src.process.indicatorReconnaissanceCount',
    'SrcProcIntegrityLevel': 'src.process.integrityLevel',
    'SrcProcIsNative64Bit': 'src.process.isNative64Bit',
    'SrcProcIsRedirectCmdProcessor': 'src.process.isRedirectCmdProcessor',
    'SrcProcIsStorylineRoot': 'src.process.isStorylineRoot',
    'SrcProcLUserName': 'src.process.lUserName',
    'SrcProcLUserUid': 'src.process.lUserUid',
    'ModelChildProcessCount': 'src.process.modelChildProcessCount',
    'ModuleCount': 'src.process.moduleCount',
    'SrcProcName': 'src.process.name',
    'NetConnCount': 'src.process.netConnCount',
    'NetConnInCount': 'src.process.netConnInCount',
    'NetConnOutCount': 'src.process.netConnOutCount',
    'SrcProcParentActiveContentHash': 'src.process.parent.activeContent.hash',
    'SrcProcParentActiveContentFileId': 'src.process.parent.activeContent.id',
    'SrcProcParentActiveContentPath': 'src.process.parent.activeContent.path',
    'SrcProcParentActiveContentSignedStatus': 'src.process.parent.activeContent.signedStatus',
    'SrcProcParentActiveContentType': 'src.process.parent.activeContentType',
    'SrcProcParentCmdLine': 'src.process.parent.cmdline',
    'SrcProcParentDisplayName': 'src.process.parent.displayName',
    'SrcProcParentEUserName': 'src.process.parent.eUserName',
    'SrcProcParentEUserUid': 'src.process.parent.eUserUid',
    'SrcProcParentImageBinaryIsExecutable': 'src.process.parent.image.binaryIsExecutable',
    'SrcProcParentImageExtension': 'src.process.parent.image.extension',
    'SrcProcParentImageLocation': 'src.process.parent.image.location',
    'SrcProcParentImageMd5': 'src.process.parent.image.md5',
    'SrcProcParentImagePath': 'src.process.parent.image.path',
    'SrcProcParentImageSha1': 'src.process.parent.image.sha1',
    'SrcProcParentImageSha256': 'src.process.parent.image.sha256',
    'SrcProcParentImageSignatureIsValid': 'src.process.parent.image.signature.isValid',
    'SrcProcParentImageSize': 'src.process.parent.image.size',
    'SrcProcParentImageType': 'src.process.parent.image.type',
    'SrcProcParentImageUID': 'src.process.parent.image.uid',
    'SrcProcParentIntegrityLevel': 'src.process.parent.integrityLevel',
    'SrcProcParentIsNative64Bit': 'src.process.parent.isNative64Bit',
    'SrcProcParentIsRedirectCmdProcessor': 'src.process.parent.isRedirectCmdProcessor',
    'SrcProcParentIsStorylineRoot': 'src.process.parent.isStorylineRoot',
    'SrcProcParentLUserName': 'src.process.parent.lUserName',
    'SrcProcParentLUserUid': 'src.process.parent.lUserUid',
    'SrcProcParentName': 'src.process.parent.name',
    'SrcProcParentPID': 'src.process.parent.pid',
    'SrcProcParentPublisher': 'src.process.parent.publisher',
    'SrcProcParentRUserName': 'src.process.parent.rUserName',
    'SrcProcParentRUserUid': 'src.process.parent.rUserUid',
    'SrcProcParentReasonSignatureInvalid': 'src.process.parent.reasonSignatureInvalid',
    'SrcProcParentSessionId': 'src.process.parent.sessionId',
    'SrcProcParentSignedStatus': 'src.process.parent.signedStatus',
    'SrcProcParentStartTime': 'src.process.parent.startTime',
    'SrcProcParentStorylineId': 'src.process.parent.storyline.id',
    'SrcProcParentUID': 'src.process.parent.uid',
    'SrcProcParentUser': 'src.process.parent.user',
    'SrcProcParentUserSID': 'src.process.parent.userSid',
    'SrcProcPID': 'src.process.pid',
    'SrcProcPublisher': 'src.process.publisher',
    'SrcProcRUserName': 'src.process.rUserName',
    'SrcProcRUserUid': 'src.process.rUserUid',
    'SrcProcReasonSignatureInvalid': 'src.process.reasonSignatureInvalid',
    'RegistryChangeCount': 'src.process.registryChangeCount',
    'SrcProcRPID': 'src.process.rpid',
    'SrcProcSessionId': 'src.process.sessionId',
    'SrcProcSignedStatus': 'src.process.signedStatus',
    'SrcProcStartTime': 'src.process.startTime',
    'SrcProcStorylineId': 'src.process.storyline.id',
    'SrcProcSubsystem': 'src.process.subsystem',
    'TgtFileCreationCount': 'src.process.tgtFileCreationCount',
    'TgtFileDeletionCount': 'src.process.tgtFileDeletionCount',
    'TgtFileModificationCount': 'src.process.tgtFileModificationCount',
    'SrcProcTid': 'src.process.tid',
    'SrcProcUID': 'src.process.uid',
    'SrcProcUser': 'src.process.user',
    'SrcProcUserSID': 'src.process.userSid',
    'SrcProcVerifiedStatus': 'src.process.verifiedStatus',

    # --- Task / ECS ---
    'TaskCluster': 'task.cluster',
    'EcsVersion': 'task.ecsVersion',
    'TaskServiceArn': 'task.serviceArn',
    'TaskServiceName': 'task.serviceName',
    'TaskTags': 'task.tags',
    'TaskArn': 'task.taskArn',
    'TaskAvailabilityZone': 'task.taskAvailabilityZone',
    'TaskDefinitionArn': 'task.taskDefinitionArn',
    'TaskDefinitionFamily': 'task.taskDefinitionFamily',
    'TaskDefinitionRevision': 'task.taskDefinitionRevision',
    'TaskName': 'task.name',
    'TaskPath': 'task.path',
    'TaskTriggerType': 'task.triggerType',

    # --- Tgt file / process ---
    'TgtFileConvictedBy': 'tgt.file.convictedBy',
    'TgtFileSha1': 'tgt.file.sha1',
    'TgtProcAccessRights': 'tgt.process.accessRights',
    'TgtProcActiveContentHash': 'tgt.process.activeContent.hash',
    'TgtProcActiveContentFileId': 'tgt.process.activeContent.id',
    'TgtProcActiveContentPath': 'tgt.process.activeContent.path',
    'TgtProcActiveContentSignedStatus': 'tgt.process.activeContent.signedStatus',
    'TgtProcActiveContentType': 'tgt.process.activeContentType',
    'TgtProcCmdLine': 'tgt.process.cmdline',
    'TgtProcImageCompletenessHints': 'tgt.process.completeness.hints',
    'TgtProcDisplayName': 'tgt.process.displayName',
    'TgtProcEUserName': 'tgt.process.eUserName',
    'TgtProcEUserUid': 'tgt.process.eUserUid',
    'TgtProcBinaryisExecutable': 'tgt.process.image.binaryIsExecutable',
    'TgtProcImageExtension': 'tgt.process.image.extension',
    'TgtProcImageMd5': 'tgt.process.image.md5',
    'TgtProcImagePath': 'tgt.process.image.path',
    'TgtProcImageSha1': 'tgt.process.image.sha1',
    'TgtProcImageSha256': 'tgt.process.image.sha256',
    'TgtProcImageSize': 'tgt.process.image.size',
    'TgtProcImageUID': 'tgt.process.image.uid',
    'TgtProcIntegrityLevel': 'tgt.process.integrityLevel',
    'TgtProcIsNative64Bit': 'tgt.process.isNative64Bit',
    'TgtProcIsRedirectCmdProcessor': 'tgt.process.isRedirectCmdProcessor',
    'TgtProcIsStorylineRoot': 'tgt.process.isStorylineRoot',
    'TgtProcLUserName': 'tgt.process.lUserName',
    'tgtProcLuserUid': 'tgt.process.lUserUid',
    'TgtProcName': 'tgt.process.name',
    'TgtProcParentImageLocation': 'tgt.process.parent.image.location',
    'TgtProcParentImageType': 'tgt.process.parent.image.type',
    'TgtProcPID': 'tgt.process.pid',
    'TgtProcPublisher': 'tgt.process.publisher',
    'TgtProcRUserName': 'tgt.process.rUserName',
    'TgtProcRUserUid': 'tgt.process.rUserUid',
    'TgtProcReasonSignatureInvalid': 'tgt.process.reasonSignatureInvalid',
    'TgtProcRelation': 'tgt.process.relation',
    'TgtProcSessionId': 'tgt.process.sessionId',
    'TgtProcSignedStatus': 'tgt.process.signedStatus',
    'TgtProcStartTime': 'tgt.process.startTime',
    'TgtProcStorylineId': 'tgt.process.storyline.id',
    'TgtProcSubsystem': 'tgt.process.subsystem',
    'TgtProcUID': 'tgt.process.uid',
    'TgtProcUser': 'tgt.process.user',
    'TgtProcUserSID': 'tgt.process.userSid',
    'TgtProcVerifiedStatus': 'tgt.process.verifiedStatus',

    # --- Command scripts ---
    'SrcProcCmdScriptApplicationName': 'cmdScript.applicationName',
    'SrcProcCmdScript': 'cmdScript.content',
    'SrcProcCmdScriptIsComplete': 'cmdScript.isComplete',
    'SrcProcCmdScriptOriginalSize': 'cmdScript.originalSize',
    'SrcProcCmdScriptSha256': 'cmdScript.sha256',

    # --- DNS ---
    'DnsRequest': 'event.dns.request',
    'DnsResponse': 'event.dns.response',
    'DnsStatus': 'event.dns.status',

    # --- Driver ---
    'DriverCertificateThumbprint': 'driver.certificate.thumbprint',
    'DriverCertificateThumbprintAlgorithm': 'driver.certificate.thumbprintAlgorithm',
    'DriverIsLoadedBeforeMonitor': 'driver.isLoadedBeforeMonitor',
    'DriverLoadStartType': 'driver.startType',
    'DriverLoadVerdict': 'driver.loadVerdict',
    'DriverPeSha1': 'driver.peSha1',
    'DriverPeSha256': 'driver.peSha256',
    'driverFileVersion': 'driver.fileVersion',
    'driverId': 'driver.id',
    'driverInstallerProcess': 'driver.installerProcess',
    'driverDropperProcess': 'driver.dropperProcess',  # FIXED (was driverProcessProcess)
    'driverRegistryKeyPath': 'driver.registryKeyPath',
    'driverServiceName': 'driver.serviceName',
    'driverSig1Publisher': 'driver.sig.1.publisher',
    'driverSig1SpcSpOpusInfo': 'driver.sig.1.spcSpOpusInfo',
    'driverSig1TimeStamp': 'driver.sig.1.timestamp',
    'driverSig1Valid': 'driver.sig.1.valid',
    'driverSig2Publisher': 'driver.sig.2.publisher',
    'driverSig2SpcSpOpusInfo': 'driver.sig.2.spcSpOpusInfo',
    'driverSig2TimeStamp': 'driver.sig.2.timestamp',
    'driverSig2Valid': 'driver.sig.2.valid',
    'driverSig3Publisher': 'driver.sig.3.publisher',
    'driverSig3SpcSpOpusInfo': 'driver.sig.3.spcSpOpusInfo',
    'driverSig3TimeStamp': 'driver.sig.3.timestamp',
    'driverSig3Valid': 'driver.sig.3.valid',
    'driverSig4Publisher': 'driver.sig.4.publisher',
    'driverSig4SpcSpOpusInfo': 'driver.sig.4.spcSpOpusInfo',
    'driverSig4TimeStamp': 'driver.sig.4.timestamp',
    'driverSig4Valid': 'driver.sig.4.valid',
    'driverSig5Publisher': 'driver.sig.5.publisher',
    'driverSig5SpcSpOpusInfo': 'driver.sig.5.spcSpOpusInfo',
    'driverSig5TimeStamp': 'driver.sig.5.timestamp',
    'driverSig5Valid': 'driver.sig.5.valid',
    'driverSigCount': 'driver.sig.count',

    # --- Files ---
    'TgtFileCreatedAt': 'tgt.file.creationTime',
    'TgtFileDescription': 'tgt.file.description',
    'TgtFileExtension': 'tgt.file.extension',
    'TgtFileId': 'tgt.file.id',
    'TgtFileInternalName': 'tgt.file.internalName',
    'TgtFileIsDirectory': 'tgt.file.isDirectory',
    'TgtFileIsExecutable': 'tgt.file.isExecutable',
    'TgtFileIsKernelModule': 'tgt.file.isKernelModule',
    'TgtFileIsSigned': 'tgt.file.isSigned',
    'TgtFileLocation': 'tgt.file.location',
    'TgtFileMd5': 'tgt.file.md5',
    'TgtFileModifiedAt': 'tgt.file.modificationTime',
    'TgtFileName': 'tgt.file.name',
    'TgtFileOldMd5': 'tgt.file.oldMd5',
    'TgtFileOldPath': 'tgt.file.oldPath',
    'TgtFileOldSha1': 'tgt.file.oldSha1',
    'TgtFileOldSha256': 'tgt.file.oldSha256',
    'TgtFileOriginalFileName': 'tgt.file.originalFileName',
    'TgtFileOwnerName': 'tgt.file.owner.name',
    'TgtFileOwnerUserSID': 'tgt.file.owner.userSid',
    'TgtFilePath': 'tgt.file.path',
    'TgtFileProductName': 'tgt.file.productName',
    'TgtFileProductVersion': 'tgt.file.productVersion',
    'TgtFilePublisher': 'tgt.file.publisher',
    'TgtFileSha256': 'tgt.file.sha256',
    'TgtFileSignatureIsValid': 'tgt.file.signature.isValid',
    'TgtFileSignatureInvalidReason': 'tgt.file.signatureInvalidReason',  # FIXED (was GroupType)
    'TgtFileSize': 'tgt.file.size',
    'TgtFileType': 'tgt.file.type',

    # --- Indicators ---
    'IndicatorCategory': 'indicator.category',
    'IndicatorDescription': 'indicator.description',
    'IndicatorIdentifier': 'indicator.identifier',
    'IndicatorMetadata': 'indicator.metadata',
    'IndicatorName': 'indicator.name',

    # --- Logins / logouts ---
    'LoginAccountDomain': 'event.login.accountDomain',  # FIXED
    'LoginAccountName': 'event.login.accountName',
    'LoginAccountSID': 'event.login.accountSid',
    'LoginsBaseType': 'event.login.baseType',
    'LoginFailureReason': 'event.login.failureReason',
    'LoginIsAdministratorEquivalent': 'event.login.isAdministratorEquivalent',
    'LoginIsSuccessful': 'event.login.loginIsSuccessful',
    'LoginSessionID': 'event.login.sessionId',
    'LoginTgtDomainName': 'event.login.tgt.domainName',  # FIXED
    'LoginTgtUserName': 'event.login.tgt.user.name',
    'LoginTgtUserSID': 'event.login.tgt.userSid',
    'LoginType': 'event.login.type',
    'LoginsUserName': 'event.login.userName',
    'LogoutTgtDomainName': 'event.logout.tgt.domainName',  # FIXED
    'LogoutTgtUserName': 'event.logout.tgt.user.name',
    'LogoutTgtUserSID': 'event.logout.tgt.userSid',
    'LogoutType': 'event.logout.type',
    'SrcMachineIP': 'src.endpoint.ip.address',

    # --- Modules ---
    'ModuleCertificateExpirationDate': 'module.certificate.expirationdate',
    'ModuleCertificateThumbprint': 'module.certificate.thumbprint',
    'ModuleMd5': 'module.md5',
    'ModulePath': 'module.path',
    'ModuleSha1': 'module.sha1',
    'ModuleSignedStatus': 'module.signed.status',
    'ModuleSignerName': 'module.signer.name',

    # --- Network ---
    'DstIP': 'dst.ip.address',
    'DstPort': 'dst.port.number',
    'NetConnStatus': 'event.network.connectionStatus',
    'NetEventDirection': 'event.network.direction',
    'NetProtocolName': 'event.network.protocolName',
    'SrcIP': 'src.ip.address',
    'SrcPort': 'src.port.number',

    # --- Registry ---
    'RegistryExportPath': 'registry.export.path',
    'RegistryImportPath': 'registry.import.path',
    'RegistryKeyPath': 'registry.keyPath',
    'RegistryUID': 'registry.keyUid',
    'RegistryOldValue': 'registry.oldValue',
    'RegistryOldValueFullSize': 'registry.oldValueFullSize',
    'RegistryOldValueIsComplete': 'registry.oldValueIsComplete',
    'RegistryOldValueType': 'registry.oldValueType',
    'RegistryOwnerUser': 'registry.owner.user',
    'RegistryOwnerUserSID': 'registry.owner.userSid',  # FIXED
    'RegistrySecurityInfo': 'registry.security.info',
    'RegistryValue': 'registry.value',
    'RegistryValueFullSize': 'registry.valueFullSize',
    'RegistryValueIsComplete': 'registry.valueIsComplete',
    'RegistryValueType': 'registry.valueType',

    # --- URL ---
    'UrlAction': 'event.url.action',
    'UrlSource': 'event.url.source',
    'Url': 'url.address',

    # --- Shortcuts ---
    'FilePath': 'filepath',
    'Hash': 'hash',
    'IP': 'ip',
    'Md5': 'md5',
    'Name': 'name',
    'Sha1': 'sha1',
    'Sha256': 'sha256',
    'StorylineId': 'storylineid',
    'UID': 'uid',
    'UserName': 'username',
    'SiteName': 'site.name',
    'siteName': 'site.name',
    'Sitename': 'site.name',
    'EndpointOS': 'endpoint.os',
    'EndpointName': 'endpoint.name',
    'EndpointMachineType': 'endpoint.type',
}


# ===========================================================================
# Escaping helpers
# ===========================================================================

def double_backslashes(s: str) -> str:
    """Double every literal backslash character. This is the whole rule for
    translating an already-valid v1 regex (from RegExp) into v2's
    double-escaped 'matches' syntax. Verified against:
      - docs: uriPath matches '\\.png$'          (doubled from a single backslash-dot)
      - docs: registry.keyPath matches '\\.*\\VSS'
      - sample: cmdScript.content matches "Set-StrictMode\\s+-Version\\s+2"
      - sample: ...KDeploy\\.exe  (single backslash doubled)
      - sample: ...\\\\Device...  (v1's already-escaped "\\Device" -- 2
        backslashes -- each independently doubled to 4)
    """
    return s.replace('\\', '\\\\')


_LEADING_CI_FLAG_RE = re.compile(r'^\(\?i\)')


def strip_leading_case_insensitive_flag(v1_regex: str) -> str:
    """Strip a leading '(?i)' inline case-insensitive flag from a v1
    RegExp value. v2's `matches` is already case-insensitive by default
    ("Our regex is case-insensitive, so [A-Z] = [a-z]" -- Regular
    Expressions doc), so the flag is redundant there. Left in place, it
    isn't wrong, just dead weight sitting at the front of the pattern --
    since it has no backslash in it, double_backslashes() has no reason to
    touch it and it would otherwise pass straight through unchanged.

    This intentionally only strips '(?i)' when it's the first thing in the
    pattern, which is the standard idiom for a global case-insensitivity
    flag. It's the scoped version of the old tool's issue #8 (a blanket,
    unconditional `.replace('(?i)', '')` over the whole query text, which
    risked corrupting any literal that happened to contain those
    characters for an unrelated reason). Other inline-flag groups --
    '(?im)', '(?s)', a flag group appearing mid-pattern -- are left alone,
    since those combine behaviors beyond simple case-insensitivity that
    can't be safely assumed away.
    """
    return _LEADING_CI_FLAG_RE.sub('', v1_regex, count=1)


def regex_escape_literal(s: str) -> str:
    """Turn a PLAIN (non-regex) literal into a properly escaped v2 regex
    literal for the 'matches' operator: standard regex-escape every
    metacharacter so the literal matches itself, then apply the same
    doubling rule on top (since the result is fed straight into 'matches').
    Used for StartsWith / EndsWith, whose v1 value is a plain string, not
    yet a regex.

    Nicely, this reduces to the same quadruple-backslash result as
    double_backslashes() does for an already-escaped literal backslash in
    a RegExp source -- re.escape() turns one literal backslash into two
    (regex-level escaping), and double_backslashes() then doubles each of
    those, giving four. Same invariant, two different starting points.
    """
    return double_backslashes(re.escape(s))



def plain_escape_literal(s: str) -> str:
    """Escape a literal for a non-regex context (contains / in / equality).
    Verified against sample queries:
      - "C:\\Program Files\\..." -> "C:\\\\Program Files\\\\..."  (backslash doubled once)
      - "Microsoft.Network/virtualNetworks/subnets" -> ".../subnets" with
        each '/' escaped to '\\/'
    """
    escaped = s.replace('\\', '\\\\')
    escaped = escaped.replace('/', '\\/')
    return escaped


def quote_literal(escaped_content: str) -> Tuple[str, Optional[str]]:
    """Adaptively choose the quote delimiter for an already-escaped literal.
    Defaults to double quotes (matches every validated sample). Falls back
    to single quotes only when that avoids a collision (embedded double
    quote, no embedded single quote). Flags a warning when the literal
    contains both quote characters, since that can't be resolved
    automatically (matches the project README's documented "chicken and
    egg" case).
    """
    has_dq = '"' in escaped_content
    has_sq = "'" in escaped_content
    if not has_dq:
        return f'"{escaped_content}"', None
    if not has_sq:
        return f"'{escaped_content}'", None
    return f'"{escaped_content}"', 'quote_collision'


# ===========================================================================
# Result type
# ===========================================================================

@dataclass
class ConversionResult:
    output: str
    ok: bool
    warnings: List[str] = dc_field(default_factory=list)
    original: str = ""


# ===========================================================================
# Tokenizing / segmenting helpers
# ===========================================================================

_STRING_LITERAL_RE = re.compile(r'"((?:\\.|[^"\\])*)"')
_PLACEHOLDER_RE = re.compile(r'\x00(\d+)\x00')

# Literal-escaping modes a placeholder can be tagged with by the operator
# rewrite rules. Defaults to PLAIN if no rule claims it (e.g. plain
# '=' / '!=' / '>' / '<' comparisons, which need no special handling beyond
# ordinary literal escaping).
MODE_PLAIN = 'plain'
MODE_REGEX = 'regex'                 # already a v1 regex (from RegExp)
MODE_REGEX_FROM_PLAIN_START = 'regex_from_plain_start'   # StartsWith
MODE_REGEX_FROM_PLAIN_END = 'regex_from_plain_end'       # EndsWith


# ===========================================================================
# Operator rewrite rules
#
# Each rule is (name, compiled_regex, kind) where `kind` tells the
# replacement builder how to shape the output and how to tag any
# placeholder(s) captured in the argument. Rules are applied in order, via
# sequential re.sub passes over the placeholder-protected "flat" text. Order
# matters in a few specific spots (documented inline) to prevent a
# shorter/more-general pattern from misfiring on a longer/more-specific one
# that shares a prefix word (e.g. "Not In" must be handled before bare
# "In", or "Not" would get treated as a fake field name).
# ===========================================================================

_FIELD = r'([A-Za-z_][A-Za-z0-9_]*)'
_ARG = r'(\x00\d+\x00|\([^()]*\))'
_PH1 = r'(\x00\d+\x00)'

# kind values:
#   'is_not_empty', 'is_empty', 'is_true', 'is_false', 'exists'
#   'starts_anycase', 'ends_anycase', 'starts', 'ends'
#   'regexp'
#   'dnc_cis', 'dnc'            (Does Not Contain[CIS])
#   'not_in'
#   'in_contains_anycase', 'in_anycase', 'in_contains'
#   'contains_anycase', 'contains_cis', 'contains'
#   'in_bare'

_RULES = [
    ('is_not_empty',        rf'{_FIELD}\s+Is\s+Not\s+Empty\b',                         'is_not_empty'),
    ('is_empty',            rf'{_FIELD}\s+Is\s+Empty\b',                               'is_empty'),
    ('is_true',             rf'{_FIELD}\s+Is\s+True\b',                                'is_true'),
    ('is_false',            rf'{_FIELD}\s+Is\s+False\b',                               'is_false'),
    ('exists',              rf'{_FIELD}\s+Exists\b',                                   'exists'),

    ('starts_anycase',      rf'{_FIELD}\s+(?:StartsWith\s+Anycase|startswithCIS)\s+{_PH1}', 'starts_anycase'),
    ('ends_anycase',        rf'{_FIELD}\s+(?:EndsWith\s+Anycase|endswithCIS)\s+{_PH1}',      'ends_anycase'),
    ('starts',              rf'{_FIELD}\s+StartsWith\s+{_PH1}',                         'starts'),
    ('ends',                rf'{_FIELD}\s+EndsWith\s+{_PH1}',                           'ends'),

    ('regexp',              rf'{_FIELD}\s+RegExp\s+{_PH1}',                             'regexp'),

    ('dnc_cis',             rf'{_FIELD}\s+Does\s+Not\s+ContainCIS\s+{_ARG}',             'dnc_cis'),
    ('dnc',                 rf'{_FIELD}\s+Does\s+Not\s+Contain\s+{_ARG}',                'dnc'),

    # "Not In" must come before the bare "In" rule -- otherwise bare "In"
    # would treat the word "Not" as a fake field name.
    ('not_in',              rf'{_FIELD}\s+Not\s+In\s+{_ARG}',                           'not_in'),

    # Longest "In ..." phrases first, same reasoning.
    ('in_contains_anycase', rf'{_FIELD}\s+In\s+Contains\s+Anycase\s+{_ARG}',             'in_contains_anycase'),
    ('in_anycase',          rf'{_FIELD}\s+In\s+Anycase\s+{_ARG}',                        'in_anycase'),
    ('in_contains',         rf'{_FIELD}\s+In\s+Contains\s+{_ARG}',                       'in_contains'),

    ('contains_anycase',    rf'{_FIELD}\s+Contains\s+Anycase\s+{_ARG}',                  'contains_anycase'),
    ('contains_cis',        rf'{_FIELD}\s+ContainsCIS\s+{_ARG}',                         'contains_cis'),
    ('contains',            rf'{_FIELD}\s+Contains\s+{_ARG}',                            'contains'),

    # Bare "In" -- only matches when immediately followed by a parenthesized
    # list, which is how "In" is actually used per the S1QL 1.0 docs
    # (EventType In ("Process Creation")). This, plus running it dead last,
    # keeps it from colliding with any of the compound "In ..." phrases or
    # with ordinary identifiers.
    ('in_bare',             rf'{_FIELD}\s+In\s+(\([^()]*\))',                            'in_bare'),
]

_COMPILED_RULES = [(name, re.compile(pat, re.IGNORECASE), kind) for name, pat, kind in _RULES]

_BETWEEN_RE = re.compile(rf'{_FIELD}\s+between\b', re.IGNORECASE)


def _tag(literal_modes: Dict[int, str], blob: str, mode: str) -> None:
    for idx_str in _PLACEHOLDER_RE.findall(blob):
        literal_modes[int(idx_str)] = mode


def _apply_rewrite(kind: str, m: 're.Match', literal_modes: Dict[int, str]) -> str:
    field = m.group(1)

    if kind == 'is_not_empty':
        return f'{field} = *'
    if kind == 'is_empty':
        return f'!({field} = *)'
    if kind == 'is_true':
        return f'{field} = true'
    if kind == 'is_false':
        return f'{field} = false'
    if kind == 'exists':
        return f'{field} = *'

    if kind == 'starts_anycase':
        # Per the OperatorComparison doc table, startswith / startswith
        # anycase / startswithCIS all collapse to the SAME plain `matches`
        # -- there's no ":anycase" variant of matches in the docs at all.
        arg = m.group(2)
        _tag(literal_modes, arg, MODE_REGEX_FROM_PLAIN_START)
        return f'{field} matches {arg}'
    if kind == 'ends_anycase':
        arg = m.group(2)
        _tag(literal_modes, arg, MODE_REGEX_FROM_PLAIN_END)
        return f'{field} matches {arg}'
    if kind == 'starts':
        arg = m.group(2)
        _tag(literal_modes, arg, MODE_REGEX_FROM_PLAIN_START)
        return f'{field} matches {arg}'
    if kind == 'ends':
        arg = m.group(2)
        _tag(literal_modes, arg, MODE_REGEX_FROM_PLAIN_END)
        return f'{field} matches {arg}'

    if kind == 'regexp':
        arg = m.group(2)
        _tag(literal_modes, arg, MODE_REGEX)
        return f'{field} matches {arg}'

    if kind == 'dnc_cis':
        arg = m.group(2)
        _tag(literal_modes, arg, MODE_PLAIN)
        return f'NOT ({field} contains {arg})'
    if kind == 'dnc':
        arg = m.group(2)
        _tag(literal_modes, arg, MODE_PLAIN)
        return f'NOT ({field} contains:matchcase {arg})'

    if kind == 'not_in':
        arg = m.group(2)
        _tag(literal_modes, arg, MODE_PLAIN)
        return f'NOT ({field} in {arg})'

    if kind == 'in_contains_anycase':
        arg = m.group(2)
        _tag(literal_modes, arg, MODE_PLAIN)
        return f'{field} contains {arg}'
    if kind == 'in_anycase':
        arg = m.group(2)
        _tag(literal_modes, arg, MODE_PLAIN)
        return f'{field} in:anycase {arg}'
    if kind == 'in_contains':
        arg = m.group(2)
        _tag(literal_modes, arg, MODE_PLAIN)
        return f'{field} contains:matchcase {arg}'

    if kind == 'contains_anycase':
        # Text search is case-insensitive by default (Operators.md), so
        # plain `contains` already IS the anycase behavior -- confirmed by
        # both Sample 1 and Sample 2, which convert "Contains Anycase" to
        # bare `contains`, never `contains:anycase`.
        arg = m.group(2)
        _tag(literal_modes, arg, MODE_PLAIN)
        return f'{field} contains {arg}'
    if kind == 'contains_cis':
        arg = m.group(2)
        _tag(literal_modes, arg, MODE_PLAIN)
        return f'{field} contains {arg}'
    if kind == 'contains':
        arg = m.group(2)
        _tag(literal_modes, arg, MODE_PLAIN)
        return f'{field} contains {arg}'

    if kind == 'in_bare':
        arg = m.group(2)
        _tag(literal_modes, arg, MODE_PLAIN)
        return f'{field} in {arg}'

    raise AssertionError(f'unhandled rule kind: {kind}')


# ===========================================================================
# Field name mapping application
# ===========================================================================

def _build_field_regex(field_map: Dict[str, str]) -> re.Pattern:
    keys = sorted(field_map.keys(), key=len, reverse=True)
    pattern = '|'.join(r'\b' + re.escape(k) + r'\b' for k in keys)
    return re.compile(pattern)


_FIELD_REGEX = _build_field_regex(FIELD_MAP)


def _apply_field_map(text: str) -> str:
    return _FIELD_REGEX.sub(lambda m: FIELD_MAP[m.group(0)], text)


# ===========================================================================
# Paren balance check (warning-only -- does not silently mutate the query,
# since any imbalance at this point stems from the ORIGINAL v1 query, not
# from our own rewriting, and silently adding/stripping characters risks
# corrupting an already-malformed query in a new, harder-to-spot way).
# ===========================================================================

def _check_paren_balance(text: str) -> Optional[str]:
    depth = 0
    for ch in text:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth < 0:
                return 'Unbalanced parentheses: unexpected closing ")" found.'
    if depth > 0:
        return f'Unbalanced parentheses: {depth} unclosed "(" remaining.'
    return None


# ===========================================================================
# Main entry point
# ===========================================================================

def convert(v1_text: str) -> ConversionResult:
    """Convert a single S1QL v1 query string to S1QL v2.

    Returns a ConversionResult. `ok` is False when the query contains a
    literal with both an embedded double-quote and an embedded single-quote
    (the one case that can't be resolved automatically -- see module
    docstring / README's documented "chicken and egg" case). In that case
    `output` still contains a best-effort conversion, but the caller should
    treat it as needing manual review rather than presenting it as final.
    """
    warnings: List[str] = []
    original = v1_text

    # Step 1: pull out quoted string literals, protect them behind
    # placeholders so nothing downstream can mangle their contents or
    # mistake their contents for field names / operators.
    literals: List[str] = []

    def _stash(m: 're.Match') -> str:
        literals.append(m.group(1))
        return f'\x00{len(literals) - 1}\x00'

    flat = _STRING_LITERAL_RE.sub(_stash, v1_text)

    # Step 2: detect (but do not convert) 'between', which needs real v1
    # sample syntax to implement correctly rather than a guess.
    for bm in _BETWEEN_RE.finditer(flat):
        v1_field = bm.group(1)
        # Look up the v2 field name so the suggested manual fix matches the
        # actual output (field mapping runs at Step 4, after this warning is
        # generated, so we resolve it explicitly here).
        v2_field = FIELD_MAP.get(v1_field, v1_field)
        warnings.append(
            f'"{v1_field} between ..." was left unconverted -- "between" '
            f'needs manual conversion to "{v2_field} >= a AND {v2_field} <= b" '
            f'(exact v1 syntax for this operator was not available to verify against).'
        )

    # Step 3: operator rewrite passes, in order. Each pass also tags any
    # placeholder(s) it consumes with the escaping mode that governs them.
    literal_modes: Dict[int, str] = {}
    for name, regex, kind in _COMPILED_RULES:
        flat = regex.sub(lambda m, k=kind: _apply_rewrite(k, m, literal_modes), flat)

    # Step 4: field name mapping, on whatever plain identifier text remains.
    flat = _apply_field_map(flat)

    # Step 5: paren balance sanity check (warning only, no mutation).
    balance_warning = _check_paren_balance(flat)
    if balance_warning:
        warnings.append(balance_warning)

    # Step 6: restore literals, escaped + quoted per their tagged mode.
    quote_collision = False

    def _restore(m: 're.Match') -> str:
        nonlocal quote_collision
        idx = int(m.group(1))
        raw = literals[idx]
        mode = literal_modes.get(idx, MODE_PLAIN)

        if mode == MODE_PLAIN:
            escaped = plain_escape_literal(raw)
        elif mode == MODE_REGEX:
            escaped = double_backslashes(strip_leading_case_insensitive_flag(raw))
        elif mode == MODE_REGEX_FROM_PLAIN_START:
            escaped = '^' + regex_escape_literal(raw)
        elif mode == MODE_REGEX_FROM_PLAIN_END:
            escaped = regex_escape_literal(raw) + '$'
        else:
            escaped = plain_escape_literal(raw)

        quoted, quote_warning = quote_literal(escaped)
        if quote_warning == 'quote_collision':
            quote_collision = True
            warnings.append(
                f'Literal "{raw}" contains BOTH a double-quote and a '
                f'single-quote and could not be automatically re-quoted. '
                f'This needs to be resolved manually -- wrap the value '
                f'yourself with whichever quote character does not appear '
                f'in it, per the project README\'s documented limitation.'
            )
        return quoted

    final = _PLACEHOLDER_RE.sub(_restore, flat)

    # `ok` reflects whether the output can be trusted as a complete,
    # unattended conversion. ANY warning -- an unresolvable quote
    # collision, unbalanced parens, or a "between" clause left
    # unconverted -- means a human needs to look at this one before it's
    # used, even though `output` still contains a best-effort result.
    ok = len(warnings) == 0
    return ConversionResult(output=final, ok=ok, warnings=warnings, original=original)
