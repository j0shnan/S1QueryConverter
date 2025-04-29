#!/usr/bin/env python3
##########################################################################################
## Convert a singular WL query from SentinelOneQL 1.0 to 2.0 from a file on disk
## Ex. usage: 
## python3 S1QueryConverter_Single.py query.txt
##########################################################################################
import re
import argparse


##### Import Query from a file. Replace this later with import from csv/xlsx
parser = argparse.ArgumentParser(
    description="Replace multiple text fields in a file based on a s1QLv1_to_s1QLv2_field_mapping."
)
parser.add_argument("input_file", help="Path to the input text file")
parser.add_argument("-o", "--output", help="Path to the output file (optional)")
args = parser.parse_args()

# Take in an text file to translate.
try:
    with open(args.input_file, "r", encoding="utf-8") as f:
        input_text = f.read()
except FileNotFoundError:
    exit(f"Error: File '{args.input_file}' not found.")

##### Define logical f() for replacement mapping:
##### Build RE pattern && sub from the mapping
def replace_mapped_query_fields_regex(text, s1QLv1_to_s1QLv2_field_mapping):
    pattern = re.compile("|".join(re.escape(key) for key in s1QLv1_to_s1QLv2_field_mapping.keys()))
    return pattern.sub(lambda match: s1QLv1_to_s1QLv2_field_mapping[match.group(0)], text)

##### F() to fix DNC issues in long strings enclosed by () 
def transform_query_containing_bad_DoesNotContain_pattern_0(text: str) -> str:
    ##### Provide RE to catch situations with DNC clauses 
    bad_DoesNotContain_pattern_0 = re.compile(r'(?i)AND\s*\(\s*(.*?)\s*\)', re.IGNORECASE | re.DOTALL)
    split_pattern_containing_multiple_DoesNotContain = re.compile(r'(?i)\bAND\b', re.IGNORECASE)
    def replacer(m: re.Match) -> str:
        #### Start making groups of clauses
        inner = m.group(1)
        #### Split the groups
        parts = split_pattern_containing_multiple_DoesNotContain.split(inner)
        #### strip out any empty fragments
        clauses = [p.strip() for p in parts if p.strip()]
        #### splits / groups  rebuild as AND NOT ( clause )
        return ' '.join(f'AND NOT ({clause})' for clause in clauses)
    ###### apply to all matches
    transformed_bad_DNC = bad_DoesNotContain_pattern_0.sub(replacer, text)
    return transformed_bad_DNC



##### Fix Unicode Problem Sequences and escapes
def escape_special_chars_inside_quotes(text: str) -> str:
    fix_unicode_escapes = text.replace("\\u", "\\\\u").replace("\\U", "\\\\U")
    def nested_func_replacing_specd_chars(m: re.Match) -> str:
        content = m.group(1)
        before   = text[:m.start(0)].rstrip()
        ###### Avoid messing with the regex queries and some conditions which are already met. We'll rectifiy this later.
        if before.endswith('matches'):       # 1) keyword before is 'matches'
            return m.group(0)
        if content.startswith('(?i)'):       # 2) starts with (?i)
            return m.group(0)
        if r'\/' in content:                 # 3) already has '\/'
            return m.group(0)
        ###### start Escaping forward slash and backslash characters
        ###### Edit here if more are needed or if you have special requirements 
        escaped = content
        #  a) escape forward slashes
        escaped = re.sub(r'(?<!\\)/', r'\\/', escaped)
        #  b) escape backslashes, but skip \u sequences
        escaped = re.sub(
            r'(?<!\\)\\(?!u[0-9A-Fa-f]{4})',
            r'\\\\',
            escaped
        )
        return f'"{escaped}"'

    clean_up_and_combine_stuff_in_quotes = re.sub(r'"([^"]*?)"', nested_func_replacing_specd_chars, fix_unicode_escapes, flags=re.DOTALL)
    # return clean_up_and_combine_stuff_in_quotes
    final_fix_unicode_escapes = clean_up_and_combine_stuff_in_quotes.replace('\\\\U','\\U').replace('\\\\u','\\u').replace('\\\\/','\/')
    return final_fix_unicode_escapes


##### F() to fix Regex escaping to comply with the new standards
regex_field_mapping = {
    '\\w':'\\\\w',
    '\\W':'\\\\W',
    '\\d':'\\\\d',
    '\\D':'\\\\D',
    '\\s':'\\\\s',
    '\\S':'\\\\S',
    '\\b':'\\\\b',
    '\\.':'\\\\.',

}

##### This f() applies escaping in the new "matches" operator, which is the "RegExp" replacement
def map_fields_in_matches(text: str, mapping: dict[str,str]) -> str:
    if not isinstance(text, str):
        return text
    qry_contains_pattern_matching_regex = re.compile(r'\smatches\s*"((?:\\.|[^"\\])*)"')
    def _repl(m: re.Match) -> str:
        inner = m.group(1) or ''
        for old, new in mapping.items():
            inner = inner.replace(old, new)
        return f' matches "{inner}"'
    qry_filtered_for_regex =  qry_contains_pattern_matching_regex.sub(_repl, text)
    return qry_filtered_for_regex

##### F() to fix trailing ")". This should only be an issue if you have logic to build queries from multiple places. 
def clean_unmatched_closing_parentheses(query: str) -> str:
    result = []
    balance = 0
    for ch in query:
        if ch == '(':
            balance += 1
            result.append(ch)
        elif ch == ')':
            if balance > 0:
                balance -= 1
                result.append(ch)
        else:
            result.append(ch)
    return ''.join(result)


##### F() to perform the full conversion
def convert_s1qlv1_to_s1qlv2():
    ##### Full Field Mapping v1 to v2
    s1QLv1_to_s1QLv2_field_mapping = {
        #Normal Operators
        'Is True': '= true',
        'Is False': '= false',
        'Is Empty': '!(x=*)',
        'Is Not Empty':'=*',
        'Exists': '=*',
        'EventType':'event.type',
        'eventType':'event.type',
        'eventtype':'event.type',
        #'between': '>= a and x<= b',
        'StartsWith Anycase':'matches',
        'startswithCIS' : 'matches',
        'EndswithCIS' : 'matches',
        'EndsWith Anycase': 'matches',
        'StartsWith': 'matches',
        'EndsWith': 'matches',
        #Problem Operators
        'Does Not ContainCIS':'contains',
        'does not containcis':'contains',
        'Does Not Contain':'contains:matchcase',
        'In Contains Anycase' : 'contains',
        'in contains anycase' : 'contains',
        'In Anycase': 'in:anycase',
        'in anycase': 'in:anycase',
        'In Contains': 'contains:matchcase',
        'in contains': 'contains:matchcase',
        'containsCIS': 'contains:anycase',
        'ContainsCIS': 'contains:anycase',
        'Contains Anycase' : 'contains:anycase',
        'Contains' : 'contains',
        # 'Not In': 'not in',
        # 'not In': 'not in',
        # 'Not in': 'not in',
        'AND ( NOT ':'AND NOT ( ',
        'In': 'in',
        ##************
        'RegExp': 'matches',
        #ProcessConversion
        'ProcessTerminationExitCode':'event.processtermination.exitCode',
        'ProcessTerminationSignal':'event.processtermination.signal',
        'ContainerId':'k8sCluster.containerId',
        'ContainerImage':'k8sCluster.containerImage',
        'ContainerImageId':'k8sCluster.containerImage.id',
        'ContainerImageSha256':'k8sCluster.containerImage.sha256',
        'ContainerLabels':'k8sCluster.containerLabels',
        'ContainerName':'k8sCluster.containerName',
        'K8sControllerLabels':'k8sCluster.controllerLabels',
        'K8sControllerName':'k8sCluster.controllerName',
        'K8sControllerType':'k8sCluster.controllerType',
        'K8sClusterName':'k8sCluster.name',
        'K8sNamespace':'k8sCluster.namespace',
        'K8sNamespaceLabels':'k8sCluster.namespaceLabels',
        'K8sNode':'k8sCluster.nodeName',
        'K8sPodLabels':'k8sCluster.podLabels',
        'K8sPodName':'k8sCluster.podName',
        'OsSrcProcActiveContentHash':'osSrc.process.activeContent.hash',
        'OsSrcProcActiveContentFileId':'osSrc.process.activeContent.id',
        'OsSrcProcActiveContentPath':'osSrc.process.activeContent.path',
        'OsSrcProcActiveContentSignedStatus':'osSrc.process.activeContent.signedStatus',
        'OsSrcProcActiveContentType':'osSrc.process.activeContentType',
        'OsSrcChildProcCount':'osSrc.process.childProcCount',
        'OsSrcProcCmdLine':'osSrc.process.cmdline',
        'OsSrcCrossProcCount':'osSrc.process.crossProcessCount',
        'OsSrcCrossProcDupRemoteProcHandleCount':'osSrc.process.crossProcessDupRemoteProcessHandleCount',
        'OsSrcCrossProcDupThreadHandleCount':'osSrc.process.crossProcessDupThreadHandleCount',
        'OsSrcCrossProcOpenProcCount':'osSrc.process.crossProcessOpenProcessCount',
        'OsSrcCrossProcOutOfStorylineCount':'osSrc.process.crossProcessOutOfStorylineCount',
        'OsSrcCrossProcThreadCreateCount':'osSrc.process.crossProcessThreadCreateCount',
        'OsSrcProcDisplayName':'osSrc.process.displayName',
        'OsSrcDnsCount':'osSrc.process.dnsCount',
        'OsSrcProcBinaryisExecutable':'osSrc.process.image.binaryIsExecutable',
        'OsSrcProcImageExtension':'osSrc.process.image.extension',
        'OsSrcProcImageLocation':'osSrc.process.image.location',
        'OsSrcProcImageMd5':'osSrc.process.image.md5',
        'OsSrcProcImagePath':'osSrc.process.image.path',
        'OsSrcProcImageSha1':'osSrc.process.image.sha1',
        'OsSrcProcImageSha256':'osSrc.process.image.sha256',
        'OsSrcProcImageSignatureIsValid':'osSrc.process.image.signature.isValid',
        'OsSrcProcImageSize':'osSrc.process.image.size',
        'OsSrcImageType':'osSrc.process.image.type',
        'OsSrcProcImageUID':'osSrc.process.image.uid',
        'OsSrcIndicatorBootConfigurationUpdateCount':'osSrc.process.indicatorBootConfigurationUpdateCount',
        'OsSrcIndicatorEvasionCount':'osSrc.process.indicatorEvasionCount',
        'OsSrcIndicatorExploitationCount':'osSrc.process.indicatorExploitationCount',
        'OsSrcIndicatorGeneralCount':'osSrc.process.indicatorGeneral.count',
        'OsSrcIndicatorInfostealerCount':'osSrc.process.indicatorInfostealerCount',
        'OsSrcIndicatorInjectionCount':'osSrc.process.indicatorInjectionCount',
        'OsSrcIndicatorPersistenceCount':'osSrc.process.indicatorPersistenceCount',
        'OsSrcIndicatorPostExploitationCount':'osSrc.process.indicatorPostExploitationCount',
        'OsSrcIndicatorRansomwareCount':'osSrc.process.indicatorRansomwareCount',
        'OsSrcIndicatorReconnaissanceCount':'osSrc.process.indicatorReconnaissanceCount',
        'OsSrcProcIntegrityLevel':'osSrc.process.integrityLevel',
        'OsSrcProcIsNative64Bit':'osSrc.process.isNative64Bit',
        'OsSrcProcIsRedirectCmdProcessor':'osSrc.process.isRedirectCmdProcessor',
        'OsSrcProcIsStorylineRoot':'osSrc.process.isStorylineRoot',
        'OsSrcModuleCount':'osSrc.process.moduleCount',
        'OsSrcProcName':'osSrc.process.name',
        'OsSrcNetConnCount':'osSrc.process.netConnCount',
        'OsSrcNetConnInCount':'osSrc.process.netConnInCount',
        'OsSrcNetConnOutCount':'osSrc.process.netConnOutCount',
        'OsSrcProcParentActiveContentHash':'osSrc.process.parent.activeContent.hash',
        'OsSrcProcParentActiveContentFileId':'osSrc.process.parent.activeContent.id',
        'OsSrcProcParentActiveContentPath':'osSrc.process.parent.activeContent.path',
        'OsSrcProcParentActiveContentSignedStatus':'osSrc.process.parent.activeContent.signedStatus',
        'OsSrcProcParentActiveContentType':'osSrc.process.parent.activeContentType',
        'OsSrcProcParentCmdLine':'osSrc.process.parent.cmdline',
        'OsSrcProcParentDisplayName':'osSrc.process.parent.displayName',
        'OsSrcProcParentImageBinaryIsExecutable':'osSrc.process.parent.image.binaryIsExecutable',
        'OsSrcProcParentImageExtension':'osSrc.process.parent.image.extension',
        'OsSrcProcParentImageLocation':'osSrc.process.parent.image.location',
        'OsSrcProcParentImageMd5':'osSrc.process.parent.image.md5',
        'OsSrcProcParentImagePath':'osSrc.process.parent.image.path',
        'OsSrcProcParentImageSha1':'osSrc.process.parent.image.sha1',
        'OsSrcProcParentImageSha256':'osSrc.process.parent.image.sha256',
        'OsSrcProcParentImageSignatureIsValid':'osSrc.process.parent.image.signature.isValid',
        'OsSrcProcParentImageSize':'osSrc.process.parent.image.size',
        'OsSrcProcParentImageType':'osSrc.process.parent.image.type',
        'OsSrcProcParentImageUID':'osSrc.process.parent.image.uid',
        'OsSrcProcParentIntegrityLevel':'osSrc.process.parent.integrityLevel',
        'OsSrcProcParentIsNative64Bit':'osSrc.process.parent.isNative64Bit',
        'OsSrcProcParentIsRedirectCmdProcessor':'osSrc.process.parent.isRedirectCmdProcessor',
        'OsSrcProcParentIsStorylineRoot':'osSrc.process.parent.isStorylineRoot',
        'OsSrcProcParentName':'osSrc.process.parent.name',
        'OsSrcProcParentPID':'osSrc.process.parent.pid',
        'OsSrcProcParentPublisher':'osSrc.process.parent.publisher',
        'OsSrcProcParentReasonSignatureInvalid':'osSrc.process.parent.reasonSignatureInvalid',
        'OsSrcProcParentSessionId':'osSrc.process.parent.sessionId',
        'OsSrcProcParentSignedStatus':'osSrc.process.parent.signedStatus',
        'OsSrcProcParentStartTime':'osSrc.process.parent.startTime',
        'OsSrcProcParentStorylineId':'osSrc.process.parent.storyline.id',
        'OsSrcProcParentSubSystem':'osSrc.process.parent.subsystem',
        'OsSrcProcParentUID':'osSrc.process.parent.uid',
        'OsSrcProcParentUser':'osSrc.process.parent.user',
        'OsSrcProcParentUserSID':'osSrc.process.parent.userSid',
        'OsSrcProcPID':'osSrc.process.pid',
        'OsSrcProcPublisher':'osSrc.process.publisher',
        'OsSrcProcReasonSignatureInvalid':'osSrc.process.reasonSignatureInvalid',
        'OsSrcRegistryChangeCount':'osSrc.process.registryChangeCount',
        'OsSrcProcSessionId':'osSrc.process.sessionId',
        'OsSrcProcSignedStatus':'osSrc.process.signedStatus',
        'OsSrcProcStartTime':'osSrc.process.startTime',
        'OsSrcProcStorylineId':'osSrc.process.storyline.id',
        'OsSrcProcSubsystem':'osSrc.process.subsystem',
        'OsSrcTgtFileCreationCount':'osSrc.process.tgtFileCreationCount',
        'OsSrcTgtFileDeletionCount':'osSrc.process.tgtFileDeletionCount',
        'OsSrcTgtFileModificationCount':'osSrc.process.tgtFileModificationCount',
        'OsSrcProcUID':'osSrc.process.uid',
        'OsSrcProcUser':'osSrc.process.user',
        'OsSrcProcUserSID':'osSrc.process.userSid',
        'OsSrcProcVerifiedStatus':'osSrc.process.verifiedStatus',
        'SrcProcActiveContentHash':'src.process.activeContent.hash',
        'SrcProcActiveContentFileId':'src.process.activeContent.id',
        'SrcProcActiveContentPath':'src.process.activeContent.path',
        'SrcProcActiveContentSignedStatus':'src.process.activeContent.signedStatus',
        'SrcProcActiveContentType':'src.process.activeContentType',
        'ChildProcCount':'src.process.childProcCount',
        'SrcProcCmdLine':'src.process.cmdline',
        'SrcProcImageCompletenessHints':'src.process.completeness.hints',
        'CrossProcCount':'src.process.crossProcessCount',
        'CrossProcDupRemoteProcHandleCount':'src.process.crossProcessDupRemoteProcessHandleCount',
        'CrossProcDupThreadHandleCount':'src.process.crossProcessDupThreadHandleCount',
        'CrossProcOpenProcCount':'src.process.crossProcessOpenProcessCount',
        'CrossProcOutOfStorylineCount':'src.process.crossProcessOutOfStorylineCount',
        'CrossProcThreadCreateCount':'src.process.crossProcessThreadCreateCount',
        'SrcProcDisplayName':'src.process.displayName',
        'DnsCount':'src.process.dnsCount',
        'SrcProcEUserName':'src.process.eUserName',
        'SrcProcEUserUid':'src.process.eUserUid',
        'ExeModificationCount':'src.process.exeModificationCount',
        'SrcProcImageExtension':'src.process.image.extension',
        'SrcProcImageLocation':'src.process.image.location',
        'SrcProcImageMd5':'src.process.image.md5',
        'SrcProcImagePath':'src.process.image.path',
        'SrcProcImageSha1':'src.process.image.sha1',
        'SrcProcImageSha256':'src.process.image.sha256',
        'SrcProcImageCompletenessHints':'src.process.image.size',
        'SrcProcImageUID':'src.process.image.uid',
        'IndicatorBootConfigurationUpdateCount':'src.process.indicatorBootConfigurationUpdateCount',
        'IndicatorEvasionCount':'src.process.indicatorEvasionCount',
        'IndicatorExploitationCount':'src.process.indicatorExploitationCount',
        'IndicatorGeneralCount':'src.process.indicatorGeneralCount',
        'IndicatorInfostealerCount':'src.process.indicatorInfostealerCount',
        'IndicatorInjectionCount':'src.process.indicatorInjectionCount',
        'IndicatorPersistenceCount':'src.process.indicatorPersistenceCount',
        'IndicatorPostExploitationCount':'src.process.indicatorPostExploitationCount',
        'IndicatorRansomwareCount':'src.process.indicatorRansomwareCount',
        'IndicatorReconnaissanceCount':'src.process.indicatorReconnaissanceCount',
        'SrcProcIntegrityLevel':'src.process.integrityLevel',
        'SrcProcIsNative64Bit':'src.process.isNative64Bit',
        'SrcProcIsRedirectCmdProcessor':'src.process.isRedirectCmdProcessor',
        'SrcProcIsStorylineRoot':'src.process.isStorylineRoot',
        'SrcProcLUserName':'src.process.lUserName',
        'SrcProcLUserUid':'src.process.lUserUid',
        'ModelChildProcessCount':'src.process.modelChildProcessCount',
        'ModuleCount':'src.process.moduleCount',
        'SrcProcName':'src.process.name',
        'NetConnCount':'src.process.netConnCount',
        'NetConnInCount':'src.process.netConnInCount',
        'NetConnOutCount':'src.process.netConnOutCount',
        'SrcProcParentActiveContentHash':'src.process.parent.activeContent.hash',
        'SrcProcParentActiveContentFileId':'src.process.parent.activeContent.id',
        'SrcProcParentActiveContentPath':'src.process.parent.activeContent.path',
        'SrcProcParentActiveContentSignedStatus':'src.process.parent.activeContent.signedStatus',
        'SrcProcParentActiveContentType':'src.process.parent.activeContentType',
        'SrcProcParentCmdLine':'src.process.parent.cmdline',
        'SrcProcParentDisplayName':'src.process.parent.displayName',
        'SrcProcParentEUserName':'src.process.parent.eUserName',
        'SrcProcParentEUserUid':'src.process.parent.eUserUid',
        'SrcProcParentImageBinaryIsExecutable':'src.process.parent.image.binaryIsExecutable',
        'SrcProcParentImageExtension':'src.process.parent.image.extension',
        'SrcProcParentImageLocation':'src.process.parent.image.location',
        'SrcProcParentImageMd5':'src.process.parent.image.md5',
        'SrcProcParentImagePath':'src.process.parent.image.path',
        'SrcProcParentImageSha1':'src.process.parent.image.sha1',
        'SrcProcParentImageSha256':'src.process.parent.image.sha256',
        'SrcProcParentImageSignatureIsValid':'src.process.parent.image.signature.isValid',
        'SrcProcParentImageSize':'src.process.parent.image.size',
        'SrcProcParentImageType':'src.process.parent.image.type',
        'SrcProcParentImageUID':'src.process.parent.image.uid',
        'SrcProcParentIntegrityLevel':'src.process.parent.integrityLevel',
        'SrcProcParentIsNative64Bit':'src.process.parent.isNative64Bit',
        'SrcProcParentIsRedirectCmdProcessor':'src.process.parent.isRedirectCmdProcessor',
        'SrcProcParentIsStorylineRoot':'src.process.parent.isStorylineRoot',
        'SrcProcParentLUserName':'src.process.parent.lUserName',
        'SrcProcParentLUserUid':'src.process.parent.lUserUid',
        'SrcProcParentName':'src.process.parent.name',
        'SrcProcParentPID':'src.process.parent.pid',
        'SrcProcParentPublisher':'src.process.parent.publisher',
        'SrcProcParentRUserName':'src.process.parent.rUserName',
        'SrcProcParentRUserUid':'src.process.parent.rUserUid',
        'SrcProcParentReasonSignatureInvalid':'src.process.parent.reasonSignatureInvalid',
        'SrcProcParentSessionId':'src.process.parent.sessionId',
        'SrcProcParentSignedStatus':'src.process.parent.signedStatus',
        'SrcProcParentStartTime':'src.process.parent.startTime',
        'SrcProcParentStorylineId':'src.process.parent.storyline.id',
        'SrcProcParentUID':'src.process.parent.uid',
        'SrcProcParentUser':'src.process.parent.user',
        'SrcProcParentUserSID':'src.process.parent.userSid',
        'SrcProcPID':'src.process.pid',
        'SrcProcPublisher':'src.process.publisher',
        'SrcProcRUserName':'src.process.rUserName',
        'SrcProcRUserUid':'src.process.rUserUid',
        'SrcProcReasonSignatureInvalid':'src.process.reasonSignatureInvalid',
        'RegistryChangeCount':'src.process.registryChangeCount',
        'SrcProcRPID':'src.process.rpid',
        'SrcProcSessionId':'src.process.sessionId',
        'SrcProcSignedStatus':'src.process.signedStatus',
        'SrcProcStartTime':'src.process.startTime',
        'SrcProcStorylineId':'src.process.storyline.id',
        'SrcProcSubsystem':'src.process.subsystem',
        'TgtFileCreationCount':'src.process.tgtFileCreationCount',
        'TgtFileDeletionCount':'src.process.tgtFileDeletionCount',
        'TgtFileModificationCount':'src.process.tgtFileModificationCount',
        'SrcProcTid':'src.process.tid',
        'SrcProcUID':'src.process.uid',
        'SrcProcUser':'src.process.user',
        'SrcProcUserSID':'src.process.userSid',
        'SrcProcVerifiedStatus':'src.process.verifiedStatus',
        'TaskCluster':'task.cluster',
        'EcsVersion':'task.ecsVersion',
        'TaskServiceArn':'task.serviceArn',
        'TaskServiceName':'task.serviceName',
        # 'TaskTags':'task.tags', #repeated later
        # 'TaskArn':'task.taskArn',
        'TaskAvailabilityZone':'task.taskAvailabilityZone',
        'TaskDefinitionArn':'task.taskDefinitionArn',
        'TaskDefinitionFamily':'task.taskDefinitionFamily',
        'TaskDefinitionRevision':'task.taskDefinitionRevision',
        'TgtFileConvictedBy':'tgt.file.convictedBy',
        'TgtFileSha1':'tgt.file.sha1',
        'TgtProcAccessRights':'tgt.process.accessRights',
        'TgtProcActiveContentHash':'tgt.process.activeContent.hash',
        'TgtProcActiveContentFileId':'tgt.process.activeContent.id',
        'TgtProcActiveContentPath':'tgt.process.activeContent.path',
        'TgtProcActiveContentSignedStatus':'tgt.process.activeContent.signedStatus',
        'TgtProcActiveContentType':'tgt.process.activeContentType',
        'TgtProcCmdLine':'tgt.process.cmdline',
        'TgtProcImageCompletenessHints':'tgt.process.completeness.hints',
        'TgtProcDisplayName':'tgt.process.displayName',
        'TgtProcEUserName':'tgt.process.eUserName',
        'TgtProcEUserUid':'tgt.process.eUserUid',
        'TgtProcBinaryisExecutable':'tgt.process.image.binaryIsExecutable',
        'TgtProcImageExtension':'tgt.process.image.extension',
        'TgtProcImageMd5':'tgt.process.image.md5',
        'TgtProcImagePath':'tgt.process.image.path',
        'TgtProcImageSha1':'tgt.process.image.sha1',
        'TgtProcImageSha256':'tgt.process.image.sha256',
        'TgtProcImageSize':'tgt.process.image.size',
        'TgtProcImageUID':'tgt.process.image.uid',
        'TgtProcIntegrityLevel':'tgt.process.integrityLevel',
        'TgtProcIsNative64Bit':'tgt.process.isNative64Bit',
        'TgtProcIsRedirectCmdProcessor':'tgt.process.isRedirectCmdProcessor',
        'TgtProcIsStorylineRoot':'tgt.process.isStorylineRoot',
        'TgtProcLUserName':'tgt.process.lUserName',
        'tgtProcLuserUid':'tgt.process.lUserUid',
        'TgtProcName':'tgt.process.name',
        'TgtProcParentImageLocation':'tgt.process.parent.image.location',
        'TgtProcParentImageType':'tgt.process.parent.image.type',
        'TgtProcPID':'tgt.process.pid',
        'TgtProcPublisher':'tgt.process.publisher',
        'TgtProcRUserName':'tgt.process.rUserName',
        'TgtProcRUserUid':'tgt.process.rUserUid',
        'TgtProcReasonSignatureInvalid':'tgt.process.reasonSignatureInvalid',
        'TgtProcSessionId':'tgt.process.sessionId',
        'TgtProcSignedStatus':'tgt.process.signedStatus',
        'TgtProcStartTime':'tgt.process.startTime',
        'TgtProcStorylineId':'tgt.process.storyline.id',
        'TgtProcSubsystem':'tgt.process.subsystem',
        'TgtProcUID':'tgt.process.uid',
        'TgtProcUser':'tgt.process.user',
        'TgtProcUserSID':'tgt.process.userSid',
        'TgtProcVerifiedStatus':'tgt.process.verifiedStatus',
        #Command Scripts
        'SrcProcCmdScriptApplicationName':'cmdScript.applicationName',
        'SrcProcCmdScript':'cmdScript.content',
        'SrcProcCmdScriptIsComplete':'cmdScript.isComplete',
        'SrcProcCmdScriptOriginalSize':'cmdScript.originalSize',
        'SrcProcCmdScriptSha256':'cmdScript.sha256',
        'SrcProcCmdLine':'src.process.cmdline',
        'SrcProcImageMd5':'src.process.image.md5',
        'SrcProcImagePath':'src.process.image.path',
        'SrcProcImageSha':'src.process.image.sha1',
        'TgtFileSha1':'tgt.file.sha1',
        #Cross Processes
        'ProcessTerminationExitCode': 'event.processtermination.exitCode',
        'ProcessTerminationSignal': 'event.processtermination.signal',
        'ContainerImageId': 'k8sCluster.containerImage.id',
        'ContainerImageSha256': 'k8sCluster.containerImage.sha256',
        'TgtProcAccessRights': 'tgt.process.accessRights',
        'TgtProcActiveContentHash': 'tgt.process.activeContent.hash',
        'TgtProcActiveContentFileId': 'tgt.process.activeContent.id',
        'TgtProcActiveContentPath': 'tgt.process.activeContent.path',
        'TgtProcActiveContentSignedStatus': 'tgt.process.activeContent.signedStatus',
        'TgtProcActiveContentType': 'tgt.process.activeContentType',
        'TgtProcCmdLine': 'tgt.process.cmdline',
        'TgtProcDisplayName': 'tgt.process.displayName',
        'TgtProcBinaryisExecutable': 'tgt.process.image.binaryIsExecutable',
        'TgtProcImageMd5': 'tgt.process.image.md5',
        'TgtProcImagePath': 'tgt.process.image.path',
        'TgtProcImageSha1': 'tgt.process.image.sha1',
        'TgtProcImageSha256': 'tgt.process.image.sha256',
        'TgtProcIntegrityLevel': 'tgt.process.integrityLevel',
        'TgtProcIsNative64Bit': 'tgt.process.isNative64Bit',
        'TgtProcIsRedirectCmdProcessor': 'tgt.process.isRedirectCmdProcessor',
        'TgtProcIsStorylineRoot': 'tgt.process.isStorylineRoot',
        'TgtProcName': 'tgt.process.name',
        'TgtProcPID': 'tgt.process.pid',
        'TgtProcPublisher': 'tgt.process.publisher',
        'TgtProcReasonSignatureInvalid': 'tgt.process.reasonSignatureInvalid',
        'TgtProcRelation': 'tgt.process.relation',
        'TgtProcSessionId': 'tgt.process.sessionId',
        'TgtProcSignedStatus': 'tgt.process.signedStatus',
        'TgtProcStartTime': 'tgt.process.startTime',
        'TgtProcStorylineId': 'tgt.process.storyline.id',
        'TgtProcSubsystem': 'tgt.process.subsystem',
        'TgtProcUID': 'tgt.process.uid',
        'TgtProcUser': 'tgt.process.user',
        'TgtProcVerifiedStatus': 'tgt.process.verifiedStatus',
        #DNS
        'DnsRequest':'event.dns.request',
        'DnsResponse':'event.dns.response',
        'DnsStatus':'event.dns.status',
        #Driver
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
        'driverProcessProcess': 'driver.dropperProcess',
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
        #Files
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
        'SrcProcBinaryisExecutable': 'src.process.image.binaryIsExecutable',
        'SrcProcImageDescription': 'src.process.image.description',
        'SrcProcImageInternalName': 'src.process.image.internalName',
        'SrcProcImageMd5': 'src.process.image.md5',
        'SrcProcImageOriginalFileName': 'src.process.image.originalFileName',
        'SrcProcImageProductName': 'src.process.image.productName',
        'SrcProcImageProductVersion': 'src.process.image.productVersion',
        'SrcProcImageSha256': 'src.process.image.sha256',
        'SrcProcImageType': 'src.process.image.type',
        'SrcProcPublisher': 'src.process.publisher',
        'SrcProcReasonSignatureInvalid': 'src.process.reasonSignatureInvalid',
        'SrcProcRPID': 'src.process.rpid',
        'SrcProcSignedStatus': 'src.process.signedStatus',
        'SrcProcTid': 'src.process.tid',
        'SrcProcVerifiedStatus': 'src.process.verifiedStatus',
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
        'TgtFileConvictedBy': 'tgt.file.convictedBy',
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
        'TgtFileSha1': 'tgt.file.sha1',
        'TgtFileSha256': 'tgt.file.sha256',
        'TgtFileSignatureIsValid': 'tgt.file.signature.isValid',
        'GroupType': 'tgt.file.signatureInvalidReason',
        'TgtFileSize': 'tgt.file.size',
        'TgtFileType': 'tgt.file.type',
        #Indicators
        'IndicatorCategory': 'indicator.category',
        'IndicatorDescription': 'indicator.description',
        'IndicatorIdentifier': 'indicator.identifier',
        'IndicatorMetadata': 'indicator.metadata',
        'IndicatorName': 'indicator.name',
        #Logins
        'LoginAccountDoconvert_s1qlv1_to_s1qlv2': 'event.login.accountDoconvert_s1qlv1_to_s1qlv2',
        'LoginAccountName': 'event.login.accountName',
        'LoginAccountSID': 'event.login.accountSid',
        'LoginsBaseType': 'event.login.baseType',
        'LoginFailureReason': 'event.login.failureReason',
        'LoginIsAdministratorEquivalent': 'event.login.isAdministratorEquivalent',
        'LoginIsSuccessful': 'event.login.loginIsSuccessful',
        'LoginSessionID': 'event.login.sessionId',
        'LoginTgtDoconvert_s1qlv1_to_s1qlv2Name': 'event.login.tgt.doconvert_s1qlv1_to_s1qlv2Name',
        'LoginTgtUserName': 'event.login.tgt.user.name',
        'LoginTgtUserSID': 'event.login.tgt.userSid',
        'LoginType': 'event.login.type',
        'LoginsUserName': 'event.login.userName',
        'LogoutTgtDoconvert_s1qlv1_to_s1qlv2Name': 'event.logout.tgt.doconvert_s1qlv1_to_s1qlv2Name',
        'LogoutTgtUserName': 'event.logout.tgt.user.name',
        'LogoutTgtUserSID': 'event.logout.tgt.userSid',
        'LogoutType': 'event.logout.type',
        'SrcMachineIP': 'src.endpoint.ip.address',
        #Modules
        'ModuleCertificateExpirationDate': 'module.certificate.expirationdate',
        'ModuleCertificateThumbprint': 'module.certificate.thumbprint',
        'ModuleMd5': 'module.md5',
        'ModulePath': 'module.path',
        'ModuleSha1': 'module.sha1',
        'ModuleSignedStatus': 'module.signed.status',
        'ModuleSignerName': 'module.signer.name',
        #Network
        'DstIP': 'dst.ip.address',
        'DstPort': 'dst.port.number',
        'NetConnStatus': 'event.network.connectionStatus',
        'NetEventDirection': 'event.network.direction',
        'NetProtocolName': 'event.network.protocolName',
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
        'SrcIP': 'src.ip.address',
        'SrcPort': 'src.port.number',
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
        #Registry
        'RegistryExportPath': 'registry.export.path',
        'RegistryImportPath': 'registry.import.path',
        'RegistryKeyPath': 'registry.keyPath',
        'RegistryUID': 'registry.keyUid',
        'RegistryOldValue': 'registry.oldValue',
        'RegistryOldValueFullSize': 'registry.oldValueFullSize',
        'RegistryOldValueIsComplete': 'registry.oldValueIsComplete',
        'RegistryOldValueType': 'registry.oldValueType',
        'RegistryOwnerUser': 'registry.owner.user',
        'registry.owner.userSid': 'registry.owner.userSid',
        'RegistrySecurityInfo': 'registry.security.info',
        'RegistryValue': 'registry.value',
        'RegistryValueFullSize': 'registry.valueFullSize',
        'RegistryValueIsComplete': 'registry.valueIsComplete',
        'RegistryValueType': 'registry.valueType',
        #ScheduledTasks
        'TaskName': 'task.name',
        'TaskPath': 'task.path',
        'TaskTriggerType': 'task.triggerType',
        #URL
        'UrlAction':'event.url.action',
        'UrlSource':'event.url.source',
        'Url':'url.address',
        #Shortcuts
        # ' CmdLine ': ' cmdline ',
        # ' DNS ': 'dns',
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
        # '':'endpoint.domain', NO OFFICIAL MAPPING 
        # '':'endpoint.id', NO OFFICIAL MAPPING 
        # '':'endpoint.macAddress', NO OFFICIAL MAPPING
        'EndpointName':'endpoint.name',
        'EndpointMachineType':'endpoint.type',
        #Escape Chars
        # '\*':'\*',
        # '\\':'\\\\',
    }
    ##### This section starts iterating over logical issues and issues with a mapping process 

    ##### Fix Issues around Does Not Contain(?:CIS)* multiple groups
    regex_check_for_bad_DoesNotContain_pattern_0 = re.compile(r'(?i)(\sAND\s+)(\()(\s+)(((?:[A-Za-z\.]*?\s+Does\s+Not\s+Contain(?:CIS)?\s+\".*?\")((?:\s*AND\s*|\s*OR\s*|\))*))+)\s*')
    check_for_bad_DoesNotContain_pattern_0 = re.findall(regex_check_for_bad_DoesNotContain_pattern_0, input_text)
    if len(check_for_bad_DoesNotContain_pattern_0) >= 1:
        transform_query_containing_bad_DoesNotContain_pattern_0(input_text)
    else:
        pass

    ##### First fix the "and not" needs it's clause in parenthesis issue for 2 conditions (patterns) in the query set
    ##### pattern1
    bad_AndNot_pattern_1 = re.compile(r'(?i)(AND\s+NOT)(\s+)((?:[A-Za-z\.]*?\s+)+\(\s?(?:\".*?\"\s*,?)+\s?\))')
    new_string_1 = re.sub(bad_AndNot_pattern_1,r'\1\2( \3 )', input_text)

    ##### pattern2: 
    bad_AndNot_pattern_2 = re.compile(r'(?i)(AND\s+NOT)(\s+)((?:[A-Za-z\.]*?\s+)+\".*?\")')
    new_string_2 = re.sub(bad_AndNot_pattern_2,r'\1\2( \3 )', new_string_1)

    ##### Fix the logical issues introduced by "Does Not Contain" and "Does Not ContainCIS"

    ##### pattern1_CIS: 
    bad_DoesNotContainCIS_pattern_1 = re.compile(r'(?i)(\sAND)(\s+)((?:[A-Za-z\.]*?\s+Does\s+Not\s+ContainCIS\s+\".*?\"))')
    new_string_3 = re.sub(bad_DoesNotContainCIS_pattern_1,r'\1 NOT\2(\3)', new_string_2)

    ##### pattern2: 
    bad_DoesNotContain_pattern_2 = re.compile(r'(?i)(\sAND)(\s+)((?:[A-Za-z\.]*?\s+Does\s+Not\s+Contain\s+\".*?\"))')
    new_string_4 = re.sub(bad_DoesNotContain_pattern_2,r'\1 NOT\2(\3)', new_string_3)

    ##### Fix the logical issues introduced by "Not In"
    bad_Not_in_pattern = re.compile(r'(?i)(\sAND)(\s+)([A-Za-z\.]*?\s+)(Not\s+In)(\s+\(\s(?:\".*?\"\s*\,*)+\))')
    new_string_5 = re.sub(bad_Not_in_pattern,r'\1\2NOT ( \3 contains \5)', new_string_4)

    ##### Fix the logical issues introduced by "Not In" in special circumstances
    bad_Not_In_SITE_pattern = re.compile(r'(?i)(\sAND)(\s+)(\(\s+site\.?name)(\s+)(Not\s+In)(\s+)(\((?:\s*\".*?\"\,*\s*)\))\s+OR')
    new_string_6 = re.sub(bad_Not_In_SITE_pattern,r'\1\2( !\3 contains \6\7) OR ', new_string_5)

    ##### Fix 3rd Does Not Contain(CIS)* when it's the first statement in a line of them inside paren's
    #pattern 3: 
    bad_DoesNotContain_pattern_3 = re.compile(r'(?i)(\sAND\s+)(\()(\s+)((?:[A-Za-z\.]*?\s+Does\s+Not\s+Contain(?:CIS)?\s+\".*?\"))\s')
    new_string_7 = re.sub(bad_DoesNotContain_pattern_3,r'\1NOT \2\3\4) ', new_string_6)

    ########## These Just needed to be after the s1 mapping f() 
    ###### This F() actually transforms old fields to new fields 
    sentinelOne_QL_v2_converted_query = replace_mapped_query_fields_regex(new_string_7, s1QLv1_to_s1QLv2_field_mapping)    
    qry_with_escaped_chars_in_quotes = escape_special_chars_inside_quotes(sentinelOne_QL_v2_converted_query)
    ###### Fix escaping for Regex components
    qry_with_escaped_regex = map_fields_in_matches(qry_with_escaped_chars_in_quotes, regex_field_mapping).replace(' ""',' "').replace('(?i)','')
    
    ##### Fix issues with trailing parenthesis + replace a couple of interesting issues with inidicator data && indicator Metadata
    
    ##### *** OF NOTE *** ##### 
    ##### If you have one off items to replace, putting them here is probably the easiest way to comlete that.
    ##### The .replace() method takes 2 arguments: first - what I want replaced, second - what I want it replaced with.  
    final_query = clean_unmatched_closing_parentheses(qry_with_escaped_regex).replace('indicatorname', 'indicator.name').replace('indicatorMetadata', 'indicator.metadata').replace('"Windows"','"windows"')


    ##### Write to a file or to the screen:
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(sentinelOne_QL_v2_converted_query)
            print(f"Transformed text written to '{args.output}'.")
        except IOError as e:
            exit(f"Error writing to output file: {e}")
    else:
        print()
        print("Original Query:")
        print(input_text)
        print()
        print()
        print()
        print()
        print()
        print()
        print("SentinelOne QL V2.0 Query:")
        print(final_query)
        print()




if __name__ == "__main__":
    convert_s1qlv1_to_s1qlv2()


