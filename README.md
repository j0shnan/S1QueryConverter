[![Sponsored By CyberMaxx](https://github.com/j0shnan/S1QueryConverter/blob/main/Images/cybermaxx_logo.png)](https://www.cybermaxx.com/)

# Sponsored by CyberMaxx

# S1 Query Converter


S1QueryConverter is a project written in Python 3 which takes SentinelOne DeepVis v1 queries and translates them into DeepVis v2 query language.  



# Contents

- [Overview](#overview)
- [Description](#description)
- [Install & Usage](#install--usage)
- [Help](#help)
- [Reporting Issues](#reporting-issues)
- [Disclaimer](#disclaimer)

# Description

S1QueryConverter is a python script which takes a file containing SentinelOne DeepVis v1 queries and translates them into DeepVis v2 query language using argparse for file intake and re for regular expressions.

When ran, the script writes output to the terminal.

To run the scripts you'll need Python 3.  You can DL the raw files from this GitHub page, the zip, or clone the repo.  It should work with files anywhere on your system the user has permission to alter. Notably, the Multi converter will convert an entire detection library.  The script needs to be altered with the following hardcoded parameters to function:
- input .xlsx file
- sheet name from the file
- column(s) to convert (that's right, we'll do multiple columns!!)
- columns to output
- output file name && path


** I'm not a dev, I just like to eliminate odysseys from my work flow.  I would test a handful of your queries with the single converter script and then move over to the multiple converter script once you've altered for any unique issues your query sets may have. You'll see at the end of the "main" converter function there's a place to write quick & dirty replacements or just go hog wild and make it what you want.  If you see something, please do say something to me and I'll work on altering the scripts. 

Lastly, there is one known issue which tends to create a chicken / egg scenario.  That's looking for double or single quotes inside of a query that is NOT part of a regex query. 
E.g., " 'httpx://SomeSite.Site" or "\\Maybe\Some\Share BlahBlah=\"AnotherResource" 
In both examples this creates an issue in the new QL.  The resolution here is to encapsulate both with Single Quotes:
E.g., 'httpx://SomeSite.Site' or '\\Maybe\Some\Share BlahBlah=\"AnotherResource'
Since v2 accepts single quotes this is not a major issue, but still needs to be solved manually.  Thankfully, these aren't scenarios we run into frequently when making queries.  Please be aware that the scripts will both hit these conditions and stop converting anything that comes after it to v2 ql (you'll have a partially converted query).  



# Install & Usage

## Install

To install you can clone the repo, DL the raw .py files (not dependent on one another), or paste them where you would like to perform operations on your file system.
E.g.,

```
# Clone the repository
git clone https://github.com/j0shnan/S1QueryConverter
cd S1QueryConverter

```

## Usage
```
# Single Converter Script:

python3 S1QueryConverter_Single.py  <FileName.txt>


# Multi query converter
# *** OF NOTE ***
# There are multiple parameters this script needs to function. The .xlsx file, sheet name, column(s) to convert, output file name and path. So, it's left as a hard coded. It can be easily modified to suit your needs. 

python3 S1QueryConverter_Multiple.py

```

# Reporting Issues
If you encounter an issue with bad conversions, please let me know. Open an issue and reference the error your see (or better yet, in the code) so that we can account for it correctly. 

# Disclaimer
This tool was made with intent to help the Cyber community at large.  The author accepts no responsibility for queries that do not function after using the tool to convert them.  Please double check your detections with validation.  
