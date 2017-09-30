Script to pull convert DMARC reports into a CSV file. This is forked
from and contains code largely written from 
https://github.com/prbinu/dmarc-report-processor

My needs are to process a set of DMARC reports I have saved to a directory
and convert them to CSV with proper headers. I have removed code from this
branch that does not directly meet my goals.

**dmarc-parser.py** - Convert the xml files to comma-seperated key=value
 pair (line oriented output for splunk). This script can handle large xml files


#### dmarc-parser.py

```
dmarc-parser.py [-h] dmarcfile

positional arguments:
  dmarcfile   dmarc file in XML format

optional arguments:
  -h, --help  show this help message and exit

Example: 
  % dmarc-parser.py dmarc-xml-file 1> outfile.csv
```