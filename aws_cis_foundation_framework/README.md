# aws-cis-foundation-benchmark-checklist
Script to evaluate your AWS account against the full CIS Amazon Web Services
Foundations Benchmark 1.1  
The script have a number of different outputs, all optional by changing the
settings inside the script.  
All outputs will generate a single report of all supported controls in short
format, full JSON or HTML.  
Delivery of the report is console output for JSON structure, S3 SignedURL for
HTML file and optional publish to SNS for the S3 SignedURL if you wish to
receive an email or trigger other functions any time a new report is done.  
You can also store the reports in a central S3 bucket if you run this for
multiple accounts

## Execution
### Requirement
Verified with Python 2.7.
Python 3.6 support in process.

### Config Rules
By adding the script to you AWS account as a Lambda function you can tie it
to a Config Rule.  
You don't need to change or enable anything in the script when using with
Config Rule, the script will autosense it and automatically start reporting
compliance status at the account level.  
The script will also report back a short-form version of the result using
the annotation field. You can see this value using the Config API:  
```aws configservice get-compliance-details-by-config-rule --config-rule-name```  
***Keep in mind that the lambda function needs to have timeout set to max time.***

### Local execution
You can also run this script from a admin console using python and AWS SDK.  
It will use the credentials you have stored in your profiles.  

Run without parameters to use default profile:')  
```python aws-cis-foundation-benchmark-checklist.py```  
Specify profile by using the -p or --profile  
```python aws-cis-foundation-benchmark-checklist.py [-p|--profile] <profile>```  

## IAM Policy
The IAM policy required to run the script is located in the file  
aws-cis-foundation-benchmark-checklist-lambdarole.json  
