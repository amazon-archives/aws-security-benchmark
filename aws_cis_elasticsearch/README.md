# aws-cis-elasticsearch
This is a lambda function that exports AWS CIS Benchmark results to Elasticsearch

Suports AWS Elasticsearch, and standard Elasticsearch.

The following environment variables can be set to your liking:

es_url:
The http/s url of the elasticsearch cluster
es_index:
The elasticsearch index name that will be created. This can be a time formatted string so that you can automatically create time based indexes, eg, aws-cis-metrics-%Y-%m-%d will be evaluated to aws-cis-metrics-2017-11-09, something that kibana can discover. See this for more information on the time formatting:
http://strftime.org/

es_authmethod:
one of "iam", "http", by default it will use "iam" and attempt to connect via EC2 IAM roles, http will using standard http auth (basic), and anything else will not attempt to use any authentication at all.

es_username: 
HTTP auth username (if using es_authmethod "http")

es_password:
HTTP auth password (if using es_authmethod "http")

es_encvar:
if set, will try to unecrypt environment variables set by the "in-transit" lambda encryption and KMS.
The the following parameters support this:
es_user
es_password
If it does decrypt the values, it will report this in the logs (but not display the actual values).


To build lambda python zip package:
./build-lambda-env-python3.6.sh && ./package-lambda.sh
