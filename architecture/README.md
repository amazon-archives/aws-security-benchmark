# aws-security-benchmark
```create-benchmark-rules.yaml``` is an AWS CloudFormation template for establishing CIS AWS 1.1 benchmark governance rules (download the benchmarks [here](https://benchmarks.cisecurity.org/en-us/?route=downloads.form.awsfoundations.110)).

```cis-benchmark-matrix.xlsx``` is a spreadsheet that maps the CIS Amazon Web Services Foundations benchmarks to the specific security controls provisioned in the CloudFormation template.

The AWS services used for these benchmarks are used in the following relationship:

![CIS Benchmark Architecture Diagram](https://github.com/awslabs/aws-security-benchmark/blob/master/architecture/assets/cis-benchmark-architecture.jpg)

The following preconditions must be met before the stack can be launched:

1. AWS Config must be running in the region where this template will be run. This is needed for Config Rules.
2. Amazon CloudTrail must be delivering logs to CloudWatch Logs. This is needed for CloudWatch metrics and alarms.
3. AWS Lambda must be supported in the region where this template will be launched. See [this](https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services/) page for region support.

The controls are a combination of AWS Config Rules (both AWS-managed and custom), Amazon CloudWatch rules, and Amazon CloudWatch alarms.
Please note that these resources will incur costs in your account; please refer to the pricing model for each service.

For example, an estimate in us-east-1:
  * Config Rules:       17 rules   @ $2.00/rule/month    = $34.00/month
  * CloudWatch Alarms:   6 alarms  @ $0.10/alarm/month   =  $0.60/month
  * CloudWatch Metrics:  6 metrics @ $0.30/metric/month  =  $1.80/month
  * CloudWatch Logs:    17 logs    @ $0.50/GB ingested   =  based on usage
  * Lambda:              variable (first 1 million requests per month are free)
