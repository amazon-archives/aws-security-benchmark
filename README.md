# aws-security-benchmark
Collection of resources related to security benchmark frameworks.
Currently covered frameworks:
- CIS Amazon Web Services Foundations Benchmark 1.1

Contents:

aws-security-benchmark/ <br/>
├── LICENSE <br/>
├── README.md <br/>
├── architecture <br/>
│   ├── README.md <br/>
│   ├── assets <br/>
│   │   └── cis-benchmark-architecture.jpg <br/>
│   ├── cis-benchmark-matrix.xlsx <br/>
│   ├── create-benchmark-rules.yaml <br/>
└── aws_cis_foundation_framework <br/>
    ├── CIS_Amazon_Web_Services_Foundations_Benchmark_v1.1.0.pdf <br/>
    ├── README.md <br/>
    ├── aws-cis-foundation-benchmark-checklist-lambdarole.json <br/>
    └── aws-cis-foundation-benchmark-checklist.py <br/>

There are two parts of this package.

1. CloudFormation template to configure AWS Config, Amazon CloudWatch to analyse against the CIS benchmarks and AWS Lambda to respond. Located under the architecture directory
2. Python script to run all of the CIS Benchmark checks from the command line and output the results to an HTML file. Located under the aws_cis_foundation_framework directory

See the REAMDME.md files for the install instructions for each part.

Prerequisites for part 1 (automated benchmarking):

1. AWS Config must be running in the region where this template will be run. This is needed for Config Rules.
2. Amazon CloudTrail must be delivering logs to CloudWatch Logs. This is needed for CloudWatch metrics and alarms.
3. AWS Lambda must be supported in the region where this template will be launched. See [this](https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services/) page for region support.

Prerequisites for part 2 (python script)

1. Python version 2.7
2. Configured AWS CLI
3. IAM permissions as defined in (aws-cis-foundation-benchmark-checklist-lambdarole.json)
