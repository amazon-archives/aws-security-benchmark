# CIS Benchmarks Matrix

|   | Benchmark | Profile Level | Scored | Automated | Security Control Type | Security Control Resource Name |
|  :------: | :------: | :------: | :------: | :------: | :------: | :------: |
|  1 | *Identity and Access Management* |  |  |  |  |  |
|  1.1 | Avoid the use of the "root" account  | 1 | Yes | Yes | CloudWatch Alarm | IAMRootActivityCloudWatchMetric |
|  1.2 | Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password  | 1 | Yes | Yes | Config Rule | UsersMustHaveMfaEnabled |
|  1.3 | Ensure credentials unused for 90 days or greater are disabled  | 1 | Yes | Yes | CloudWatch Rule (scheduled) | DisableUnusedCredentials |
|  1.4 | Ensure access keys are rotated every 90 days or less  | 1 | Yes | Yes | CloudWatch Rule (scheduled) | DisableUnusedCredentials |
|  1.5 | Ensure IAM password policy requires at least one uppercase letter  | 1 | Yes | Yes | Config Rule | IamPasswordPolicyMustMeetRequirements |
|  1.6 | Ensure IAM password policy require at least one lowercase letter  | 1 | Yes | Yes | Config Rule | IamPasswordPolicyMustMeetRequirements |
|  1.7 | Ensure IAM password policy require at least one symbol  | 1 | Yes | Yes | Config Rule | IamPasswordPolicyMustMeetRequirements |
|  1.8 | Ensure IAM password policy require at least one number  | 1 | Yes | Yes | Config Rule | IamPasswordPolicyMustMeetRequirements |
|  1.9 | Ensure IAM password policy requires minimum length of 14 or greater  | 1 | Yes | Yes | Config Rule | IamPasswordPolicyMustMeetRequirements |
|  1.1 | Ensure IAM password policy prevents password reuse    | 1 | Yes | Yes | Config Rule | IamPasswordPolicyMustMeetRequirements |
|  1.11 | Ensure IAM password policy expires passwords within 90 days or less  | 1 | Yes | Yes | Config Rule | IamPasswordPolicyMustMeetRequirements |
|  1.12 | Ensure no root account access key exists    | 1 | Yes | Yes | Config Rule | RootAccoutMustHaveMfaEnabled |
|  1.13 | Ensure MFA is enabled for the "root" account  | 2 | Yes | Yes | Config Rule | RootAccoutMustHaveMfaEnabled |
|  1.14 | Ensure hardware MFA is enabled for the "root" account    | 2 | Yes | Yes | Config Rule | RootAccoutMustHaveMfaEnabled |
|  1.15 | Ensure security questions are registered in the AWS account  | 1 | No | No |  |  |
|  1.16 | Ensure IAM policies are attached only to groups or roles    | 1 | Yes | Yes | Config Rule | UsersMustNotHaveAssociatedPolicies |
|  1.17 | Enable detailed billing  | 1 | Yes | No |  |  |
|  1.18 | Ensure IAM Master and IAM Manager roles are active  | 1 | Yes | No |  |  |
|  1.19 | Maintain current contact details  | 1 | Yes | No |  |  |
|  1.2 | Ensure security contact information is registered  | 1 | Yes | No |  |  |
|  1.21 | Ensure IAM instance roles are used for AWS resource access from instances | 2 | No | Yes | Config Rule | InstancesMustUseIamRoles |
|  1.22 | Ensure a support role has been created to manage incidents with AWS Support   | 1 | Yes | No |  |  |
|  1.23 | Do not setup access keys during initial user setup for all IAM users that have a console password  | 1 | No | No |  |  |
|  1.24 | Ensure IAM policies that allow full "*:*" administrative privileges are not created  | 1 | Yes | Yes | Config Rule | IamPoliciesMustNotContainStarStar |
|  2 | *Logging* |  |  |  |  |  |
|  2.1 | Ensure CloudTrail is enabled in all regions  | 1 | Yes | Yes | Config Rule | CloudTrailMustBeActive |
|  2.2 | Ensure CloudTrail log file validation is enabled    | 2 | Yes | Yes | Config Rule | CloudTrailLogsMustBeValidatedAndEncrypted |
|  2.3 | Ensure the S3 bucket CloudTrail logs to is not publicly accessible    | 1 | Yes | Yes | Config Rule | CloudTrailBucketMustBeSecure |
|  2.4 | Ensure CloudTrail trails are integrated with CloudWatch Logs    | 1 | Yes | Yes | Config Rule | CloudTrailMustBeActive |
|  2.5 | Ensure AWS Config is enabled in all regions  | 1 | Yes | Yes | Config Rule | ConfigMustBeEnabledInAllRegions |
|  2.6 | Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket  | 1 | Yes | Yes | Config Rule | CloudTrailBucketMustBeSecure |
|  2.7 | Ensure CloudTrail logs are encrypted at rest using KMS CMKs    | 2 | Yes | Yes | Config Rule | CloudTrailLogsMustBeValidatedAndEncrypted |
|  2.8 | Ensure rotation for customer created CMKs is enabled  | 2 | Yes | Yes | Config Rule | KmsCustomerKeysMustBeRotated |
|  3 | *Monitoring* |  |  |  |  |  |
|  3.1 | Ensure a log metric filter and alarm exist for unauthorized API calls    | 1 | Yes | Yes | CloudWatch Alarm | UnauthorizedAttemptsCloudWatchFilter |
|  3.2 | Ensure a log metric filter and alarm exist for Management Console sign-in without MFA    | 1 | Yes | Yes | CloudWatch Alarm | ConsoleSigninWithoutMfaCloudWatchMetric |
|  3.3 | Ensure a log metric filter and alarm exist for usage of "root" account  | 1 | Yes | Yes | CloudWatch Alarm | IAMRootActivityCloudWatchMetric |
|  3.4 | Ensure a log metric filter and alarm exist for IAM policy changes  | 1 | Yes | Yes | CloudWatch Rule | DetectIamPolicyChanges |
|  3.5 | Ensure a log metric filter and alarm exist for CloudTrail configuration changes  | 1 | Yes | Yes | CloudWatch Rule | DetectCloudTrailChanges |
|  3.6 | Ensure a log metric filter and alarm exist for AWS Management Console authentication failures  | 2 | Yes | Yes | CloudWatch Alarm | ConsoleLoginFailureCloudWatchMetric |
|  3.7 | Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs  | 2 | Yes | Yes | CloudWatch Alarm | KMSCustomerKeyDeletionCloudWatchMetric |
|  3.8 | Ensure a log metric filter and alarm exist for S3 bucket policy changes    | 1 | Yes | Yes | CloudWatch Rule | DetectS3BucketPolicyChanges |
|  3.9 | Ensure a log metric filter and alarm exist for AWS Config configuration changes    | 2 | Yes | Yes | CloudWatch Rule | DetectConfigChanges |
|  3.1 | Ensure a log metric filter and alarm exist for security group changes    | 2 | Yes | Yes | CloudWatch Rule | DetectSecurityGroupChanges |
|  3.11 | Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)    | 2 | Yes | Yes | CloudWatch Rule | DetectNetworkAclChanges |
|  3.12 | Ensure a log metric filter and alarm exist for changes to network gateways    | 1 | Yes | Yes | CloudWatch Rule | DetectNetworkChangeEvents |
|  3.13 | Ensure a log metric filter and alarm exist for route table changes    | 1 | Yes | Yes | CloudWatch Rule | DetectNetworkChangeEvents |
|  3.14 | Ensure a log metric filter and alarm exist for VPC changes    | 1 | Yes | Yes | CloudWatch Rule | DetectNetworkChangeEvents |
|  3.15 | Ensure appropriate subscribers to each SNS topic  | 1 | Yes | Yes | CloudWatch Rule | DetectNetworkChangeEvents |
|  4 | *Networking* |  |  |  |  |  |
|  4.1 | Ensure no security groups allow ingress from 0.0.0.0/0 to port 22  | 2 | Yes | Yes | Config Rule | SecurityGroupsMustRestrictSshTraffic |
|  4.2 | Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389  | 2 | Yes | Yes | Config Rule | SecurityGroupsMustDisallowTcpTraffic |
|  4.3 | Ensure VPC flow logging is enabled in all VPCs  | 2 | Yes | Yes | Config Rule | VpcsMustHaveFlowLogs |
|  4.4 | Ensure the default security group of every VPC restricts all traffic  | 2 | Yes | Yes | Config Rule | VpcDefaultSecurityGroupsMustRestrictAllTraffic |
|  4.5 | Ensure routing tables for VPC peering are "least access"  | 2 | No | Yes | Config Rule | VpcPeeringRouteTablesMustBeLeastAccess |
