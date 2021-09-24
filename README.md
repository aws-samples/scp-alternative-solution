# SCP Alternative Solution For China Region

AWS Organizations provides central governance and management for multiple accounts. Central security administrators use [service control policies (SCPs)](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html) with AWS Organizations to establish controls that all IAM principals (users and roles) adhere to.

However Service Control Policies (SCPs) feature in AWS Organizations is not available in the China regions (BJS and ZHY) yet as of Sep 2021.

This repository is part of [the CN blog post](https://aws.amazon.com/cn/blogs/china/scp-alternative-based-on-iam-permission-boundaries/) that guides users through implementing a SCP Alternative Solution for China Region from scratch.

## Rationale

Before we dive into the architecture, let’s learn more about SCPs in the context of IAM. SCPs are similar to IAM permission policies and use a common syntax. The difference being, an SCP never grants permissions. Instead, SCPs are JSON policies that specify the maximum permissions for the affected accounts.

![PolicyEvaluationHorizontal.png](docs/images/PolicyEvaluationHorizontal.png)

In an AWS account where SCP is applied, the above flow chart provides details about [how the decision is made](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html#policy-eval-denyallow).

SCPs are similar to IAM boundaries, in that they define the maximum set of actions that can be allowed. The difference is that SCPs applies to principals of accounts, and IAM permission boundary applies to principals of IAM users and roles.

Based on the rationale above, the SCP alternative solution is to implement a automated way to ensure the "SCP policies" are applied to all IAM user/roles within the account by IAM permission boundary.

## Architecture Overview

The purpose of the design is to simulate the native SCP as possible as we can, also considering the migration path to native SCP once it’s available.

![scp-to-be-architecture](docs/images/scp-alternative-solution.png)

The architecture is based on AWS native services, the core AWS services used are:

* *S3 bucket*: used to store SCP custom policies. In nativ SCP provided by AWS Organizations, users can directly edit and update the SCP policy file through the console. In this alternative design, the SCP policy files are updated in a dedicated S3 bucket of the security account, and the corresponding event notification is configured for the bucket to detect any changes for the updates of the SCP policies.
* *SCP Service Catalog*: Provides a friendly user interface for administrators to manually register accounts that need to apply the SCP policies. In native SCP provided by AWS Organizations, by using the account structure created in AWS Organizations, it can apply SCP policy on the account or organizational unit level. In this alternative design, all accounts that need to apply the SCP policies need to manually register and initilized from this SCP Service Catalog Product.
* *Event Rule and CloudTrail*: Continuously monitor the API activities of newly created IAM users or roles in the account, and send the events to the Lambda of the security account for further processing, and apply the IAM Permission Boundary to the newly created IAM users and roles. In the native SCP provided by AWS Organizations, the SCP policy is applied to the entire account, and any newly created IAM users and roles will automatically apply the SCP policy. Since this solution is based on IAM Permission Boundary, whenever a new user or role is created, it's required to ensure that the newly created user or role also applies the IAM Permission Boundary.
* **Lambda functions**:
    * *scp-account-register*: used to register and initialize the account that needs to be apply the SCP policy, and store the account information in DynamoDB for other Lambda functions to query account related info.
    * *scp-iam-event-dispatcher*: Used to receive events of newly created IAM users and roles in registered accounts, and apply the corresponding IAM Permission Boundary to the newly created IAM users or roles
    * *scp-s3-event-dispatcher*: Used to receive the update event of the policy file in the S3 bucket, and automatically update the IAM permission boundary policy accroding to the updated SCP policy file in the registered accounts.
* *SNS*: Used to receive information about the failure of SCP policy creation and binding. The security administrator can opt-in to subscribe to the SNS Topic to get timely failure notifications
* *DynamoDB*: It is used to store the registered account meta-information for query. The format of the stored information is as follows:

|AccountId|MgtId|OuId|ScpCustomPolicyList (L)|ScpPolicyPathList (L)|ScpUpdateTime (S)|
| --- | ----------- | --- | ----------- | --- | ----------- |
|1123456789|2123456789|OU-abcd-xxxxxxxx|[ { "S" : "arn:aws-cn:iam::1123456789:policy/CustomPermissionBoundaries" }]|[ { "S" : "permission-boundary-policy/ou-abcd-xxxxxxxxx.json" }]|Tue Jul 20 11:00:38 2021|

## Deployment

The infrastructure required in this solution can be deployed by the CloudFormation templates.

### Build Artifacts

Clone the repository, and switch to the top-level folder of the repo. Run `make` command:

```bash
➜  make
zip assets/scp-s3-event-dispatcher.zip lambda/scp-s3-event-dispatcher.py
updating: lambda/scp-s3-event-dispatcher.py (deflated 74%)
zip assets/scp-iam-event-dispatcher.zip lambda/scp-iam-event-dispatcher.py
updating: lambda/scp-iam-event-dispatcher.py (deflated 77%)
zip assets/scp-account-register.zip lambda/scp-account-register.py
updating: lambda/scp-account-register.py (deflated 77%)
cp -f cloudformation/scp-service-catalog-product-template.yaml assets/scp-service-catalog-product-template.yaml
```

The lambda artifacts and the required cloudformation template are created under `assets` directory:

```
➜  ls assets
scp-account-register.zip                  scp-s3-event-dispatcher.zip
scp-iam-event-dispatcher.zip              scp-service-catalog-product-template.yaml
```

### Deployment for Management Account

Log in to the management account, select the CloudFormation template file [010-create-iam-role-in-master-account.yaml](cloudformation/010-create-iam-role-in-master-account.yaml), and create an IAM role that allows the security account to assume to:

* **ManagementAccountAccessRoleName**: - The name of the role deployed in the management account, used to allow the security account to assume to the management account, ensure that the parameters deployed under the security account are consistent
* **OrganizationAccessRoleName**: - The name of the role deployed in all member accounts, used to allow the management account Assume to each member account, ensure that the parameters deployed under the security account are consistent
* **SecurityAccountID**: The AWS Security Account ID

### Deployment for Security Account

Login to Security account and perform the following deployment:

* Select the CloudFormation template file [020-create-s3-bucket-in-security-account.yaml](cloudformation/020-create-s3-bucket-in-security-account.yaml) to create an S3 bucket for CloudFormation deployment.
    * *Note*: The SCP policy files should be uploaded to the bucket folder **permission-boundary-policy** in the security account, The naming convention of the policy files are:
        * Account-level policy file: `account-<ACCOUNT-ID>.json`
        * Organization unit level file: `<OrganizationUnit-ID>.json`
* The assets file has been created in step __Build Artifacts__. Upload all the files in the assets directory to the root directory of the above S3 bucket.
* Select the CloudFormation template file [030-create-scp-infra-in-security-account.yaml](cloudformation/030-create-scp-infra-in-security-account.yaml) to create the required infrastructure.
    * **ManagementAccountID**: The AWS management Account ID
    * **ManagementAccountAccessRoleName**: The name of the role deployed in the management account, used to allow the security account to assume to the management account, ensure that the parameters deployed under the management account are consistent
    * **OrganizationAccessRoleName**: The name of the role deployed in all member accounts, used to allow the management account to assume to each member account, ensure that the parameters deployed under the management account are consistent
    * **SCPCatalogAdministrator**: The name of the IAM role/user deployed under the security account, this role/user will be the administrator of the Service Catalog Product of the SCP Account Register
        * IAM Role: e.g role/Operation
        * IAM User: e.g user/Alice

### Limitation

This is a SCP workaround solution by using AWS IAM's permission boundary, the user should be aware of the limitations prior to using it:

1. Since it is based on AWS IAM's permission boundary, which is essentially an IAM managed policy. The size of each managed policy cannot exceed 6,144 characters per the [doc](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html#reference_iam-quotas-entity-length).
1. The feature [SCP policy inheritance](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_inheritance.html) in AWS Organizations is not supported in the alternative solution. It's required to create the policy in S3 bucket for each organization unit.
1. The infra resources created for the solution in registered accounts are not allowed to be modified, these `Deny` actions will be appended to the default IAM permission boundary policy by default.
1. The core resources in the solution are deployed in security account, it's crucial to ensure the actions executed in the lambda functions won't be affected by attached IAM permission boundary policy. By default it's not allowed to register the security account into the SCP service catalog.
1. During the creation of the IAM permission boundary for the registered accounts, it's required to assume to the registered accounts from the master accounts to manage the IAM permission boundary policy. To avoid the permission issues caused by the attached IAM permission boundary policy, the IAM admin role (`OrganizationAccountAccessRole` by default) is reserved to not attach any IAM permission boundary policies. The user can specify arbitary role name by CloudFormation parameter `OrganizationAccessRoleName` during the deployment.

### Recommendation

As the services and features in AWS China regions are moving very quickly, it's highly recommended to move to native SCP feature once it's available in AWS China regions.

## License

This sample code is made available under the MIT-0 license. See the LICENSE file.
