# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

#!/usr/bin/env python
# coding=utf-8

import json
import os
import sys
import time
import boto3
import copy
import re
from collections import OrderedDict
from hashlib import blake2b
from boto3.dynamodb.conditions import Key

s3_client = boto3.client("s3")
sns_client = boto3.client("sns")
iam_client = boto3.client("iam")
dynamodb_resource = boto3.resource("dynamodb")

DYNAMODB_TABLE_ARN = os.environ["DYNAMODB_TABLE_ARN"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
S3_BUCKET_NAME = os.environ["S3_BUCKET_NAME"]
ORGANIZATION_ROLE = os.environ["ORGANIZATION_ROLE"]
S3_OBJECT_FOLDER = os.environ["S3_OBJECT_FOLDER"]
PERMISSION_BOUNDARY_NAME = os.environ["PERMISSION_BOUNDARY_NAME"]
MANAGEMENT_ACCOUNT_ID = os.environ["MANAGEMENT_ACCOUNT_ID"]
MANAGEMENT_ACCOUNT_ACCESS_ROLE = os.environ["MANAGEMENT_ACCOUNT_ACCESS_ROLE"]

dynamodb_table = dynamodb_resource.Table(DYNAMODB_TABLE_ARN.split("/")[-1])
MAX_POLICY_VERSIONS = 5
MANAGED_POLICY_LIMIT = 6144
REGION_NAME="cn-north-1"
BLAKE2B_DIGEST_SIZE = 2
BLAKE2B_INPUT_ENCODING = "utf-8"
HASH_PREFIX_NUM = 5

# The permission boundary won't be attached to the roles below
IAM_ROLE_WHITELIST = [ORGANIZATION_ROLE]
IAM_USER_WHITELIST = []

ACCOUNT_EVENT_RULE_NAME = "scp-event-rule"
ACCOUNT_BUCKET_PREFIX = "scp-trail-bucket"
ACCOUNT_TRAIL_NAME = "scp-trail"
SCP_ENFORCE_POLICY = [
    {
        "Sid": "EnforceDeny1",
        "Effect": "Deny",
        "Action": [
            "iam:DeleteUserPermissionsBoundary",
            "iam:DeleteRolePermissionsBoundary"
        ],
        "Resource": "*",
        "Condition": {
            "ArnNotLike": {
                "aws:PrincipalArn": "arn:aws-cn:iam::*:role/{0}".format(ORGANIZATION_ROLE)
            }
        }
    },
    {
        "Sid": "EnforceDeny2",
        "Effect": "Deny",
        "Action": "*",
        "Resource": [
            "arn:aws-cn:iam::*:policy/{0}".format(PERMISSION_BOUNDARY_NAME),
            "arn:aws-cn:cloudtrail:*:*:trail/{0}".format(ACCOUNT_TRAIL_NAME),
            "arn:aws-cn:s3:::{0}-<ACCOUNT_ID>".format(ACCOUNT_BUCKET_PREFIX),
            "arn:aws-cn:events:*:*:rule/{0}".format(ACCOUNT_EVENT_RULE_NAME),
            "arn:aws-cn:iam::*:role/{0}".format(ORGANIZATION_ROLE)
        ],
        "Condition": {
            "ArnNotLike": {
                "aws:PrincipalArn": "arn:aws-cn:iam::*:role/{0}".format(ORGANIZATION_ROLE)
            }
        }
    }
]

def failure_notify(message, subject="Failure when executing SCP lambda"):
    """
    Send the failure message to SNS.
    """
    subject = "[AWS Lambda]:" + subject
    json_message = {"Error": str(message)}
    print("Failure captured! Subject: {0}; Message: {1}".format(subject, json_message))
    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=json.dumps(json_message, indent=2))

    sys.exit(1)

def get_aws_partition(context):
    return context.invoked_function_arn.split(":")[1]

def master_acount_org_session(service="organizations",
                              region_name=REGION_NAME,
                              mgt_account_id=None,
                              account_id=None):

    local_sts_client = boto3.client('sts')

    assume_role_arn = "arn:" + "aws-cn" + ":iam::" \
                    + mgt_account_id + ":role/" + MANAGEMENT_ACCOUNT_ACCESS_ROLE
    member_assume_role_arn = "arn:" + "aws-cn" + ":iam::" \
                    + account_id + ":role/" + ORGANIZATION_ROLE

    Management_Account_Credentials = local_sts_client.assume_role(
        RoleArn=assume_role_arn,
        RoleSessionName=MANAGEMENT_ACCOUNT_ID,
        DurationSeconds=900)

    management_account_access_key=Management_Account_Credentials['Credentials']['AccessKeyId']
    management_account_secret_access_key=Management_Account_Credentials['Credentials']['SecretAccessKey']
    management_account_session_token=Management_Account_Credentials['Credentials']['SessionToken']

    member_account_client = boto3.client('sts',aws_access_key_id=management_account_access_key,aws_secret_access_key=management_account_secret_access_key,aws_session_token=management_account_session_token,)
    member_sts_connection = member_account_client.assume_role(
	    RoleArn=member_assume_role_arn,
        RoleSessionName="cross_mem_acct_lambda"
    )

    mem_ACCESS_KEY = member_sts_connection['Credentials']['AccessKeyId']
    mem_SECRET_KEY = member_sts_connection['Credentials']['SecretAccessKey']
    mem_SESSION_TOKEN=member_sts_connection['Credentials']['SessionToken']

    client = boto3.client(service,
        aws_access_key_id = mem_ACCESS_KEY,
        aws_secret_access_key= mem_SECRET_KEY,
        aws_session_token = mem_SESSION_TOKEN )

    return client


def exact_object_key(object_key):
    """
    Exact the BU account id, AWS organization unit, account id from object_key

    object_key:
      permission-bounday-policy/ou-47kj-8dquliyv.json
      permission-bounday-policy/781422229198.json
    """
    ou_id = ""
    account_id = ""

    object_key_list = object_key.split("/")
    object_key_basename = object_key_list[1]

    ou_m = re.match("(ou-[0-9a-z]+-[0-9a-z]+).json", object_key_basename)
    account_m = re.match("account-([0-9]+).json", object_key_basename)

    if account_m:
        account_id = account_m.group(1)
    elif ou_m:
        ou_id = ou_m.group(1)
    else:
        failure_notify(
            "This is invalid object_key {0}, please check the event setting."
            .format(object_key))

    return ou_id, account_id

def get_event_details(records):
    """
    Pre-process the records from the sqs and s3

    @param records: The native events from S3 or SQS
    @return: The event list
    """
    details = []
    for record in records:
        # identify if the record is from sqs
        if "body" in record:
            record_body = json.loads(record["body"])
            details.append(record_body['detail'])
        else:
            details.append(record)
    return details

def read_s3_object(s3_bucket_name, s3_object_key):
    """
    Read the S3 object per the S3 bucket and S3 object key.
    """
    try:
        s3_object = s3_client.get_object(Bucket=s3_bucket_name, Key=s3_object_key)
        body = s3_object['Body']
    except Exception as e:
        msg = "Failed to read object key {0} from bucket {1}, Error: {2}".format(
            s3_object_key,
            s3_bucket_name,
            e
            )
        failure_notify(msg)

    return body.read()

def to_list(item):
    """
    Wrap almost anything besides list into a list.
    If the input item is a tuple, covert it to a list.
    """
    if isinstance(item, tuple):
        item = list(item)
    elif not isinstance(item, list):
        item = [item]
    return item

def extract_sid_prefix(s3_object_key):
    """
    Convert the inputted s3_object_key into a prefix for PolicyStatement.
    """
    base = s3_object_key.rstrip(".json")
    return re.sub("[\W_]", "", base)

def get_str_length(policy):
    """
    Caculate the number of the string against a given json.
    """
    str_policy  = str(policy).split(' ')
    num = 0
    for alpha in str_policy:
        num = num + len(alpha)

    return num

def blake2b_hash(string):
    """handy hash function for unique ID generation."""
    return blake2b(
        string.encode(BLAKE2B_INPUT_ENCODING), digest_size=BLAKE2B_DIGEST_SIZE
    ).hexdigest()

def is_valid_role(iam_client, role_name):
    try:
        response = iam_client.get_role(
            RoleName=role_name
            )
    except Exception as e:
        msg = "Failed to get role {0} in the account {1}".format(role_name, e)
        failure_notify(msg)
    # exclude the service role
    role_path_prefix = response["Role"]["Path"].split("/")[1]

    if ((role_name not in IAM_ROLE_WHITELIST) and (role_path_prefix != "aws-service-role")):
        return True
    else:
        print("Role {0} is either in whitelist or service linked role"
              .format(role_name))
        return False

def is_valid_user(iam_client, user_name):
    try:
        response = iam_client.get_user(
            UserName=user_name
            )
    except Exception as e:
        msg = "Failed to get user {0} in the account {1}".format(user_name, e)
        failure_notify(msg)

    if user_name not in IAM_USER_WHITELIST:
        return True
    else:
        print("User {0} is in whitelist"
              .format(user_name))
        return False

def bind_permission_boundary_role(iam_client, role_name, permission_boundary_arn):
    try:
        iam_client.put_role_permissions_boundary(
            RoleName = role_name,
            PermissionsBoundary = permission_boundary_arn
        )
        print("Role {0} has been bind to permission boundary policy {1}".format(role_name, permission_boundary_arn))
    except Exception as e:
        msg = "Failed to bind permission boundary policy {0} to role {1} due to exceptional {2}".format(permission_boundary_arn, role_name, e)
        failure_notify(msg)

def bind_permission_boundary_user(iam_client, user_name, permission_boundary_arn):
    try:
        iam_client.put_user_permissions_boundary(
            UserName = user_name,
            PermissionsBoundary = permission_boundary_arn
        )
        print("User {0} has been bind to permission boundary policy {1}".format(user_name, permission_boundary_arn))
    except Exception as e:
        msg = "Failed to bind permission boundary policy {0} to role {1} due to exceptional {2}".format(permission_boundary_arn, user_name, e)
        failure_notify(msg)

def attach_to_role(iam_client, role_name, policy_arn):
    """
    Attaches a policy to a role.
    :param role_name: The name of the role. **Note** this is the name, not the ARN.
    :param policy_arn: The ARN of the policy.
    """
    try:
        iam_client.Policy(policy_arn).attach_role(RoleName=role_name)
        logger.info("Attached policy %s to role %s.", policy_arn, role_name)
    except iam_client.exceptions.ClientError:
        logger.exception("Couldn't attach policy %s to role %s.", policy_arn, role_name)
        raise

def generate_policy_statement_sid(s3_object_key):
    """
    Generate an unique PolicyStatement ID for the inputted s3_object.
        prefix => the value returned by extract_sid_prefix(s3_object.key)
        suffix => empty string or hash value of either the original PolicyStatement ID or the PolicyStatement dumps
    """
    sid_prefix = extract_sid_prefix(s3_object_key)
    sid_prefix_hash = blake2b_hash(sid_prefix)[:HASH_PREFIX_NUM]
    return "%s" % (sid_prefix_hash)

def create_policy_statement(s3_bucket_name, s3_object_key):
    """
    Create policy statement per the S3 bucket name, S3 object key
    """
    policy_version_document_json = {"Version": "2012-10-17", "Statement": []}
    try:
        s3_object_content = read_s3_object(s3_bucket_name, s3_object_key)
        # ignore empty policy statement
        if not s3_object_content.strip():
            print(
                "Skipping empty json object: %s/%s"
                % (s3_bucket_name, s3_object_key)
            )
        policy_statement_json = json.loads(
            s3_object_content, object_pairs_hook=OrderedDict
        )
    except json.JSONDecodeError as e:
        # ignore malformed policy statement
        print(
            "Skipping malformed json object: %s/%s"
            % (s3_bucket_name, s3_object_key)
        )
        print("Error message: %s" % e)
    except Exception as e:
        # something unexpected
        failure_notify(e)

    # The format of the content of the policy statements may vary, we do our best to regulate it
    if not isinstance(policy_statement_json, dict) or "Statement" not in policy_statement_json:
        msg = "The object is not a valid IAM policy: {0}".format(policy_statement_json)
        failure_notify(msg)

    policy_statement_json = policy_statement_json["Statement"]
    policy_statement_json = to_list(policy_statement_json)

    # Merge the SCP enforced policy to user defined policy
    policy_statement_json = policy_statement_json + SCP_ENFORCE_POLICY

    statement_sid = generate_policy_statement_sid(s3_object_key)
    for index, stmt in enumerate(policy_statement_json):
        # generate a conventional sid for each statements and overwrite the original one in the file (if present)
        stmt["Sid"] = statement_sid + str(index)
        policy_version_document_json["Statement"].append(stmt)
    print(
        "policy_version_document_json after upsert(%s, %s): %s"
        % (s3_bucket_name, s3_object_key, policy_version_document_json)
    )

    if get_str_length(policy_version_document_json) > MANAGED_POLICY_LIMIT:
        failure_notify(
            "The generated policy %s exceeded the max string limit %s".format(
                policy_version_document_json, MANAGED_POLICY_LIMIT
                )
        )

    return policy_version_document_json

def render_policy(policy, account):
    render_policy = json.loads(json.dumps(policy).replace('<ACCOUNT_ID>', account))
    print("Created render policy in account {0}: {1}".format(account, render_policy))
    return render_policy

def assume_role(sts_client, account, context, service="iam"):
    assume_role_arn = "arn:" + get_aws_partition(context) + ":iam::" \
                    + account + ":role/" + ORGANIZATION_ROLE
    Credentials = sts_client.assume_role(
        RoleArn=assume_role_arn,
        RoleSessionName=account,
        DurationSeconds=900)

    client = boto3.client(
        service,
        aws_access_key_id=Credentials['Credentials']['AccessKeyId'],
        aws_secret_access_key=Credentials['Credentials']['SecretAccessKey'],
        aws_session_token=Credentials['Credentials']['SessionToken'])

    return client

def process_permission_boundary_to_role(target_iam_client,
                                        policy_arn,
                                        account,
                                        render_policy_version_document_json,
                                        s3_object_key,
                                        event):
    """
    Main function to process the permission boundary for roles
    """

    role_name = event['requestParameters']['roleName']
    print("Processing role {0}".format(role_name))
    if is_valid_role(target_iam_client, role_name):
        response = target_iam_client.get_role(RoleName=role_name)
        role_permission_boundary_arn = ""

        if "PermissionsBoundary" in response["Role"]:
            role_permission_boundary_arn = response["Role"]["PermissionsBoundary"]["PermissionsBoundaryArn"]
        if not role_permission_boundary_arn:
            bind_permission_boundary_role(target_iam_client, role_name, policy_arn)
        elif role_permission_boundary_arn != policy_arn:
            append_item_to_list(account, 'ScpCustomPolicyList', role_permission_boundary_arn)
            policy_reponse = target_iam_client.get_policy(PolicyArn=role_permission_boundary_arn)
            default_version_id = policy_reponse["Policy"]["DefaultVersionId"]
            target_policy_version = target_iam_client.get_policy_version(
                PolicyArn=role_permission_boundary_arn,
                VersionId=default_version_id
            )

            target_policy_version_document_json = target_policy_version["PolicyVersion"]["Document"]
            consolidated_policy_json = consolidate_permission_boundary_arn(
                                      source_policy=render_policy_version_document_json,
                                      target_policy=target_policy_version_document_json,
                                      sid_prefix=generate_policy_statement_sid(s3_object_key))
            delete_oldest_policy_versions(target_iam_client, role_permission_boundary_arn)
            print("Setting it as the default policy version for {0}".format(role_permission_boundary_arn))
            try:
                print("Creating policy version for policy arn {0}"
                      .format(role_permission_boundary_arn))
                policy_version_resp = target_iam_client.create_policy_version(
                    PolicyArn=role_permission_boundary_arn,
                    PolicyDocument=json.dumps(consolidated_policy_json),
                    SetAsDefault=True,
                )
            except Exception as e:
                failure_notify(e)

def process_permission_boundary_to_user(target_iam_client,
                                        policy_arn,
                                        account,
                                        render_policy_version_document_json,
                                        s3_object_key,
                                        event):
    """
    Main function to process the permission boundary for IAM user
    """
    user_name = event['requestParameters']['userName']
    print("Processing user {0}".format(user_name))
    if is_valid_user(target_iam_client, user_name):
        response = target_iam_client.get_user(UserName=user_name)
        user_permission_boundary_arn = ""
        if "PermissionsBoundary" in response["User"]:
           user_permission_boundary_arn = response["User"]["PermissionsBoundary"]["PermissionsBoundaryArn"]
        if not user_permission_boundary_arn:
            bind_permission_boundary_user(target_iam_client, user_name, policy_arn)
        elif user_permission_boundary_arn != policy_arn:
            append_item_to_list(account, 'ScpCustomPolicyList', user_permission_boundary_arn)
            policy_reponse = target_iam_client.get_policy(PolicyArn=user_permission_boundary_arn)
            default_version_id = policy_reponse["Policy"]["DefaultVersionId"]
            target_policy_version = target_iam_client.get_policy_version(
                PolicyArn=user_permission_boundary_arn,
                VersionId=default_version_id
            )

            target_policy_version_document_json = target_policy_version["PolicyVersion"]["Document"]
            consolidated_policy_json = consolidate_permission_boundary_arn(
                                      source_policy=render_policy_version_document_json,
                                      target_policy=target_policy_version_document_json,
                                      sid_prefix=generate_policy_statement_sid(s3_object_key))
            delete_oldest_policy_versions(target_iam_client, user_permission_boundary_arn)
            print("Setting it as the default policy version for {0}".format(user_permission_boundary_arn))
            try:
                print("Creating policy version for policy arn {0}"
                      .format(user_permission_boundary_arn))
                policy_version_resp = target_iam_client.create_policy_version(
                    PolicyArn=user_permission_boundary_arn,
                    PolicyDocument=json.dumps(consolidated_policy_json),
                    SetAsDefault=True,
                )
            except Exception as e:
                failure_notify(e)

def delete_oldest_policy_versions(iam_client, policy_arn):
    """
    Delete the oldest non-default PolicyVersions until we can assure the success of a new PolicyVersion creation.
    """
    policy_versions = sorted(
        iam_client.list_policy_versions(PolicyArn=policy_arn)["Versions"],
        key=lambda x: (x["IsDefaultVersion"], x["CreateDate"]),
    )
    while len(policy_versions) >= MAX_POLICY_VERSIONS:
        policy_version_to_delete = policy_versions.pop(0)
        print("PolicyVersion to delete: %r" % policy_version_to_delete)
        iam_client.delete_policy_version(
            PolicyArn = policy_arn,
            VersionId = policy_version_to_delete["VersionId"]
        )

def create_policy_in_account(policy_version_document_json,
                             account,
                             context,
                             s3_object_key, event):
    """
    Create the global permission boundary in the target account.
    """
    render_policy_version_document_json = render_policy(
                policy_version_document_json, account)

    sts_client = master_acount_org_session(service="sts", mgt_account_id=MANAGEMENT_ACCOUNT_ID,account_id=account)
    target_iam_client = assume_role(sts_client, account, context)
    policy_arn = "arn:" + get_aws_partition(context) + ":iam::" + account \
            + ":policy/" + PERMISSION_BOUNDARY_NAME

    if render_policy_version_document_json:
        # Create a base permission boundary policy if it doesn't exist in the
        # target account.
        try:
            target_iam_client.get_policy(PolicyArn=policy_arn)
        except target_iam_client.exceptions.NoSuchEntityException:
            print("Policy arn {0} not found, creating...".format(policy_arn))
            try:
                target_iam_client.create_policy(
                    PolicyName=PERMISSION_BOUNDARY_NAME,
                    PolicyDocument=json.dumps(render_policy_version_document_json)
                )
            except Exception as e:
                failure_notify(e)
        except Exception as e:
                failure_notify(e)
        else:
            delete_oldest_policy_versions(target_iam_client, policy_arn)
            print("Setting it as the default policy version for {0}".format(policy_arn))
            try:
                print("Creating policy version for policy arn {0}"
                      .format(policy_arn))
                policy_version_resp = target_iam_client.create_policy_version(
                    PolicyArn=policy_arn,
                    PolicyDocument=json.dumps(render_policy_version_document_json),
                    SetAsDefault=True,
                )
            except Exception as e:
                failure_notify(e)

    if event['eventName'] == "CreateUser":
        process_permission_boundary_to_user(target_iam_client,
                                            policy_arn,
                                            account,
                                            render_policy_version_document_json,
                                            s3_object_key,
                                            event)
    elif event['eventName'] == "CreateRole":
        process_permission_boundary_to_role(target_iam_client,
                                            policy_arn,
                                            account,
                                            render_policy_version_document_json,
                                            s3_object_key,
                                            event)

def consolidate_permission_boundary_arn(source_policy, target_policy, sid_prefix):
    """
    Consolidate the global permission boundary and the custom permission boundary
    """
    tmp_policy = copy.deepcopy(source_policy)

    for stmt in target_policy["Statement"]:
        if (
            "Sid" not in stmt
            or stmt["Sid"][0 : len(sid_prefix)]
            != sid_prefix
        ):
            tmp_policy["Statement"].append(stmt)

    print("The consolidated policy json {0}".format(tmp_policy))

    if get_str_length(tmp_policy) > MANAGED_POLICY_LIMIT:
        failure_notify(
            "The generated policy %s exceeded the max string limit %s".format(
                tmp_policy, MANAGED_POLICY_LIMIT
                )
        )

    return tmp_policy

def check_s3_object_exists(bucket_name, object_key):
    """
    Check if the s3 object exists.
    """
    try:
        s3_client.head_object(Bucket=bucket_name, Key=object_key)
    except Exception as e:
        print("The s3 object key {0} doesn't exist in bucket {1}, error {2}"
              .format(object_key, bucket_name, e))
        return False
    return True

def get_valid_object_key(mgt_account_id, ou_id, account_id):
    """
    Get the valid object key from the environment variables.
    """
    valid_object_key_list = []
    if not mgt_account_id:
        failure_notify("Please input a valid Management Account ID")

    if account_id:
        object_key = "{0}/account-{1}.json".format(
            S3_OBJECT_FOLDER,
            account_id)
        if check_s3_object_exists(S3_BUCKET_NAME, object_key):
            valid_object_key_list.append(object_key)
            return valid_object_key_list

    if ou_id:
        object_key = "{0}/{1}.json".format(
            S3_OBJECT_FOLDER,
            ou_id)
        if check_s3_object_exists(S3_BUCKET_NAME, object_key):
            valid_object_key_list.append(object_key)

    if not valid_object_key_list:
        failure_notify("Please input a valid OU_ID or ACCOUNT_ID")

    return valid_object_key_list


def exact_account(source_account_id):
    try:
        response = dynamodb_table.get_item(Key={'AccountId': source_account_id})
    except Exception as e:
        failure_notify("Unable to query account id {0}, detailed exception {1}".format(source_account_id, e))
    print(response)

    mgt_account_id = response['Item']['MgtId']
    ou_id = response['Item']['OuId']

    return mgt_account_id, ou_id, source_account_id

def append_item_to_list(account_id, key, value):
    try:
        get_response = dynamodb_table.get_item(Key={'AccountId': account_id})
    except Exception as e:
        failure_notify('Failed to get item {0}, detailed failure: {1}'.format(account_id, e))

    current_value =  get_response['Item'].get(key, [])

    if not current_value:
        current_value = []

    if value not in current_value:
        current_value.append(value)
        update_item(account_id, key, current_value)
    else:
        print("Current value is {0} which contains {1}".format(current_value, value))

def update_item(account_id, key, value):
    try:
        update_exp = "set {0}=:value".format(key)
        dynamodb_table.update_item(
            Key={
                'AccountId': account_id
            },
            UpdateExpression=update_exp,
            ExpressionAttributeValues={
                ':value': value
            },
            ReturnValues="UPDATED_NEW"
        )
    except Exception as e:
        failure_notify('Failed to write item {0} to {1}, detailed failure: {1}'.format(value, account_id, e))

def get_current_time():
    t = time.ctime()
    return t

def main(event, context):
    """
    Main handler of the lambda function which tries to bind the
    permission boundary policy to IAM roles/users.
    """
    bucket_name = S3_BUCKET_NAME

    if 'Records' in event:
        details = get_event_details(event['Records'])
    for detail in details:
        print("Event detail: {0}".format(detail))
        source_account_id = detail["userIdentity"]["accountId"]
        mgt_account_id, ou_id, account_id = exact_account(source_account_id)

        for object_key in get_valid_object_key(mgt_account_id=mgt_account_id, ou_id=ou_id, account_id=account_id):
            append_item_to_list(account_id, 'ScpPolicyPathList', object_key)
            policy_version_document_json = create_policy_statement(bucket_name, object_key)
            create_policy_in_account(policy_version_document_json, account_id, context, object_key, detail)
            update_item(account_id, 'ScpUpdateTime', get_current_time())
