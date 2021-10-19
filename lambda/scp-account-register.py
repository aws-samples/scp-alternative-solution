# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

#!/usr/bin/env python
# coding=utf-8

import json
import os
import sys
import boto3
import time
import copy
import re
import traceback
from hashlib import blake2b
from urllib.request import Request, urlopen

s3_client = boto3.client("s3")
sns_client = boto3.client("sns")
iam_client = boto3.client("iam")
events_client = boto3.client("events")
dynamodb_resource = boto3.resource("dynamodb")

DYNAMODB_TABLE_ARN = os.environ["DYNAMODB_TABLE_ARN"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
SCP_EVENT_BUS_ARN = os.environ["SCP_EVENT_BUS_ARN"]
SCP_EVENT_RULE_ARN = os.environ["SCP_EVENT_RULE_ARN"]
S3_BUCKET_NAME = os.environ["S3_BUCKET_NAME"]
MANAGEMENT_ACCOUNT_ID = os.environ["MANAGEMENT_ACCOUNT_ID"]
ACCOUNT_ID = os.environ["ACCOUNT_ID"]
OU_ID = os.environ["OU_ID"]
CREATE_SCP_TRAIL = os.environ["CREATE_SCP_TRAIL"]
ORGANIZATION_ROLE = os.environ["ORGANIZATION_ROLE"]
PERMISSION_BOUNDARY_NAME = os.environ["PERMISSION_BOUNDARY_NAME"]
READ_POLICY_STATEMENT_SID = os.environ["READ_POLICY_STATEMENT_SID"]
S3_OBJECT_FOLDER = os.environ["S3_OBJECT_FOLDER"]
MANAGEMENT_ACCOUNT_ACCESS_ROLE = os.environ["MANAGEMENT_ACCOUNT_ACCESS_ROLE"]

dynamodb_table = dynamodb_resource.Table(DYNAMODB_TABLE_ARN.split("/")[-1])
MAX_POLICY_VERSIONS = 5
MANAGED_POLICY_LIMIT = 6144
REGION_NAME="cn-north-1"
BLAKE2B_DIGEST_SIZE = 2
BLAKE2B_INPUT_ENCODING = "utf-8"
HASH_PREFIX_NUM = 5
ACCOUNT_EVENT_RULE_NAME = "scp-event-rule"
ACCOUNT_BUCKET_PREFIX = "scp-trail-bucket"
ACCOUNT_TRAIL_NAME = "scp-trail"

ACCOUNT_EVENT_BUS_NAME = "default"
ACCOUNT_EVENT_PATTERN ={
  "source": [
    "aws.iam"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "iam.amazonaws.com"
    ],
    "eventName": [
      "CreateRole",
      "CreateUser"
    ]
  }
}

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
            "arn:aws-cn:iam::<ACCOUNT_ID>:policy/{0}".format(PERMISSION_BOUNDARY_NAME),
            "arn:aws-cn:cloudtrail:cn-north-1:<ACCOUNT_ID>:trail/{0}".format(ACCOUNT_TRAIL_NAME),
            "arn:aws-cn:s3:::{0}-<ACCOUNT_ID>".format(ACCOUNT_BUCKET_PREFIX),
            "arn:aws-cn:events:cn-north-1:<ACCOUNT_ID>:rule/{0}".format(ACCOUNT_EVENT_RULE_NAME),
            "arn:aws-cn:iam::<ACCOUNT_ID>:role/{1}".format(ORGANIZATION_ROLE)
        ],
        "Condition": {
            "ArnNotLike": {
                "aws:PrincipalArn": "arn:aws-cn:iam::*:role/{0}".format(ORGANIZATION_ROLE)
            }
        }
    }
]

AWS_ARN_TEMPLATE = "arn:%(partition)s:iam::%(account_id)s:root"

# The permission boundary won't be attached to the roles below
IAM_ROLE_WHITELIST = [ORGANIZATION_ROLE]

IAM_USER_WHITELIST = []

ACCOUNT_EVENT_ROLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "events:PutEvents"
            ],
            "Resource": [
                "{0}".format(SCP_EVENT_BUS_ARN)
            ]
        }
    ]
}

ACCOUNT_EVENT_ROLE_TRUST_POLICY = {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}

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

    send_response("FAILURE", { "Message": "Account register failed" })
    sys.exit(1)

def get_current_account_id(context):
    """
    Get current account id.

    @param context: the context of the event
    @return: current account id
    """
    return  context.invoked_function_arn.split(":")[4]

def get_aws_partition(context):
    """
    Get aws partition

    @param context: the context of the event
    @return: current account partition
    """
    return context.invoked_function_arn.split(":")[1]

def get_accounts_from_ou(mgt_account_id, ou_id):
    """
    Get the account id list by the name of AWS Root Account (BU) ID,
    AWS Organization Unit ID.

    @param mgt_account_id: The name of the AWS Root Account ID.
    @param ou_id: The name of the AWS organization unit.
    @return: The active account list under the AWS organization unit.
    """
    accounts = []
    org_client = master_acount_org_session(mgt_account_id=MANAGEMENT_ACCOUNT_ID)

    try:
        response = org_client.list_accounts_for_parent(
            ParentId=ou_id)
    except Exception as e:
        subject = "Unexpected error when fetching the account from ou %s"\
                   .format(ou_id)
        failure_notify(e, subject)

    if "Accounts" in response:
        for account in response["Accounts"]:
            if account["Status"] == "ACTIVE":
                accounts.append(account["Id"])
            else:
                print("The account %s is suspended, ignoring..." %(account["Name"]))

    return accounts

def master_acount_org_session(service="organizations",
                              region_name=REGION_NAME,
                              mgt_account_id=None):

    local_sts_client = boto3.client('sts')

    assume_role_arn = "arn:" + "aws-cn" + ":iam::" \
                    + mgt_account_id + ":role/" + MANAGEMENT_ACCOUNT_ACCESS_ROLE
    member_assume_role_arn = "arn:" + "aws-cn" + ":iam::" \
                    + ACCOUNT_ID + ":role/" + ORGANIZATION_ROLE

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
    Exact the management id, AWS organization unit, account id from object_key
    Return the existing S3 object

    e.g:
        permission-bounday-policy/ou-47kj-8dqxxxx.json
        permission-bounday-policy/account-78142222xxxx.json

    @param object_key: The S3 object key
    @return ou_id, account_list

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

    return  ou_id, account_id

def get_account_list(object_key, context):
    """
    Get the valid account list from s3 object key

    Only the fixed naming convention is supported of the object key.
    e.g: account-295131063008.json ou-47kj-8dquliyv.json

    @param context: The context of the event
    @param object_key: The name of the s3 object, permission-bounday-policy/ou-47kj-8dquliyv.json

    @return: account_list:  list/None
    """
    accounts = []
    ou_id, account_id = exact_object_key(object_key)

    if account_id:
        accounts.append(account_id)
    elif ou_id:
        accounts = get_accounts_from_ou(ou_id)

    current_account_id = get_current_account_id(context)

    if current_account_id in accounts:
        accounts.remove(current_account_id)

    return accounts

def is_valid_event(event):
    """
    Check the validation of the s3 event.
    """
    s3_bucket_name = event["s3"]["bucket"]["name"]

    if s3_bucket_name:
        return True
    else:
        return False

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
            if "Records" in record_body:
                for r in record_body["Records"]:
                    if is_valid_event(r):
                        details.append(r)
        # Otherwise it's from native s3 event
        elif is_valid_event(record):
            details.append(record)
    return details

def read_s3_object(s3_bucket_name, s3_object_key):
    """
    Read the content of the s3 object.

    @param s3_bucket_name: The s3 bucket name
    @param s3_object_name: The s3 object key name

    @return s3_content
    """
    try:
        s3_object = s3_client.get_object(Bucket=s3_bucket_name, Key=s3_object_key)
        body = s3_object['Body']
    except Exception as e:
        msg = "Failed to read object key {0} from bucket {1}, Error: {2}"\
             .format(s3_object_key, s3_bucket_name, e)
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
    Caculate the number of character for a given string.
    The permission boundary policy can't exceed 6144 characters.
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

def get_available_roles(iam_client):
    """
    Get the valid roles from the current account, exclude the service linked
    role and the whitested roles.
    """
    ava_roles = []
    try:
        response = iam_client.list_roles()
    except Exception as e:
        msg = "Failed to list roles in the account {0}".format(e)
        failure_notify(msg)
    for role in response["Roles"]:
        role_name = role["RoleName"]
        # exclude the service linked role
        role_path_prefix = role["Path"].split("/")[1]
        if ((role_name not in IAM_ROLE_WHITELIST) and (role_path_prefix != "aws-service-role")):
            ava_roles.append(role_name)
    return ava_roles

def get_available_users(iam_client):
    """
    Get the valid users from the current account, exclude the whitested users.
    """
    ava_users = []
    try:
        response = iam_client.list_users()
    except Exception as e:
        msg = "Failed to list users in the account {0}".format(e)
        failure_notify(msg)
    for user in response["Users"]:
        user_name = user["UserName"]
        # exclude the service user
        user_path_prefix = user["Path"].split("/")[1]
        if ((user_name not in IAM_USER_WHITELIST) and (user_path_prefix != "aws-service-user")):
            ava_users.append(user_name)

    return ava_users

def bind_permission_boundary_role(iam_client, role_name, permission_boundary_arn):
    """
    Bind the permission boundary arn to the role.
    """
    try:
        iam_client.put_role_permissions_boundary(
            RoleName = role_name,
            PermissionsBoundary = permission_boundary_arn
        )
        print("Role {0} has been bind to permission boundary policy {1}"
              .format(role_name, permission_boundary_arn))
    except Exception as e:
        msg = "Failed to bind permission boundary policy {0} to role {1} due \
               to exceptional {2}".format(permission_boundary_arn, role_name, e)
        failure_notify(msg)

def delete_permission_boundary_role(iam_client, role_name):
    """
    Delete the permission boundary arn for IAM role.
    """
    try:
        iam_client.delete_role_permissions_boundary(
            RoleName = role_name,
        )
        print("Default permission boundary policy has been deleted for role {0}"
              .format(role_name))
    except Exception as e:
        msg = "Failed to delete permission boundary policy for role {0} due \
               to exceptional {1}".format(role_name, e)
        failure_notify(msg)

def bind_permission_boundary_user(iam_client, user_name, permission_boundary_arn):
    """
    Bind the permission boundary arn to the user.
    """
    try:
        iam_client.put_user_permissions_boundary(
            UserName = user_name,
            PermissionsBoundary = permission_boundary_arn
        )
        print("user {0} has been bind to permission boundary policy {1}"
              .format(user_name, permission_boundary_arn))
    except Exception as e:
        msg = "Failed to bind permission boundary policy {0} to user {1} due \
              to exceptional {2}".format(permission_boundary_arn, user_name, e)
        failure_notify(msg)

def delete_permission_boundary_user(iam_client, user_name):
    """
    Delete the permission boundary arn for IAM user.
    """
    try:
        iam_client.delete_user_permissions_boundary(
            UserName = user_name
        )
        print("Default permission boundary policy has been deleted for user {0}"
              .format(user_name))
    except Exception as e:
        msg = "Failed to delete default permission boundary policy for user {0} due \
              to exceptional {1}".format(user_name, e)
        failure_notify(msg)

def generate_policy_statement_sid(s3_object_key):
    """
    Generate an unique PolicyStatement ID for the inputted s3_object.
        prefix => the value returned by extract_sid_prefix(s3_object.key)
        suffix => empty string or hash value of either the original
                  PolicyStatement ID or the PolicyStatement dumps
    """
    sid_prefix = extract_sid_prefix(s3_object_key)
    sid_prefix_hash = blake2b_hash(sid_prefix)[:HASH_PREFIX_NUM]
    print("The generated hash is {0} by s3 object key {1}".format(sid_prefix_hash, s3_object_key))

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
        policy_statement_json = json.loads(s3_object_content)
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

    return policy_version_document_json

def render_policy(policy, account):
    """
    Render the policy, replace <ACCOUNT_ID> to the actual account id.
    """
    render_policy = json.loads(json.dumps(policy).replace('<ACCOUNT_ID>', account))
    print("Created render policy in account {0}: {1}".format(account, render_policy))

    if get_str_length(render_policy) > MANAGED_POLICY_LIMIT:
        failure_notify(
            "The generated policy %s exceeded the max string limit %s".format(
                render_policy, MANAGED_POLICY_LIMIT
                )
        )

    return render_policy

def assume_role(sts_client, account, context, service="iam"):
    """
    Assume to the target account.
    """
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

def assume_role_resource(sts_client, account, context, service="iam"):
    """
    Assume to the target account.
    """
    assume_role_arn = "arn:" + get_aws_partition(context) + ":iam::" \
                    + account + ":role/" + ORGANIZATION_ROLE

    Credentials = sts_client.assume_role(
        RoleArn=assume_role_arn,
        RoleSessionName=account,
        DurationSeconds=900)

    client = boto3.resource(
        service,
        aws_access_key_id=Credentials['Credentials']['AccessKeyId'],
        aws_secret_access_key=Credentials['Credentials']['SecretAccessKey'],
        aws_session_token=Credentials['Credentials']['SessionToken'])

    return client

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

def process_permission_boundary_to_role(target_iam_client,
                                        policy_arn,
                                        account,
                                        render_policy_version_document_json,
                                        s3_object_key):
    """
    The main function to process the permission boundary against the IAM roles
    """

    role_list = get_available_roles(target_iam_client)

    for role in role_list:
        print("Processing role {0}".format(role))
        response = target_iam_client.get_role(RoleName=role)
        role_permission_boundary_arn = ""

        if "PermissionsBoundary" in response["Role"]:
            role_permission_boundary_arn = response["Role"]["PermissionsBoundary"]["PermissionsBoundaryArn"]
        if not role_permission_boundary_arn:
            bind_permission_boundary_role(target_iam_client, role, policy_arn)
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

def delete_permission_boundary_to_role(target_iam_client,
                                        policy_arn,
                                        account,
                                        s3_object_key):
    """
    The main function to delete the permission boundary against the IAM roles
    """

    role_list = get_available_roles(target_iam_client)

    for role in role_list:
        print("Processing role {0}".format(role))
        response = target_iam_client.get_role(RoleName=role)
        role_permission_boundary_arn = ""

        if "PermissionsBoundary" in response["Role"]:
            role_permission_boundary_arn = response["Role"]["PermissionsBoundary"]["PermissionsBoundaryArn"]
        if role_permission_boundary_arn:
            if role_permission_boundary_arn == policy_arn:
                delete_permission_boundary_role(target_iam_client, role)
            else:
                policy_reponse = target_iam_client.get_policy(PolicyArn=role_permission_boundary_arn)
                default_version_id = policy_reponse["Policy"]["DefaultVersionId"]
                target_policy_version = target_iam_client.get_policy_version(
                    PolicyArn=role_permission_boundary_arn,
                    VersionId=default_version_id
                )

                target_policy_version_document_json = target_policy_version["PolicyVersion"]["Document"]
                consolidated_policy_json = delete_permission_boundary_arn(
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
                                        s3_object_key):
    """
    The main function to process the permission boundary against the IAM roles
    """
    user_list = get_available_users(target_iam_client)

    for user_name in user_list:
        print("Processing user {0}".format(user_name))
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

def delete_permission_boundary_to_user(target_iam_client,
                                        policy_arn,
                                        account,
                                        s3_object_key):
    """
    The main function to delete the permission boundary against the IAM roles
    """
    user_list = get_available_users(target_iam_client)

    for user_name in user_list:
        print("Deleting permission boundary for user {0}".format(user_name))
        response = target_iam_client.get_user(UserName=user_name)
        user_permission_boundary_arn = ""

        if "PermissionsBoundary" in response["User"]:
           user_permission_boundary_arn = response["User"]["PermissionsBoundary"]["PermissionsBoundaryArn"]
        if user_permission_boundary_arn:
            if user_permission_boundary_arn == policy_arn:
                delete_permission_boundary_user(target_iam_client, user_name)
            else:
                policy_reponse = target_iam_client.get_policy(PolicyArn=user_permission_boundary_arn)
                default_version_id = policy_reponse["Policy"]["DefaultVersionId"]
                target_policy_version = target_iam_client.get_policy_version(
                    PolicyArn=user_permission_boundary_arn,
                    VersionId=default_version_id
                )

                target_policy_version_document_json = target_policy_version["PolicyVersion"]["Document"]
                consolidated_policy_json = delete_permission_boundary_arn(
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

def create_policy_in_account(policy_version_document_json, account, context, s3_object_key):
    """
    Create the global permission boundary in the target account.
    """
    render_policy_version_document_json = render_policy(
                policy_version_document_json, account)

    sts_client = master_acount_org_session(service="sts", mgt_account_id=MANAGEMENT_ACCOUNT_ID)
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

    process_permission_boundary_to_user(target_iam_client,
                                        policy_arn, account,
                                        render_policy_version_document_json,
                                        s3_object_key)
    process_permission_boundary_to_role(target_iam_client,
                                        policy_arn, account,
                                        render_policy_version_document_json,
                                        s3_object_key)

def delete_policy_in_account(account, context, s3_object_key):
    """
    Delete the global permission boundary in the target account.
    """
    sts_client = master_acount_org_session(service="sts", mgt_account_id=MANAGEMENT_ACCOUNT_ID)
    target_iam_client = assume_role(sts_client, account, context)
    policy_arn = "arn:" + get_aws_partition(context) + ":iam::" + account \
            + ":policy/" + PERMISSION_BOUNDARY_NAME

    delete_permission_boundary_to_user(target_iam_client,
                                        policy_arn, account,
                                        s3_object_key)
    delete_permission_boundary_to_role(target_iam_client,
                                        policy_arn, account,
                                        s3_object_key)

def consolidate_permission_boundary_arn(source_policy, target_policy, sid_prefix):

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

def delete_permission_boundary_arn(target_policy, sid_prefix):

    tmp_policy = copy.deepcopy(target_policy)

    for stmt in target_policy["Statement"]:
        if (
            "Sid" in stmt
            and stmt["Sid"][0 : len(sid_prefix)]
            == sid_prefix
        ):
            tmp_policy["Statement"].remove(stmt)

    print("The consolidated policy json {0}".format(tmp_policy))

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

def get_valid_object_key():
    """
    Get the valid object key from the environment variables.
    """
    valid_object_key_list = []

    if ACCOUNT_ID:
        object_key = "{0}/account-{1}.json".format(
            S3_OBJECT_FOLDER,
            ACCOUNT_ID)
        if check_s3_object_exists(S3_BUCKET_NAME, object_key):
            valid_object_key_list.append(object_key)
            return valid_object_key_list

    if OU_ID:
        object_key = "{0}/{1}.json".format(
            S3_OBJECT_FOLDER,
            OU_ID)
        if check_s3_object_exists(S3_BUCKET_NAME, object_key):
            valid_object_key_list.append(object_key)

    if not valid_object_key_list:
        failure_notify("Please input a valid OU_ID or ACCOUNT_ID")

    return valid_object_key_list

def create_event_rule_in_account(target_account_id, context):
    """
    Create event rule/event target/IAM role/IAM policy in the target account.
    """
    current_account_id = get_current_account_id(context)
    sts_client = master_acount_org_session(service="sts", mgt_account_id=MANAGEMENT_ACCOUNT_ID)
    target_events_client = assume_role(sts_client, target_account_id, context, "events")
    target_iam_client = assume_role(sts_client, target_account_id, context, "iam")

    existing_rules = target_events_client.list_rules(
        NamePrefix=ACCOUNT_EVENT_RULE_NAME,
        EventBusName=ACCOUNT_EVENT_BUS_NAME,
    )
    event_rule_exists = False
    for rule in existing_rules["Rules"]:
        if rule["Name"] == ACCOUNT_EVENT_RULE_NAME:
            print("Event rule {0} was created in account {1}"
              .format(ACCOUNT_EVENT_RULE_NAME, target_account_id))
            event_rule_exists = True
            break

    if not event_rule_exists:
        print("Event rule {0} not found in account {1}, creating..."
              .format(ACCOUNT_EVENT_RULE_NAME, target_account_id))
        try:
            target_events_client.put_rule(
                Name=ACCOUNT_EVENT_RULE_NAME,
                EventPattern=json.dumps(ACCOUNT_EVENT_PATTERN),
                State='ENABLED',
                Description='Event rule for SCP Alternative Solution',
                EventBusName=ACCOUNT_EVENT_BUS_NAME
            )
        except Exception as e:
            msg = "Failed to create event rule {0} in account {1}"\
                  .format(ACCOUNT_EVENT_RULE_NAME, target_account_id)
            failure_notify(msg)

    role_exists = False
    roles_response = target_iam_client.list_roles()
    role_list = roles_response['Roles']
    for key in role_list:
        if key["RoleName"] == ACCOUNT_EVENT_RULE_NAME:
            print("IAM role {0} was created in account {1}, skipping..."
              .format(ACCOUNT_EVENT_RULE_NAME, target_account_id))
            role_exists = True
            break

    if not role_exists:
        iam_role_response = target_iam_client.create_role(
            RoleName=ACCOUNT_EVENT_RULE_NAME,
            AssumeRolePolicyDocument=json.dumps(ACCOUNT_EVENT_ROLE_TRUST_POLICY),
        )
    else:
        iam_role_response = target_iam_client.get_role(
            RoleName=ACCOUNT_EVENT_RULE_NAME
        )

    policy_exists = False
    policy_response = target_iam_client.list_policies(
            Scope='Local',
            PolicyUsageFilter='PermissionsPolicy',
        )
    policy_list = policy_response['Policies']
    for key in policy_list:
        if key["PolicyName"] == ACCOUNT_EVENT_RULE_NAME:
            print("IAM policy {0} was created in account {1}, skipping..."
              .format(ACCOUNT_EVENT_RULE_NAME, target_account_id))
            policy_exists = True
            break

    if not policy_exists:
        target_iam_client.create_policy(
            PolicyName=ACCOUNT_EVENT_RULE_NAME,
            PolicyDocument=json.dumps(ACCOUNT_EVENT_ROLE_POLICY),
        )

    role_policy_exists = False
    role_policy_response = target_iam_client.list_attached_role_policies(
            RoleName=ACCOUNT_EVENT_RULE_NAME,
        )

    role_policy_list = role_policy_response['AttachedPolicies']
    for key in role_policy_list:
        if key["PolicyName"] == ACCOUNT_EVENT_RULE_NAME:
            print("IAM policy {0} was created attached in account {1}, skipping..."
              .format(ACCOUNT_EVENT_RULE_NAME, target_account_id))
            role_policy_exists = True
            break

    if not role_policy_exists:
        l_policy_arn = "arn:" + get_aws_partition(GLOBAL_CONTEXT) + ":iam::" + ACCOUNT_ID \
                + ":policy/" + ACCOUNT_EVENT_RULE_NAME
        target_iam_client.attach_role_policy(
            RoleName=iam_role_response['Role']['RoleName'],
            PolicyArn=l_policy_arn
        )

    target_exists = False
    target_response = target_events_client.list_targets_by_rule(
        Rule=ACCOUNT_EVENT_RULE_NAME,
    )
    target_list = target_response['Targets']
    for key in target_list:
        if key["Id"] == ACCOUNT_EVENT_RULE_NAME:
            print("Event target {0} was created in account {1}, skipping..."
              .format(ACCOUNT_EVENT_RULE_NAME, target_account_id))
            target_exists = True
            break

    if not target_exists:
        target_events_client.put_targets(
            Rule=ACCOUNT_EVENT_RULE_NAME,
            Targets=[
                {
                    'Id': ACCOUNT_EVENT_RULE_NAME,
        		    'Arn': SCP_EVENT_BUS_ARN,
                    'RoleArn': iam_role_response['Role']['Arn']
                },
        	]
        )

def delete_event_rule_in_account(target_account_id, context):
    """
    Delete event rule/event target/IAM role/IAM policy in the target account.
    """
    current_account_id = get_current_account_id(context)
    sts_client = master_acount_org_session(service="sts", mgt_account_id=MANAGEMENT_ACCOUNT_ID)
    target_events_client = assume_role(sts_client, target_account_id, context, "events")
    target_iam_client = assume_role(sts_client, target_account_id, context, "iam")

    existing_rules = target_events_client.list_rules(
        NamePrefix=ACCOUNT_EVENT_RULE_NAME,
        EventBusName=ACCOUNT_EVENT_BUS_NAME,
    )

    rule_exists = False
    for rule in existing_rules["Rules"]:
        if rule["Name"] == ACCOUNT_EVENT_RULE_NAME:
            print("Event rule {0} was created in account {1}, deleting..."
              .format(ACCOUNT_EVENT_RULE_NAME, target_account_id))
            rule_exists = True
            break

    if rule_exists:
        print("Event rule {0} does exist in account {1}, deleting..."
              .format(ACCOUNT_EVENT_RULE_NAME, target_account_id))

        target_events_client.remove_targets(
            Rule=ACCOUNT_EVENT_RULE_NAME,
            Ids=[ACCOUNT_EVENT_RULE_NAME],
            Force=True
        )

        target_events_client.delete_rule(Name=ACCOUNT_EVENT_RULE_NAME)

    # Detach policy from role
    role_exists = False
    roles_response = target_iam_client.list_roles()
    role_list = roles_response['Roles']
    for key in role_list:
        if key["RoleName"] == ACCOUNT_EVENT_RULE_NAME:
            print("IAM role {0} was created in account {1}, deleting..."
              .format(ACCOUNT_EVENT_RULE_NAME, target_account_id))
            role_exists = True
            break

    if role_exists:
        role_policy_response = target_iam_client.list_attached_role_policies(
            RoleName=ACCOUNT_EVENT_RULE_NAME,
        )

        for policy in role_policy_response["AttachedPolicies"]:
            target_iam_client.detach_role_policy(
                PolicyArn=policy["PolicyArn"],
                RoleName=ACCOUNT_EVENT_RULE_NAME
            )

            iam_policy_response = target_iam_client.delete_policy(
                PolicyArn=policy["PolicyArn"]
            )

        iam_role_response = target_iam_client.delete_role(
            RoleName=ACCOUNT_EVENT_RULE_NAME
        )

def get_current_account_arn(context):
    return get_account_arn(get_current_account_id(context), context)

def get_account_arn(account_id, context):
    return AWS_ARN_TEMPLATE % {
       "account_id": account_id,
       "partition": get_aws_partition(context),
    }

def add_arn_to_policy(target_account_arn, policy_json):
    """
    Add the source account id to event resource policy in security account
    """
    for stmt in policy_json["Statement"]:
        if stmt.get("Sid", None) == READ_POLICY_STATEMENT_SID:
            if target_account_arn not in stmt["Principal"]["AWS"]:
                tmp_principal = to_list(stmt["Principal"]["AWS"])
                tmp_principal.append(target_account_arn)
                stmt["Principal"]["AWS"] = tmp_principal
        else:
            print("The policy SID {0} not found".format(READ_POLICY_STATEMENT_SID))
    print("updated policy {0}".format(policy_json))
    return policy_json

def update_resource_policy(target_account_id, context):
    """
    Add the source account id to event bus resource policy in security account
    """
    target_account_arn = get_account_arn(target_account_id, context)
    default_event_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "{0}".format(READ_POLICY_STATEMENT_SID),
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "{0}".format(target_account_arn)
                    ]
                },
                "Action": "events:PutEvents",
                "Resource": [
                    "{0}".format(SCP_EVENT_BUS_ARN)
                ]
            }
        ]
    }

    event_bus_policy = events_client.describe_event_bus(Name=SCP_EVENT_BUS_ARN)
    if "Policy" not in event_bus_policy:
        event_bus_policy_json= default_event_policy
    else:
        event_bus_policy_json = json.loads(event_bus_policy['Policy'])
    events_client.put_permission(EventBusName=SCP_EVENT_BUS_ARN.split('/')[-1],
                                 Policy=json.dumps(add_arn_to_policy(
                                     target_account_arn,
                                     event_bus_policy_json
                                     )))

    event_rule_policy = events_client.describe_rule(
        Name=SCP_EVENT_RULE_ARN.split('/')[-1],
        EventBusName=SCP_EVENT_BUS_ARN)
    event_pattern_policy_json = json.loads(event_rule_policy['EventPattern'])

    if 'account' in event_pattern_policy_json:
        if target_account_id not in event_pattern_policy_json['account']:
            event_pattern_policy_json['account'].append(target_account_id)
    else:
        event_pattern_policy_json['account'] = [target_account_id]

    events_client.put_rule(
        Name=SCP_EVENT_RULE_ARN.split('/')[-1],
        EventBusName=SCP_EVENT_BUS_ARN,
        EventPattern=json.dumps(event_pattern_policy_json),
        State='ENABLED'
    )

def exact_account(source_account_id):
    """
    Get the BU id, OU id by the account id in dynamodb table.
    """
    try:
        response = dynamodb_table.get_item(Key={'AccountId': source_account_id})
    except Exception as e:
        failure_notify("Unable to query account id {0}, detailed exception {1}".format(source_account_id, e))
    print(response)

    mgt_account_id = response['Item']['MgtId']
    ou_id = response['Item']['OuId']

    return mgt_account_id, ou_id, source_account_id

def append_item_to_list(account_id, key, value):
    """
    Append a value to the key which is a list in the dyanmodb tables
    """
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
    """
    Update the value of the key in dyanmodb table.
    """
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
        failure_notify('Failed to write item {0} to {1}, detailed failure: {1}'
                       .format(value, account_id, e))

def delete_item(account_id):
    """
    Delete the value of the key in dyanmodb table.
    """
    try:
        dynamodb_table.delete_item(
            Key={
                'AccountId': account_id
            }
        )
    except Exception as e:
        failure_notify('Failed to delete item {0}, detailed failure: {1}'
                       .format(account_id, e))

def init_item(account_id, mgt_account_id, ou_id):
    """
    Init the account and write the account to dynamodb table.
    """
    item_exp = {
        'AccountId': account_id,
        'MgtId': mgt_account_id,
        'OuId': ou_id
    }
    try:
        dynamodb_table.put_item(Item=item_exp)
    except Exception as e:
        failure_notify('Failed to write item {0} to {1}, detailed failure: {2}'
                       .format(value, account_id, e))

def get_current_time():
    """
    Get current time
    """
    t = time.ctime()
    return t

def str2bool(v):
  return v.lower() in ("yes", "true", "t", "1")

def create_and_enable_scp_trail(target_account_id, context):
    """
    Create CloudTrail for SCP.
    """
    current_account_id = get_current_account_id(context)
    sts_client = master_acount_org_session(service="sts", mgt_account_id=MANAGEMENT_ACCOUNT_ID)

    target_s3_client = assume_role(sts_client, target_account_id, context, "s3")
    target_trail_client = assume_role(sts_client, target_account_id, context, "cloudtrail")

    bucket_name = ACCOUNT_BUCKET_PREFIX + '-' + target_account_id
    trail_name = ACCOUNT_TRAIL_NAME

    bucket_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Sid': 'AddPerm1',
                'Effect': 'Allow',
                'Principal': {
                    'Service': 'cloudtrail.amazonaws.com'
                },
                'Action': 's3:GetBucketAcl',
                'Resource': f'arn:aws-cn:s3:::{bucket_name}'
            },
            {
                'Sid': 'AddPerm2',
                'Effect': 'Allow',
                'Principal': {
                    'Service': 'cloudtrail.amazonaws.com'
                },
                'Action': 's3:PutObject',
                'Resource': f'arn:aws-cn:s3:::{bucket_name}/AWSLogs/{target_account_id}/*',
                'Condition': {
                    'ForAnyValue:StringEquals': {
                        's3:x-amz-acl': 'bucket-owner-full-control'
                    }
                }
            }
        ]
    }

    try:
        target_s3_client.head_bucket(Bucket=bucket_name)
    except Exception as e:
        print("The bucket was not created, Hit error {0}".format(e))
        print("Trail bucket do not exist yet. Creating trail bucket \
              " + bucket_name + " in account " + target_account_id)
        try:
            bucket = target_s3_client.create_bucket(
                Bucket= bucket_name,
                CreateBucketConfiguration={
                    'LocationConstraint': REGION_NAME
                }
            )

            time.sleep(60)
            target_s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            bucket_enc = target_s3_client.put_bucket_encryption(
                Bucket = bucket_name,
                    ServerSideEncryptionConfiguration= {
                        'Rules': [{
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'aws:kms',
                            }
                        }]
                    }
                )
            print(bucket_name)

            target_s3_client.put_bucket_policy(Bucket=bucket_name,
                                               Policy=json.dumps(bucket_policy))
        except Exception as e:
            msg = "Failed to create CloudTrail Bucket {0}, error {1}"\
                    .format(bucket_name, e)
            failure_notify(msg)

    # Create CloudTrail
    response_trail_list = target_trail_client.list_trails()
    for trail in response_trail_list['Trails']:
        if (('Name' in trail) and (trail['Name'] == trail_name)):
            print("CloudTrail {0} was already created....".format(trail_name))
            return
    try:
        response_trail = target_trail_client.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name,
            IncludeGlobalServiceEvents=True,
            IsMultiRegionTrail=True
        )
        time.sleep(30)
        response_trail_on = target_trail_client.start_logging(
            Name=trail_name
        )
    except Exception as e:
        msg = "Failed to create trail for bucket {0}, error {1}"\
            .format(trail_bucket, e)
        failure_notify(msg)

    return

def delete_scp_trail(target_account_id, context):
    """
    Delete the CloudTrail for SCP.
    """
    current_account_id = get_current_account_id(context)
    sts_client = master_acount_org_session(service="sts", mgt_account_id=MANAGEMENT_ACCOUNT_ID)

    target_s3_resource = assume_role_resource(sts_client, target_account_id, context, "s3")
    target_s3_client = assume_role(sts_client, target_account_id, context, "s3")
    target_trail_client = assume_role(sts_client, target_account_id, context, "cloudtrail")

    bucket_name = ACCOUNT_BUCKET_PREFIX + '-' + target_account_id
    trail_name = ACCOUNT_TRAIL_NAME

    try:
        target_s3_client.head_bucket(Bucket=bucket_name)
        target_s3_resource_client = target_s3_resource.Bucket(bucket_name)
        target_s3_resource_client.objects.all().delete()
        target_s3_resource_client.delete()
    except Exception as e:
        print("The bucket was not created, Hit error {0}".format(e))

    # Delete CloudTrail
    response_trail_list = target_trail_client.list_trails()
    for trail in response_trail_list['Trails']:
        if (('Name' in trail) and (trail['Name'] == trail_name)):
            print("CloudTrail {0} was created, deleting....".format(trail_name))
            target_trail_client.delete_trail(Name=trail_name)
            return

def send_response(rs, rd):
    """
    Packages response and send signals to CloudFormation
    :param rs: Returned status to be sent back to CFN
    :param rd: Returned data to be sent back to CFN
    """
    e = GLOBAL_EVENT
    c = GLOBAL_CONTEXT

    r = json.dumps({
        "Status": rs,
        "Reason": "CloudWatch Log Stream: " + c.log_stream_name,
        "PhysicalResourceId": e['LogicalResourceId'],
        "StackId": e['StackId'],
        "RequestId": e['RequestId'],
        "LogicalResourceId": e['LogicalResourceId'],
        "Data": rd
    })
    d = str.encode(r)
    h = {
        'content-type': '',
        'content-length': str(len(d))
    }
    req = Request(e['ResponseURL'], data=d, method='PUT', headers=h)
    r = urlopen(req)
    print("Status message: {} {}".format(r.msg, r.getcode()))

############################################################
#                 SIGNAL HANDLER FUNCTIONS                 #
############################################################

def create():
    """
    Enroll the target AWS account to the framework:
    - Create account metadata in dynamodb.
    - Create required resources in the target account to monitor IAM activity.
    - Create and attach the IAM permission boundary policy for SCP to IAM roles.
    """
    bucket_name = S3_BUCKET_NAME
    init_item(ACCOUNT_ID, MANAGEMENT_ACCOUNT_ID, OU_ID)
    for object_key in get_valid_object_key():
        append_item_to_list(ACCOUNT_ID, 'ScpPolicyPathList', object_key)
        policy_version_document_json = create_policy_statement(bucket_name, object_key)
        create_policy_in_account(policy_version_document_json, ACCOUNT_ID, GLOBAL_CONTEXT, object_key)
        update_item(ACCOUNT_ID, 'ScpUpdateTime', get_current_time())

    if str2bool(CREATE_SCP_TRAIL):
        create_and_enable_scp_trail(ACCOUNT_ID, GLOBAL_CONTEXT)

    create_event_rule_in_account(ACCOUNT_ID, GLOBAL_CONTEXT)
    update_resource_policy(ACCOUNT_ID, GLOBAL_CONTEXT)

    return

def delete():
    """
    Enroll the target AWS account to the framework:
    - Delete required resources in the target account to monitor IAM activity.
    - Delete account metadata in dynamodb.
    - Dettach the IAM permission boundary policy for SCP to IAM roles.
    """
    for object_key in get_valid_object_key():
        delete_policy_in_account(ACCOUNT_ID, GLOBAL_CONTEXT, object_key)

    if str2bool(CREATE_SCP_TRAIL):
        delete_scp_trail(ACCOUNT_ID, GLOBAL_CONTEXT)

    delete_event_rule_in_account(ACCOUNT_ID, GLOBAL_CONTEXT)
    delete_item(ACCOUNT_ID)

    return

def update():
    """
    Re-enroll account with updated parameters.
    """
    delete()
    create()

    return

############################################################
#                LAMBDA FUNCTION HANDLER                   #
############################################################
# IMPORTANT: The Lambda function will be called whenever   #
# changes are made to the stack. Thus, ensure that the     #
# signals are handled by your Lambda function correctly,   #
# or the stack could get stuck in the DELETE_FAILED state  #
############################################################

def main(event, context, reply=True):
    """
    Main handler of the lambda function which tries to create or update the
    permission boundary policy.
    """
    global  GLOBAL_EVENT, GLOBAL_CONTEXT
    GLOBAL_EVENT = event
    GLOBAL_CONTEXT = context

    request_type = event['RequestType']

    print("Lambda Event: {0}".format(event))
    if ACCOUNT_ID == get_current_account_id(context):
        failure_notify("Account register for the security account {0} is not allowed".format(ACCOUNT_ID))

    try:
        if request_type == 'Create':
            create()
            if reply == True:
                send_response("SUCCESS", {"Message": "Created"})
        elif request_type == 'Update':
            update()
            if reply == True:
                send_response("SUCCESS",
                          {"Message": "Updated"})
        elif request_type == 'Delete':
            delete()
            if reply == True:
                send_response("SUCCESS",
                          {"Message": "Deleted"})
        else:
            if reply == True:
                send_response("FAILED",
                          {"Message": "Unexpected"})
    except Exception as ex:
        print(ex)
        traceback.print_tb(ex.__traceback__)
        if reply == True:
            send_response(
                "FAILED",
                {
                    "Message": "Exception"
                }
            )
