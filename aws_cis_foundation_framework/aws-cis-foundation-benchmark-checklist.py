"""Summary

Attributes:
    AWS_CIS_BENCHMARK_VERSION (str): Description
    CONFIG_RULE (bool): Description
    CONTROL_1_1_DAYS (int): Description
    IAM_CLIENT (TYPE): Description
    REGIONS (list): Description
    S3_WEB_REPORT (bool): Description
    S3_REPORT_BUCKET (str): Description
    S3_WEB_REPORT_EXPIRE (str): Description
    S3_WEB_REPORT_OBFUSCATE_ACCOUNT (bool): Description
    SCRIPT_OUTPUT_JSON (bool): Description
"""

import json
import csv
import time
import sys
import re
import getopt
from io import BytesIO, StringIO
import os
from datetime import datetime
import boto3
from botocore.client import Config
import logging
from multiprocessing.pool import ThreadPool


# --- Script controls ---

# CIS Benchmark version referenced. Only used in web report.
AWS_CIS_BENCHMARK_VERSION = "1.2"

# Would you like to upload reports to S3 bucket ?
# Files will be delivered using a signed URL.
S3_WEB_REPORT = True

# Where should the report be delivered to?
# Make sure to update permissions for the Lambda role if you change bucket name.
S3_REPORT_BUCKET = None

# Create separate report files?
# This will add date and account number as prefix. Example: cis_report_111111111111_161220_1213.html
S3_WEB_REPORT_NAME_DETAILS = True

# Create separate report files?
# This will add date and account number as prefix. Example: cis_report_111111111111_161220_1213.json
S3_JSON_NAME_DETAILS = True


# How many hours should the report be available? Default = 168h/7days
S3_WEB_REPORT_EXPIRE = "168"

# Set to true if you wish to anonymize the account number in the report.
# This is mostly used for demo/sharing purposes.
S3_WEB_REPORT_OBFUSCATE_ACCOUNT = False

# Would  you like to send the report signedURL to an SNS topic
SEND_REPORT_URL_TO_SNS = False
SNS_TOPIC_ARN = "CHANGE_ME_TO_YOUR_TOPIC_ARN"

# Would you like to print the results as JSON to output?
SCRIPT_OUTPUT_JSON = True

# Would you like to supress all output except JSON result?
# Can be used when you want to pipe result to another system.
# If using S3 reporting, please enable SNS integration to get S3 signed URL
OUTPUT_ONLY_JSON = False


# --- Control Parameters ---

# Control 1.18 - IAM manager and master role names <Not implemented yet, under review>
IAM_MASTER = "iam_master"
IAM_MANAGER = "iam_manager"
IAM_MASTER_POLICY = "iam_master_policy"
IAM_MANAGER_POLICY = "iam_manager_policy"

# Control 1.1 - Days allowed since use of root account.
CONTROL_1_1_DAYS = 0


# Log to stdout
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
streamformater = logging.Formatter("[%(levelname)s] %(message)s")

logstreamhandler = logging.StreamHandler()
logstreamhandler.setLevel(logging.INFO)
logstreamhandler.setFormatter(streamformater)
logger.addHandler(logstreamhandler)


# --- Global ---
IAM_CLIENT = boto3.client('iam')
S3_CLIENT = boto3.client('s3', config=Config(s3={'addressing_style': 'path'}, signature_version='s3v4'))

def time_decorator(original_func):

    def wrapper(*args, **kwargs):
        start = time.time()
        result = original_func(*args, **kwargs)
        end = time.time()
        logger.info('{} is executed in {:.2f} seconds.'.format(original_func.__name__, end-start))
        return result
    return wrapper

# --- 1 Identity and Access Management ---

# 1.1 Avoid the use of the "root" account (Scored)
@time_decorator
def control_1_1_root_use(resource):
    """Summary

    Args:
        resource (TYPE): Description

    Returns:
        TYPE: Description
    """

    credreport = resource['credreport']
    result = True
    fail_reason = ""
    offenders = []
    control = "1.1"
    description = "Avoid the use of the root account"
    scored = True
    if "Fail" in credreport:  # Report failure in control
        sys.exit(credreport)
    # Check if root is used in the last 24h
    now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
    frm = "%Y-%m-%dT%H:%M:%S+00:00"

    try:
        pwd_delta = (datetime.strptime(now, frm) - datetime.strptime(credreport[0]['password_last_used'], frm))
        if (pwd_delta.days == CONTROL_1_1_DAYS) & (pwd_delta.seconds > 0):  # Used within last 24h
            fail_reason = "Used within 24h"
            result = False
    except:
        if credreport[0]['password_last_used'] == "N/A" or "no_information":
            pass
        else:
            logger.error("Something went wrong")

    try:
        key1_delta = (datetime.strptime(now, frm) - datetime.strptime(credreport[0]['access_key_1_last_used_date'], frm))
        if (key1_delta.days == CONTROL_1_1_DAYS) & (key1_delta.seconds > 0):  # Used within last 24h
            fail_reason = "Used within 24h"
            result = False
    except:
        if credreport[0]['access_key_1_last_used_date'] == "N/A" or "no_information":
            pass
        else:
            logger.error("Something went wrong")
    try:
        key2_delta = datetime.strptime(now, frm) - datetime.strptime(credreport[0]['access_key_2_last_used_date'], frm)
        if (key2_delta.days == CONTROL_1_1_DAYS) & (key2_delta.seconds > 0):  # Used within last 24h
            fail_reason = "Used within 24h"
            result = False
    except:
        if credreport[0]['access_key_2_last_used_date'] == "N/A" or "no_information":
            pass
        else:
            logger.error("Something went wrong")

    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except #pylint: disable=broad-except


# 1.2 Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored)
@time_decorator
def control_1_2_mfa_on_password_enabled_iam(resource):
    """Summary

    Args:
        credreport (TYPE): Description

    Returns:
        TYPE: Description
    """

    credreport = resource['credreport']
    result = True
    fail_reason = ""
    offenders = []
    control = "1.2"
    description = "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password"
    scored = True
    for i in range(len(credreport)):
        # Verify if the user have a password configured
        if credreport[i]['password_enabled'] == "true":
            # Verify if password users have MFA assigned
            if credreport[i]['mfa_active'] == "false":
                result = False
                fail_reason = "No MFA on users with password. "
                offenders.append(str(credreport[i]['arn']))
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.3 Ensure credentials unused for 90 days or greater are disabled (Scored)
@time_decorator
def control_1_3_unused_credentials(resource):
    """Summary

    Args:
        credreport (TYPE): Description

    Returns:
        TYPE: Description
    """
    credreport = resource['credreport']
    result = True
    fail_reason = ""
    offenders = []
    control = "1.3"
    description = "Ensure credentials unused for 90 days or greater are disabled"
    scored = True
    # Get current time
    now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
    frm = "%Y-%m-%dT%H:%M:%S+00:00"

    # Look for unused credentails
    for i in range(len(credreport)):
        if credreport[i]['password_enabled'] == "true":
            try:
                delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['password_last_used'], frm)
                # Verify password have been used in the last 90 days
                if delta.days > 90:
                    result = False
                    fail_reason = "Credentials unused > 90 days detected. "
                    offenders.append(str(credreport[i]['arn']) + ":password")
            except:
                pass  # Never used
        if credreport[i]['access_key_1_active'] == "true":
            try:
                delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['access_key_1_last_used_date'], frm)
                # Verify password have been used in the last 90 days
                if delta.days > 90:
                    result = False
                    fail_reason = "Credentials unused > 90 days detected. "
                    offenders.append(str(credreport[i]['arn']) + ":key1")
            except:
                pass
        if credreport[i]['access_key_2_active'] == "true":
            try:
                delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['access_key_2_last_used_date'], frm)
                # Verify password have been used in the last 90 days
                if delta.days > 90:
                    result = False
                    fail_reason = "Credentials unused > 90 days detected. "
                    offenders.append(str(credreport[i]['arn']) + ":key2")
            except:
                # Never used
                pass
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.4 Ensure access keys are rotated every 90 days or less (Scored)
@time_decorator
def control_1_4_rotated_keys(resource):
    """Summary

    Args:
        credreport (TYPE): Description

    Returns:
        TYPE: Description
    """
    credreport = resource['credreport']
    result = True
    fail_reason = ""
    offenders = []
    control = "1.4"
    description = "Ensure access keys are rotated every 90 days or less"
    scored = True
    # Get current time
    now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
    frm = "%Y-%m-%dT%H:%M:%S+00:00"

    # Look for unused credentails
    for i in range(len(credreport)):
        if credreport[i]['access_key_1_active'] == "true":
            try:
                delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['access_key_1_last_rotated'], frm)
                # Verify keys have rotated in the last 90 days
                if delta.days > 90:
                    result = False
                    fail_reason = "Key rotation >90 days or not used since rotation"
                    offenders.append(str(credreport[i]['arn']) + ":unrotated key1")
            except:
                pass
            try:
                last_used_datetime = datetime.strptime(credreport[i]['access_key_1_last_used_date'], frm)
                last_rotated_datetime = datetime.strptime(credreport[i]['access_key_1_last_rotated'], frm)
                # Verify keys have been used since rotation.
                if last_used_datetime < last_rotated_datetime:
                    result = False
                    fail_reason = "Key rotation >90 days or not used since rotation"
                    offenders.append(str(credreport[i]['arn']) + ":unused key1")
            except:
                pass
        if credreport[i]['access_key_2_active'] == "true":
            try:
                delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['access_key_2_last_rotated'], frm)
                # Verify keys have rotated in the last 90 days
                if delta.days > 90:
                    result = False
                    fail_reason = "Key rotation >90 days or not used since rotation"
                    offenders.append(str(credreport[i]['arn']) + ":unrotated key2")
            except:
                pass
            try:
                last_used_datetime = datetime.strptime(credreport[i]['access_key_2_last_used_date'], frm)
                last_rotated_datetime = datetime.strptime(credreport[i]['access_key_2_last_rotated'], frm)
                # Verify keys have been used since rotation.
                if last_used_datetime < last_rotated_datetime:
                    result = False
                    fail_reason = "Key rotation >90 days or not used since rotation"
                    offenders.append(str(credreport[i]['arn']) + ":unused key2")
            except:
                pass
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.5 Ensure IAM password policy requires at least one uppercase letter (Scored)
@time_decorator
def control_1_5_password_policy_uppercase(resource):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    passwordpolicy = resource['passwordpolicy']
    result = True
    fail_reason = ""
    offenders = []
    control = "1.5"
    description = "Ensure IAM password policy requires at least one uppercase letter"
    scored = True
    if passwordpolicy is False:
        result = False
        fail_reason = "Account does not have a IAM password policy."
    else:
        if passwordpolicy['RequireUppercaseCharacters'] is False:
            result = False
            fail_reason = "Password policy does not require at least one uppercase letter"
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.6 Ensure IAM password policy requires at least one lowercase letter (Scored)
@time_decorator
def control_1_6_password_policy_lowercase(resource):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    passwordpolicy = resource['passwordpolicy']
    result = True
    fail_reason = ""
    offenders = []
    control = "1.6"
    description = "Ensure IAM password policy requires at least one lowercase letter"
    scored = True
    if passwordpolicy is False:
        result = False
        fail_reason = "Account does not have a IAM password policy."
    else:
        if passwordpolicy['RequireLowercaseCharacters'] is False:
            result = False
            fail_reason = "Password policy does not require at least one uppercase letter"
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.7 Ensure IAM password policy requires at least one symbol (Scored)
@time_decorator
def control_1_7_password_policy_symbol(resource):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    passwordpolicy = resource['passwordpolicy']
    result = True
    fail_reason = ""
    offenders = []
    control = "1.7"
    description = "Ensure IAM password policy requires at least one symbol"
    scored = True
    if passwordpolicy is False:
        result = False
        fail_reason = "Account does not have a IAM password policy."
    else:
        if passwordpolicy['RequireSymbols'] is False:
            result = False
            fail_reason = "Password policy does not require at least one symbol"
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.8 Ensure IAM password policy requires at least one number (Scored)
@time_decorator
def control_1_8_password_policy_number(resource):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    passwordpolicy = resource['passwordpolicy']
    result = True
    fail_reason = ""
    offenders = []
    control = "1.8"
    description = "Ensure IAM password policy requires at least one number"
    scored = True
    if passwordpolicy is False:
        result = False
        fail_reason = "Account does not have a IAM password policy."
    else:
        if passwordpolicy['RequireNumbers'] is False:
            result = False
            fail_reason = "Password policy does not require at least one number"
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.9 Ensure IAM password policy requires minimum length of 14 or greater (Scored)
@time_decorator
def control_1_9_password_policy_length(resource):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    passwordpolicy = resource['passwordpolicy']
    result = True
    fail_reason = ""
    offenders = []
    control = "1.9"
    description = "Ensure IAM password policy requires minimum length of 14 or greater"
    scored = True
    if passwordpolicy is False:
        result = False
        fail_reason = "Account does not have a IAM password policy."
    else:
        if passwordpolicy['MinimumPasswordLength'] < 14:
            result = False
            fail_reason = "Password policy does not require at least 14 characters"
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.10 Ensure IAM password policy prevents password reuse (Scored)
@time_decorator
def control_1_10_password_policy_reuse(resource):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    passwordpolicy = resource['passwordpolicy']
    result = True
    fail_reason = ""
    offenders = []
    control = "1.10"
    description = "Ensure IAM password policy prevents password reuse"
    scored = True
    if passwordpolicy is False:
        result = False
        fail_reason = "Account does not have a IAM password policy."
    else:
        try:
            if passwordpolicy['PasswordReusePrevention'] == 24:
                pass
            else:
                result = False
                fail_reason = "Password policy does not prevent reusing last 24 passwords"
        except:
            result = False
            fail_reason = "Password policy does not prevent reusing last 24 passwords"
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.11 Ensure IAM password policy expires passwords within 90 days or less (Scored)
@time_decorator
def control_1_11_password_policy_expire(resource):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    passwordpolicy = resource['passwordpolicy']
    result = True
    fail_reason = ""
    offenders = []
    control = "1.11"
    description = "Ensure IAM password policy expires passwords within 90 days or less"
    scored = True
    if passwordpolicy is False:
        result = False
        fail_reason = "Account does not have a IAM password policy."
    else:
        if passwordpolicy['ExpirePasswords'] is True:
            if 0 < passwordpolicy['MaxPasswordAge'] > 90:
                result = False
                fail_reason = "Password policy does not expire passwords after 90 days or less"
        else:
            result = False
            fail_reason = "Password policy does not expire passwords after 90 days or less"
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.12 Ensure no root account access key exists (Scored)
@time_decorator
def control_1_12_root_key_exists(resource):
    """Summary

    Args:
        credreport (TYPE): Description

    Returns:
        TYPE: Description
    """
    credreport = resource['credreport']

    result = True
    fail_reason = ""
    offenders = []
    control = "1.12"
    description = "Ensure no root account access key exists"
    scored = True
    if (credreport[0]['access_key_1_active'] == "true") or (credreport[0]['access_key_2_active'] == "true"):
        result = False
        fail_reason = "Root have active access keys"
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.13 Ensure MFA is enabled for the "root" account (Scored)
@time_decorator
def control_1_13_root_mfa_enabled(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    fail_reason = ""
    offenders = []
    control = "1.13"
    description = "Ensure MFA is enabled for the root account"
    scored = True
    response = IAM_CLIENT.get_account_summary()
    if response['SummaryMap']['AccountMFAEnabled'] != 1:
        result = False
        fail_reason = "Root account not using MFA"
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.14 Ensure hardware MFA is enabled for the "root" account (Scored)
@time_decorator
def control_1_14_root_hardware_mfa_enabled(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    fail_reason = ""
    offenders = []
    control = "1.14"
    description = "Ensure hardware MFA is enabled for the root account"
    scored = True
    # First verify that root is using MFA (avoiding false positive)
    response = IAM_CLIENT.get_account_summary()
    if response['SummaryMap']['AccountMFAEnabled'] == 1:
        paginator = IAM_CLIENT.get_paginator('list_virtual_mfa_devices')
        response_iterator = paginator.paginate(
            AssignmentStatus='Any',
        )
        pagedResult = []
        for page in response_iterator:
            for n in page['VirtualMFADevices']:
                pagedResult.append(n)
        if "mfa/root-account-mfa-device" in str(pagedResult):
            fail_reason = "Root account not using hardware MFA"
            result = False
    else:
        result = False
        fail_reason = "Root account not using MFA"
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.15 Ensure security questions are registered in the AWS account (Not Scored/Manual)
@time_decorator
def control_1_15_security_questions_registered(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    result = "Manual"
    fail_reason = ""
    offenders = []
    control = "1.15"
    description = "Ensure security questions are registered in the AWS account, please verify manually"
    scored = False
    fail_reason = "Control not implemented using API, please verify manually"
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.16 Ensure IAM policies are attached only to groups or roles (Scored)
@time_decorator
def control_1_16_no_policies_on_iam_users(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    fail_reason = ""
    offenders = []
    control = "1.16"
    description = "Ensure IAM policies are attached only to groups or roles"
    scored = True
    paginator = IAM_CLIENT.get_paginator('list_users')
    response_iterator = paginator.paginate()
    pagedResult = []
    for page in response_iterator:
        for n in page['Users']:
            pagedResult.append(n)
    offenders = []
    for n in pagedResult:
        policies = IAM_CLIENT.list_user_policies(
            UserName=n['UserName'],
            MaxItems=1
        )
        if policies['PolicyNames'] != []:
            result = False
            fail_reason = "IAM user have inline policy attached"
            offenders.append(str(n['Arn']))
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except

# 1.17 Maintain current contact details (not Scored)
@time_decorator
def control_1_17_maintain_current_contact_details(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    result = "Manual"
    fail_reason = ""
    offenders = []
    control = "1.17"
    description = "Maintain current contact details, please verify manually"
    scored = False
    fail_reason = "Control not implemented using API, please verify manually"
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.18 Ensure security contact information is registered (not Scored)
@time_decorator
def control_1_18_ensure_security_contact_details(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    result = "Manual"
    fail_reason = ""
    offenders = []
    control = "1.18"
    description = "Ensure security contact information is registered, please verify manually"
    scored = False
    fail_reason = "Control not implemented using API, please verify manually"
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.19 Ensure IAM instance roles are used for AWS resource access from instances (Scored)
@time_decorator
def control_1_19_ensure_iam_instance_roles_used(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    offenders = []
    control = "1.19"
    description = "Ensure IAM instance roles are used for AWS resource access from instances, application code is not audited"
    scored = True
    fail_reason = "Instance not assigned IAM role for EC2"
    client = boto3.client('ec2')
    response = client.describe_instances()
    offenders = []
    for n, _ in enumerate(response['Reservations']):
        try:
            if response['Reservations'][n]['Instances'][0]['IamInstanceProfile']:
                pass
        except:
                result = False
                offenders.append(str(response['Reservations'][n]['Instances'][0]['InstanceId']))
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.20 Ensure a support role has been created to manage incidents with AWS Support (Scored)
@time_decorator
def control_1_20_ensure_incident_management_roles(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    fail_reason = ""
    offenders = []
    control = "1.20"
    description = "Ensure a support role has been created to manage incidents with AWS Support"
    scored = True
    offenders = []
    try:
        response = IAM_CLIENT.list_entities_for_policy(
            PolicyArn='arn:aws:iam::aws:policy/AWSSupportAccess'
        )
        if (len(response['PolicyGroups']) + len(response['PolicyUsers']) + len(response['PolicyRoles'])) == 0:
            result = False
            fail_reason = "No user, group or role assigned AWSSupportAccess"
    except:
        result = False
        fail_reason = "AWSSupportAccess policy not created"
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.21 Do not setup access keys during initial user setup for all IAM users that have a console password (Not Scored)
@time_decorator
def control_1_21_no_active_initial_access_keys_with_iam_user(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    credreport = resource['credreport']
    result = True
    fail_reason = ""
    offenders = []
    control = "1.21"
    description = "Do not setup access keys during initial user setup for all IAM users that have a console password"
    scored = False
    offenders = []
    for n, _ in enumerate(credreport):
        if (credreport[n]['access_key_1_active'] or credreport[n]['access_key_2_active'] == 'true') and n > 0:
            response = IAM_CLIENT.list_access_keys(
                UserName=str(credreport[n]['user'])
            )
            for m in response['AccessKeyMetadata']:
                if re.sub(r"\s", "T", str(m['CreateDate'])) == credreport[n]['user_creation_time']:
                    result = False
                    fail_reason = "Users with keys created at user creation time found"
                    offenders.append(str(credreport[n]['arn']) + ":" + str(m['AccessKeyId']))
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 1.22  Ensure IAM policies that allow full "*:*" administrative privileges are not created (Scored)
@time_decorator
def control_1_22_no_overly_permissive_policies(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    fail_reason = ""
    offenders = []
    control = "1.22"
    description = "Ensure IAM policies that allow full administrative privileges are not created"
    scored = True
    offenders = []
    paginator = IAM_CLIENT.get_paginator('list_policies')
    response_iterator = paginator.paginate(
        Scope='Local',
        OnlyAttached=False,
    )
    paged_result = []
    for page in response_iterator:
        for n in page['Policies']:
            paged_result.append(n)
    for m in paged_result:
        policy = IAM_CLIENT.get_policy_version(
            PolicyArn=m['Arn'],
            VersionId=m['DefaultVersionId']
        )

        statements = []
        # a policy may contain a single statement, a single statement in an array, or multiple statements in an array
        if isinstance(policy['PolicyVersion']['Document']['Statement'], list):
            for statement in policy['PolicyVersion']['Document']['Statement']:
                statements.append(statement)
        else:
            statements.append(policy['PolicyVersion']['Document']['Statement'])

        for n in statements:
            # a policy statement has to contain either an Action or a NotAction
            if 'Action' in n.keys() and n['Effect'] == 'Allow':
                if ("'*'" in str(n['Action']) or str(n['Action']) == "*") and ("'*'" in str(n['Resource']) or str(n['Resource']) == "*"):
                    result = False
                    fail_reason = "Found full administrative policy"
                    offenders.append(str(m['Arn']))
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# --- 2 Logging ---

# 2.1 Ensure CloudTrail is enabled in all regions (Scored)
@time_decorator
def control_2_1_ensure_cloud_trail_all_regions(resource):
    """Summary

    Args:
        cloudtrails (TYPE): Description

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = False
    fail_reason = ""
    offenders = []
    control = "2.1"
    description = "Ensure CloudTrail is enabled in all regions"
    scored = True
    for m, n in cloudtrails.items():
        for o in n:
            if o['IsMultiRegionTrail']:
                client = boto3.client('cloudtrail', region_name=m)
                response = client.get_trail_status(
                    Name=o['TrailARN']
                )
                if response['IsLogging'] is True:
                    result = True
                    break
    if result is False:
        fail_reason = "No enabled multi region trails found"
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 2.2 Ensure CloudTrail log file validation is enabled (Scored)
@time_decorator
def control_2_2_ensure_cloudtrail_validation(resource):
    """Summary

    Args:
        cloudtrails (TYPE): Description

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = True
    fail_reason = ""
    offenders = []
    control = "2.2"
    description = "Ensure CloudTrail log file validation is enabled"
    scored = True
    for m, n in cloudtrails.items():
        for o in n:
            if o['LogFileValidationEnabled'] is False:
                result = False
                fail_reason = "CloudTrails without log file validation discovered"
                offenders.append(str(o['TrailARN']))
    offenders = set(offenders)
    offenders = list(offenders)
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 2.3 Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible (Scored)
@time_decorator
def control_2_3_ensure_cloudtrail_bucket_not_public(resource):
    """Summary

    Args:
        cloudtrails (TYPE): Description

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = True
    fail_reason = ""
    offenders = []
    control = "2.3"
    description = "Ensure the S3 bucket CloudTrail logs to is not publicly accessible"
    scored = True
    for m, n in cloudtrails.items():
        for o in n:
            #  We only want to check cases where there is a bucket
            if "S3BucketName" in str(o):
                try:
                    response = S3_CLIENT.get_bucket_acl(Bucket=o['S3BucketName'])
                    for p in response['Grants']:
                        # print("Grantee is " + str(p['Grantee']))
                        if re.search(r'(global/AllUsers|global/AuthenticatedUsers)', str(p['Grantee'])):
                            result = False
                            offenders.append(str(o['TrailARN']) + ":PublicBucket")
                            if "Publically" not in fail_reason:
                                fail_reason = fail_reason + "Publically accessible CloudTrail bucket discovered."
                except Exception as e:
                    result = False
                    if "AccessDenied" in str(e):
                        offenders.append(str(o['TrailARN']) + ":AccessDenied")
                        if "Missing" not in fail_reason:
                            fail_reason = "Missing permissions to verify bucket ACL. " + fail_reason
                    elif "NoSuchBucket" in str(e):
                        offenders.append(str(o['TrailARN']) + ":NoBucket")
                        if "Trailbucket" not in fail_reason:
                            fail_reason = "Trailbucket doesn't exist. " + fail_reason
                    else:
                        offenders.append(str(o['TrailARN']) + ":CannotVerify")
                        if "Cannot" not in fail_reason:
                            fail_reason = "Cannot verify bucket ACL. " + fail_reason
            else:
                result = False
                offenders.append(str(o['TrailARN']) + "NoS3Logging")
                fail_reason = "Cloudtrail not configured to log to S3. " + fail_reason
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 2.4 Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)
@time_decorator
def control_2_4_ensure_cloudtrail_cloudwatch_logs_integration(resource):
    """Summary

    Args:
        cloudtrails (TYPE): Description

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = True
    fail_reason = ""
    offenders = []
    control = "2.4"
    description = "Ensure CloudTrail trails are integrated with CloudWatch Logs"
    scored = True
    for m, n in cloudtrails.items():
        for o in n:
            try:
                if "arn:aws:logs" in o['CloudWatchLogsLogGroupArn']:
                    pass
                else:
                    result = False
                    fail_reason = "CloudTrails without CloudWatch Logs discovered"
                    offenders.append(str(o['TrailARN']))
            except:
                result = False
                fail_reason = "CloudTrails without CloudWatch Logs discovered"
                offenders.append(str(o['TrailARN']))
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 2.5 Ensure AWS Config is enabled in all regions (Scored)
@time_decorator
def control_2_5_ensure_config_all_regions(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    regions = resource['regions']
    result = True
    fail_reason = ""
    offenders = []
    control = "2.5"
    description = "Ensure AWS Config is enabled in all regions"
    scored = True
    global_config_capture = False  # Only one region needs to capture global events
    for n in regions:
        config_client = boto3.client('config', region_name=n)
        response = config_client.describe_configuration_recorder_status()
        # Get recording status
        try:
            if not response['ConfigurationRecordersStatus'][0]['recording'] is True:
                result = False
                fail_reason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
                offenders.append(str(n) + ":NotRecording")
        except:
            result = False
            fail_reason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
            offenders.append(str(n) + ":NotRecording")

        # Verify that each region is capturing all events
        response = config_client.describe_configuration_recorders()
        try:
            if not response['ConfigurationRecorders'][0]['recordingGroup']['allSupported'] is True:
                result = False
                fail_reason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
                offenders.append(str(n) + ":NotAllEvents")
        except:
            pass  # This indicates that Config is disabled in the region and will be captured above.

        # Check if region is capturing global events. Fail is verified later since only one region needs to capture them.
        try:
            if response['ConfigurationRecorders'][0]['recordingGroup']['includeGlobalResourceTypes'] is True:
                global_config_capture = True
        except:
            pass

        # Verify the delivery channels
        response = config_client.describe_delivery_channel_status()
        try:
            if response['DeliveryChannelsStatus'][0]['configHistoryDeliveryInfo']['lastStatus'] != "SUCCESS":
                result = False
                fail_reason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
                offenders.append(str(n) + ":S3orSNSDelivery")
        except:
            pass  # Will be captured by earlier rule
        try:
            if response['DeliveryChannelsStatus'][0]['configStreamDeliveryInfo']['lastStatus'] != "SUCCESS":
                result = False
                fail_reason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
                offenders.append(str(n) + ":SNSDelivery")
        except:
            pass  # Will be captured by earlier rule

    # Verify that global events is captured by any region
    if global_config_capture is False:
        result = False
        fail_reason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
        offenders.append("Global:NotRecording")
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 2.6 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)
@time_decorator
def control_2_6_ensure_cloudtrail_bucket_logging(resource):
    """Summary

    Args:
        cloudtrails (TYPE): Description

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = True
    fail_reason = ""
    offenders = []
    control = "2.6"
    description = "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket"
    scored = True
    for m, n in cloudtrails.items():
        for o in n:
            # it is possible to have a cloudtrail configured with a nonexistant bucket
            try:
                response = S3_CLIENT.get_bucket_logging(Bucket=o['S3BucketName'])
            except:
                result = False
                fail_reason = "Cloudtrail not configured to log to S3. "
                offenders.append(str(o['TrailARN']))
            try:
                if response['LoggingEnabled']:
                    pass
            except:
                result = False
                fail_reason = fail_reason + "CloudTrail S3 bucket without logging discovered"
                offenders.append("Trail:" + str(o['TrailARN']) + " - S3Bucket:" + str(o['S3BucketName']))
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 2.7 Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)
@time_decorator
def control_2_7_ensure_cloudtrail_encryption_kms(resource):
    """Summary

    Args:
        cloudtrails (TYPE): Description

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = True
    fail_reason = ""
    offenders = []
    control = "2.7"
    description = "Ensure CloudTrail logs are encrypted at rest using KMS CMKs"
    scored = True
    for m, n in cloudtrails.items():
        for o in n:
            try:
                if o['KmsKeyId']:
                    pass
            except:
                result = False
                fail_reason = "CloudTrail not using KMS CMK for encryption discovered"
                offenders.append("Trail:" + str(o['TrailARN']))
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 2.8 Ensure rotation for customer created CMKs is enabled (Scored)
@time_decorator
def control_2_8_ensure_kms_cmk_rotation(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    regions = resource['regions']
    result = True
    fail_reason = ""
    offenders = []
    control = "2.8"
    description = "Ensure rotation for customer created CMKs is enabled"
    scored = True
    for n in regions:
        kms_client = boto3.client('kms', region_name=n)
        paginator = kms_client.get_paginator('list_keys')
        response_iterator = paginator.paginate()
        for page in response_iterator:
            for n in page['Keys']:
                try:
                    rotationStatus = kms_client.get_key_rotation_status(KeyId=n['KeyId'])
                    if rotationStatus['KeyRotationEnabled'] is False:
                        keyDescription = kms_client.describe_key(KeyId=n['KeyId'])
                        if "Default master key that protects my" not in str(keyDescription['KeyMetadata']['Description']):  # Ignore service keys
                            result = False
                            fail_reason = "KMS CMK rotation not enabled"
                            offenders.append("Key:" + str(keyDescription['KeyMetadata']['Arn']))
                except:
                    pass  # Ignore keys without permission, for example ACM key
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# moved from 4.3 to 2.9 in v1.2 of CISFB
# 2.9 Ensure VPC flow logging is enabled in all VPCs (Scored)
@time_decorator
def control_2_9_ensure_flow_logs_enabled_on_all_vpc(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    regions = resource['regions']
    result = True
    fail_reason = ""
    offenders = []
    control = "2.9"
    description = "Ensure VPC flow logging is enabled in all VPCs"
    scored = True
    for n in regions:
        client = boto3.client('ec2', region_name=n)
        flowlogs = client.describe_flow_logs(
            #  No paginator support in boto atm.
        )
        activeLogs = []
        for m in flowlogs['FlowLogs']:
            if "vpc-" in str(m['ResourceId']):
                activeLogs.append(m['ResourceId'])
        vpcs = client.describe_vpcs(
            Filters=[
                {
                    'Name': 'state',
                    'Values': [
                        'available',
                    ]
                },
            ]
        )
        for m in vpcs['Vpcs']:
            if not str(m['VpcId']) in str(activeLogs):
                result = False
                fail_reason = "VPC without active VPC Flow Logs found"
                offenders.append(str(n) + " : " + str(m['VpcId']))
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# --- Monitoring ---

# 3.1 Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)
@time_decorator
def control_3_1_ensure_log_metric_filter_unauthorized_api_calls(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = False
    fail_reason = ""
    offenders = []
    control = "3.1"
    description = "Ensure log metric filter unauthorized api calls"
    scored = True
    fail_reason = "Incorrect log metric alerts for unauthorized_api_calls"
    for m, n in cloudtrails.items():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.errorCode\s*=\s*\"?\*UnauthorizedOperation(\"|\)|\s)", "\$\.errorCode\s*=\s*\"?AccessDenied\*(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            sns_client = boto3.client('sns', region_name=m)
                            subscribers = sns_client.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 3.2 Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)
@time_decorator
def control_3_2_ensure_log_metric_filter_console_signin_no_mfa(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = False
    fail_reason = ""
    offenders = []
    control = "3.2"
    description = "Ensure a log metric filter and alarm exist for Management Console sign-in without MFA"
    scored = True
    fail_reason = "Incorrect log metric alerts for management console signin without MFA"
    for m, n in cloudtrails.items():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventName\s*=\s*\"?ConsoleLogin(\"|\)|\s)", "\$\.additionalEventData\.MFAUsed\s*\!=\s*\"?Yes"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            sns_client = boto3.client('sns', region_name=m)
                            subscribers = sns_client.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 3.3 Ensure a log metric filter and alarm exist for usage of "root" account (Scored)
@time_decorator
def control_3_3_ensure_log_metric_filter_root_usage(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = False
    fail_reason = ""
    offenders = []
    control = "3.3"
    description = "Ensure a log metric filter and alarm exist for root usage"
    scored = True
    fail_reason = "Incorrect log metric alerts for root usage"
    for m, n in cloudtrails.items():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.userIdentity\.type\s*=\s*\"?Root", "\$\.userIdentity\.invokedBy\s*NOT\s*EXISTS",
                                    "\$\.eventType\s*\!=\s*\"?AwsServiceEvent(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            sns_client = boto3.client('sns', region_name=m)
                            subscribers = sns_client.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 3.4 Ensure a log metric filter and alarm exist for IAM policy changes  (Scored)
@time_decorator
def control_3_4_ensure_log_metric_iam_policy_change(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = False
    fail_reason = ""
    offenders = []
    control = "3.4"
    description = "Ensure a log metric filter and alarm exist for IAM changes"
    scored = True
    fail_reason = "Incorrect log metric alerts for IAM policy changes"
    for m, n in cloudtrails.items():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventName\s*=\s*\"?DeleteGroupPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteRolePolicy(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?DeleteUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutGroupPolicy(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?PutRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutUserPolicy(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?CreatePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeletePolicy(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?CreatePolicyVersion(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeletePolicyVersion(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?AttachRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachRolePolicy(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?AttachUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachUserPolicy(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?AttachGroupPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachGroupPolicy(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            sns_client = boto3.client('sns', region_name=m)
                            subscribers = sns_client.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 3.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored)
@time_decorator
def control_3_5_ensure_log_metric_cloudtrail_configuration_changes(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = False
    fail_reason = ""
    offenders = []
    control = "3.5"
    description = "Ensure a log metric filter and alarm exist for CloudTrail configuration changes"
    scored = True
    fail_reason = "Incorrect log metric alerts for CloudTrail configuration changes"
    for m, n in cloudtrails.items():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventName\s*=\s*\"?CreateTrail(\"|\)|\s)", "\$\.eventName\s*=\s*\"?UpdateTrail(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?DeleteTrail(\"|\)|\s)", "\$\.eventName\s*=\s*\"?StartLogging(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?StopLogging(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            sns_client = boto3.client('sns', region_name=m)
                            subscribers = sns_client.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 3.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Scored)
@time_decorator
def control_3_6_ensure_log_metric_console_auth_failures(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = False
    offenders = []
    control = "3.6"
    description = "Ensure a log metric filter and alarm exist for console auth failures"
    scored = True
    fail_reason = "Ensure a log metric filter and alarm exist for console auth failures"
    for m, n in cloudtrails.items():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventName\s*=\s*\"?ConsoleLogin(\"|\)|\s)", "\$\.errorMessage\s*=\s*\"?Failed authentication(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            sns_client = boto3.client('sns', region_name=m)
                            subscribers = sns_client.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 3.7 Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Scored)
@time_decorator
def control_3_7_ensure_log_metric_disabling_scheduled_delete_of_kms_cmk(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = False
    offenders = []
    control = "3.7"
    description = "Ensure a log metric filter and alarm exist for disabling or scheduling deletion of KMS CMK"
    scored = True
    fail_reason = "Ensure a log metric filter and alarm exist for disabling or scheduling deletion of KMS CMK"
    for m, n in cloudtrails.items():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventSource\s*=\s*\"?kms\.amazonaws\.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DisableKey(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?ScheduleKeyDeletion(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            sns_client = boto3.client('sns', region_name=m)
                            subscribers = sns_client.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 3.8 Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)
@time_decorator
def control_3_8_ensure_log_metric_s3_bucket_policy_changes(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = False
    fail_reason = ""
    offenders = []
    control = "3.8"
    description = "Ensure a log metric filter and alarm exist for S3 bucket policy changes"
    scored = True
    fail_reason = "Ensure a log metric filter and alarm exist for S3 bucket policy changes"
    for m, n in cloudtrails.items():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventSource\s*=\s*\"?s3\.amazonaws\.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketAcl(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?PutBucketPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketCors(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?PutBucketLifecycle(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketReplication(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?DeleteBucketPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketCors(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?DeleteBucketLifecycle(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketReplication(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            sns_client = boto3.client('sns', region_name=m)
                            subscribers = sns_client.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 3.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes (Scored)
@time_decorator
def control_3_9_ensure_log_metric_config_configuration_changes(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = False
    fail_reason = ""
    offenders = []
    control = "3.9"
    description = "Ensure a log metric filter and alarm exist for for AWS Config configuration changes"
    scored = True
    fail_reason = "Ensure a log metric filter and alarm exist for for AWS Config configuration changes"
    for m, n in cloudtrails.items():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventSource\s*=\s*\"?config\.amazonaws\.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?StopConfigurationRecorder(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?DeleteDeliveryChannel(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutDeliveryChannel(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?PutConfigurationRecorder(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            sns_client = boto3.client('sns', region_name=m)
                            subscribers = sns_client.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 3.10 Ensure a log metric filter and alarm exist for security group changes (Scored)
@time_decorator
def control_3_10_ensure_log_metric_security_group_changes(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = False
    fail_reason = ""
    offenders = []
    control = "3.10"
    description = "Ensure a log metric filter and alarm exist for security group changes"
    scored = True
    fail_reason = "Ensure a log metric filter and alarm exist for security group changes"
    for m, n in cloudtrails.items():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventName\s*=\s*\"?AuthorizeSecurityGroupIngress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AuthorizeSecurityGroupEgress(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?RevokeSecurityGroupIngress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?RevokeSecurityGroupEgress(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?CreateSecurityGroup(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteSecurityGroup(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            sns_client = boto3.client('sns', region_name=m)
                            subscribers = sns_client.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 3.11 Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Scored)
@time_decorator
def control_3_11_ensure_log_metric_nacl(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = False
    fail_reason = ""
    offenders = []
    control = "3.11"
    description = "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)"
    scored = True
    fail_reason = "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)"
    for m, n in cloudtrails.items():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventName\s*=\s*\"?CreateNetworkAcl(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateNetworkAclEntry(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?DeleteNetworkAcl(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteNetworkAclEntry(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?ReplaceNetworkAclEntry(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?ReplaceNetworkAclAssociation(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            sns_client = boto3.client('sns', region_name=m)
                            subscribers = sns_client.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 3.12 Ensure a log metric filter and alarm exist for changes to network gateways (Scored)
@time_decorator
def control_3_12_ensure_log_metric_changes_to_network_gateways(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = False
    fail_reason = ""
    offenders = []
    control = "3.12"
    description = "Ensure a log metric filter and alarm exist for changes to network gateways"
    scored = True
    fail_reason = "Ensure a log metric filter and alarm exist for changes to network gateways"
    for m, n in cloudtrails.items():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventName\s*=\s*\"?CreateCustomerGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteCustomerGateway(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?AttachInternetGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateInternetGateway(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?DeleteInternetGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachInternetGateway(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            sns_client = boto3.client('sns', region_name=m)
                            subscribers = sns_client.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 3.13 Ensure a log metric filter and alarm exist for route table changes (Scored)
@time_decorator
def control_3_13_ensure_log_metric_changes_to_route_tables(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = False
    fail_reason = ""
    offenders = []
    control = "3.13"
    description = "Ensure a log metric filter and alarm exist for route table changes"
    scored = True
    fail_reason = "Ensure a log metric filter and alarm exist for route table changes"
    for m, n in cloudtrails.items():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventName\s*=\s*\"?CreateRoute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateRouteTable(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?ReplaceRoute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceRouteTableAssociation(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?DeleteRouteTable(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteRoute(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?DisassociateRouteTable(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            sns_client = boto3.client('sns', region_name=m)
                            subscribers = sns_client.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 3.14 Ensure a log metric filter and alarm exist for VPC changes (Scored)
@time_decorator
def control_3_14_ensure_log_metric_changes_to_vpc(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    cloudtrails = resource['cloudtrails']
    result = False
    fail_reason = ""
    offenders = []
    control = "3.14"
    description = "Ensure a log metric filter and alarm exist for VPC changes"
    scored = True
    fail_reason = "Ensure a log metric filter and alarm exist for VPC changes"
    for m, n in cloudtrails.items():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventName\s*=\s*\"?CreateVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteVpc(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?ModifyVpcAttribute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AcceptVpcPeeringConnection(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?CreateVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteVpcPeeringConnection(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?RejectVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachClassicLinkVpc(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?DetachClassicLinkVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DisableVpcClassicLink(\"|\)|\s)",
                                    "\$\.eventName\s*=\s*\"?EnableVpcClassicLink(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            sns_client = boto3.client('sns', region_name=m)
                            subscribers = sns_client.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# --- Networking ---

# 4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)
@time_decorator
def control_4_1_ensure_ssh_not_open_to_world(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    regions = resource['regions']
    result = True
    fail_reason = ""
    offenders = []
    control = "4.1"
    description = "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"
    scored = True
    for n in regions:
        client = boto3.client('ec2', region_name=n)
        response = client.describe_security_groups()
        for m in response['SecurityGroups']:
            if "0.0.0.0/0" in str(m['IpPermissions']):
                for o in m['IpPermissions']:
                    try:
                        if int(o['FromPort']) <= 22 <= int(o['ToPort']) and '0.0.0.0/0' in str(o['IpRanges']):
                            result = False
                            fail_reason = "Found Security Group with port 22 open to the world (0.0.0.0/0)"
                            offenders.append(str(m['GroupId']))
                    except:
                        if str(o['IpProtocol']) == "-1" and '0.0.0.0/0' in str(o['IpRanges']):
                            result = False
                            fail_reason = "Found Security Group with port 22 open to the world (0.0.0.0/0)"
                            offenders.append(str(n) + " : " + str(m['GroupId']))
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)
@time_decorator
def control_4_2_ensure_rdp_not_open_to_world(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    regions = resource['regions']
    result = True
    fail_reason = ""
    offenders = []
    control = "4.2"
    description = "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389"
    scored = True
    for n in regions:
        client = boto3.client('ec2', region_name=n)
        response = client.describe_security_groups()
        for m in response['SecurityGroups']:
            if "0.0.0.0/0" in str(m['IpPermissions']):
                for o in m['IpPermissions']:
                    try:
                        if int(o['FromPort']) <= 3389 <= int(o['ToPort']) and '0.0.0.0/0' in str(o['IpRanges']):
                            result = False
                            fail_reason = "Found Security Group with port 3389 open to the world (0.0.0.0/0)"
                            offenders.append(str(m['GroupId']))
                    except:
                        if str(o['IpProtocol']) == "-1" and '0.0.0.0/0' in str(o['IpRanges']):
                            result = False
                            fail_reason = "Found Security Group with port 3389 open to the world (0.0.0.0/0)"
                            offenders.append(str(n) + " : " + str(m['GroupId']))
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 4.3 Ensure the default security group of every VPC restricts all traffic (Scored)
@time_decorator
def control_4_3_ensure_default_security_groups_restricts_traffic(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    regions = resource['regions']
    result = True
    fail_reason = ""
    offenders = []
    control = "4.3"
    description = "Ensure the default security group of every VPC restricts all traffic"
    scored = True
    for n in regions:
        client = boto3.client('ec2', region_name=n)
        response = client.describe_security_groups(
            Filters=[
                {
                    'Name': 'group-name',
                    'Values': [
                        'default',
                    ]
                },
            ]
        )
        for m in response['SecurityGroups']:
            if not (len(m['IpPermissions']) + len(m['IpPermissionsEgress'])) == 0:
                result = False
                fail_reason = "Default security groups with ingress or egress rules discovered"
                offenders.append(str(n) + " : " + str(m['GroupId']))
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# 4.4 Ensure routing tables for VPC peering are "least access" (Not Scored)
@time_decorator
def control_4_4_ensure_route_tables_are_least_access(resource):
    """Summary

    Returns:
        TYPE: Description
    """
    regions = resource['regions']
    result = True
    fail_reason = ""
    offenders = []
    control = "4.4"
    description = "Ensure routing tables for VPC peering are least access"
    scored = False
    for n in regions:
        client = boto3.client('ec2', region_name=n)
        response = client.describe_route_tables()
        for m in response['RouteTables']:
            for o in m['Routes']:
                try:
                    if o['VpcPeeringConnectionId']:
                        if int(str(o['DestinationCidrBlock']).split("/", 1)[1]) < 24:
                            result = False
                            fail_reason = "Large CIDR block routed to peer discovered, please investigate"
                            offenders.append(str(n) + " : " + str(m['RouteTableId']))
                except:
                    pass
    return {'Result': result, 'failReason': fail_reason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control} #pylint: disable=broad-except


# --- Central functions ---

def get_cred_report():
    """Summary

    Returns:
        TYPE: Description
    """
    x = 0
    status = ""
    while IAM_CLIENT.generate_credential_report()['State'] != "COMPLETE":
        time.sleep(2)
        x += 1
        # If no credentail report is delivered within this time fail the check.
        if x > 10:
            status = "Fail: rootUse - no CredentialReport available."
            break
    if "Fail" in status:
        return status
    response = IAM_CLIENT.get_credential_report()
    report = []
    reader = csv.DictReader(response['Content'].decode("UTF-8").splitlines(), delimiter=',')
    for row in reader:
        report.append(row)

    # Verify if root key's never been used, if so add N/A
    try:
        if report[0]['access_key_1_last_used_date']:
            pass
    except:
        report[0]['access_key_1_last_used_date'] = "N/A"
    try:
        if report[0]['access_key_2_last_used_date']:
            pass
    except:
        report[0]['access_key_2_last_used_date'] = "N/A"
    return report


def get_account_password_policy():
    """Check if a IAM password policy exists, if not return false

    Returns:
        Account IAM password policy or False
    """
    try:
        response = IAM_CLIENT.get_account_password_policy()
        return response['PasswordPolicy']
    except Exception as e:
        if "cannot be found" in str(e):
            return False


def get_regions():
    """Summary

    Returns:
        TYPE: Description
    """
    client = boto3.client('ec2')
    region_response = client.describe_regions()
    regions = [region['RegionName'] for region in region_response['Regions']]
    return regions


def get_cloudtrails(regions):
    """Summary

    Returns:
        TYPE: Description
    """
    trails = dict()
    for n in regions:
        client = boto3.client('cloudtrail', region_name=n)
        response = client.describe_trails()
        temp = []
        for m in response['trailList']:
            if m['IsMultiRegionTrail'] is True:
                if m['HomeRegion'] == n:
                    temp.append(m)
            else:
                temp.append(m)
        if len(temp) > 0:
            trails[n] = temp
    return trails


def find_in_string(pattern, target):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    for n in pattern:
        if not re.search(n, target):
            result = False
            break
    return result


def get_account_number():
    """Summary

    Returns:
        TYPE: Description
    """
    if S3_WEB_REPORT_OBFUSCATE_ACCOUNT is False:
        client = boto3.client("sts")
        account = client.get_caller_identity()["Account"]
    else:
        account = "111111111111"
    return account


def set_evaluation(invokeEvent, main_event, annotation):
    """Summary

    Args:
        main_event (TYPE): Description
        annotation (TYPE): Description

    Returns:
        TYPE: Description
    """
    config_client = boto3.client('config')
    if len(annotation) > 0:
        config_client.put_evaluations(
            Evaluations=[
                {
                    'ComplianceResourceType': 'AWS::::Account',
                    'ComplianceResourceId': main_event['accountId'],
                    'ComplianceType': 'NON_COMPLIANT',
                    'Annotation': str(annotation),
                    'OrderingTimestamp': invokeEvent['notificationCreationTime']
                },
            ],
            ResultToken=main_event['resultToken']
        )
    else:
        config_client.put_evaluations(
            Evaluations=[
                {
                    'ComplianceResourceType': 'AWS::::Account',
                    'ComplianceResourceId': main_event['accountId'],
                    'ComplianceType': 'COMPLIANT',
                    'OrderingTimestamp': invokeEvent['notificationCreationTime']
                },
            ],
            ResultToken=main_event['resultToken']
        )


def json2html(control_result, account):
    """Summary

    Args:
        control_result (TYPE): Description

    Returns:
        TYPE: Description
    """
    table = []
    short_report = short_annotation(control_result)
    table.append("<html>\n<head>\n<style>\n\n.table-outer {\n    background-color: #eaeaea;\n    border: 3px solid darkgrey;\n}\
\n\n.table-inner {\n    background-color: white;\n    border: 3px solid darkgrey;\n}\n\n.table-hover tr{\nbackground: transparent;\n}\
\n\n.table-hover tr:hover {\nbackground-color: lightgrey;\n}\n\ntable, tr, td, th{\n    line-height: 1.42857143;\n    vertical-align: top;\n    \
border: 1px solid darkgrey;\n    border-spacing: 0;\n    border-collapse: collapse;\n    width: auto;\n    max-width: auto;\n    background-color: \
transparent;\n    padding: 5px;\n}\n\ntable th {\n    padding-right: 20px;\n    text-align: left;\n}\n\ntd {\n    width:100%;\n}\n\ndiv.centered\n\
{\n  position: absolute;\n  width: auto;\n  height: auto;\n  z-index: 15;\n  top: 10%;\n  left: 20%;\n  right: 20%;\n  background: white;\n}\n\ndiv.centered \
table\n{\n    margin: auto;\n    text-align: left;\n}\n</style>\n</head>\n<body>\n<h1 style=\"text-align: center;\">AWS CIS Foundation Framework</h1>\n\
<div class=\"centered\">")
    table.append("<table class=\"table table-inner\">")
    table.append("<tr><td>Account: " + account + "</td></tr>")
    table.append("<tr><td>Report date: " + time.strftime("%c") + "</td></tr>")
    table.append("<tr><td>Benchmark version: " + AWS_CIS_BENCHMARK_VERSION + "</td></tr>")
    table.append("<tr><td>Whitepaper location: <a href=\"https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf\" \
target=\"_blank\">https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf</a></td></tr>")
    table.append("<tr><td>" + short_report + "</td></tr></table><br><br>")
    tableHeadOuter = "<table class=\"table table-outer\">"
    tableHeadInner = "<table class=\"table table-inner\">"
    tableHeadHover = "<table class=\"table table-hover\">"
    table.append(tableHeadOuter)  # Outer table
    for m, _ in enumerate(control_result):
        table.append("<tr><th>" + control_result[m][0]['ControlId'].split('.')[0] + "</th><td>" + tableHeadInner)
        for n in range(len(control_result[m])):
            if str(control_result[m][n]['Result']) == "False":
                result_style = " style=\"background-color:#ef3d47;\""
            elif str(control_result[m][n]['Result']) == "Manual":
                result_style = " style=\"background-color:#ffff99;\""
            else:
                result_style = " style=\"background-color:lightgreen;\""
            table.append("<tr><th" + result_style + ">" + control_result[m][n]['ControlId'].split('.')[1] + "</th><td>" + tableHeadHover)
            table.append("<tr><th>ControlId</th><td>" + control_result[m][n]['ControlId'] + "</td></tr>")
            table.append("<tr><th>Description</th><td>" + control_result[m][n]['Description'] + "</td></tr>")
            table.append("<tr><th>failReason</th><td>" + control_result[m][n]['failReason'] + "</td></tr>")
            table.append("<tr><th>Offenders</th><td><ul>" + str(control_result[m][n]['Offenders']).replace("', ", "',<br>") + "</ul></td></tr>")
            table.append("<tr><th>Result</th><td>" + str(control_result[m][n]['Result']) + "</td></tr>")
            table.append("<tr><th>ScoredControl</th><td>" + str(control_result[m][n]['ScoredControl']) + "</td></tr>")
            table.append("</table></td></tr>")
        table.append("</table></td></tr>")
    table.append("</table>")
    table.append("</div>\n</body>\n</html>")
    return table

def s3report(html_report, json_report, account):
    """Summary

    Args:
        html_report (TYPE): Description

    Returns:
        TYPE: Description
    """
    signed_url_list = list()
    global S3_REPORT_BUCKET
    if not S3_REPORT_BUCKET:
        try:
            S3_REPORT_BUCKET = os.environ['S3_REPORT_BUCKET']
        except KeyError as e:
            logger.error("Bucket not set: {0}".format(e))

    def detailed_name(acc, ext):
        return "{0}.{1}".format("cis_report_" + str(acc) + "_" + str(datetime.now().strftime('%Y%m%d_%H%M')), ext)

    def s3_upload(byte_obj, name, bucket=S3_REPORT_BUCKET):
        ttl = int(S3_WEB_REPORT_EXPIRE) * 60
        try:
            S3_CLIENT.upload_fileobj(byte_obj, bucket, name)
        except Exception as e:
            logger.error("Failed to upload {0} report to S3 because: {1}".format(name, str(e)))
            return ""

        return S3_CLIENT.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': bucket,
                'Key': name
            },
            ExpiresIn=ttl)

    # upload HTML report
    if S3_WEB_REPORT_NAME_DETAILS:
        html_report_name = detailed_name(account, 'html')
    else:
        html_report_name = "cis_report.html"
    fd = StringIO()
    for item in html_report:
        fd.write(item)
    html_url = s3_upload(BytesIO(fd.getvalue().encode()), html_report_name)

    # upload json report
    if S3_JSON_NAME_DETAILS:
        json_report_name = detailed_name(account, 'json')
    else:
        json_report_name = "cis_report.json"

    json_url = s3_upload(BytesIO(json_report.encode()), json_report_name)

    signed_url_list = [html_url, json_url]

    return signed_url_list


def json_result(control_result):
    """Summary

    Args:
        control_result (TYPE): Description

    Returns:
        string: json with all benchmark results
    """

    outer = dict()
    for m in range(len(control_result)):
        inner = dict()
        for n in range(len(control_result[m])):
            x = int(control_result[m][n]['ControlId'].split('.')[1])
            inner[x] = control_result[m][n]
        y = control_result[m][0]['ControlId'].split('.')[0]
        outer[y] = inner
    return json.dumps(outer, sort_keys=True, indent=4, separators=(',', ': '))


def print_json(result, annotation):
    """Summary

    Args:
        controlResult (TYPE): Description

    Returns:
        TYPE: Description
    """

    if OUTPUT_ONLY_JSON is True:
        logger.info(result)
    else:
        logger.info("JSON output:")
        logger.info("-------------------------------------------------------")
        logger.info(result)
        logger.info("-------------------------------------------------------")
        logger.info("\n")
        logger.info("Summary:")
        logger.info(annotation)
        logger.info("\n")
    return 0


def short_annotation(control_result):
    """Summary

    Args:
        control_result (TYPE): Description

    Returns:
        TYPE: Description
    """
    annotation = []
    long_annotation = False
    for m, _ in enumerate(control_result):
        for n in range(len(control_result[m])):
            if control_result[m][n]['Result'] is False:
                if len(str(annotation)) < 220:
                    annotation.append(control_result[m][n]['ControlId'])
                else:
                    long_annotation = True
    if long_annotation:
        annotation.append("etc")
        return "{\"Failed\":" + json.dumps(annotation) + "}"
    else:
        return "{\"Failed\":" + json.dumps(annotation) + "}"


def send_results_to_sns(url):
    """Summary

    Args:
        url (TYPE): SignedURL created by the S3 upload function

    Returns:
        TYPE: Description
    """
    # Get correct region for the TopicARN
    region = (SNS_TOPIC_ARN.split("sns:", 1)[1]).split(":", 1)[0]
    client = boto3.client('sns', region_name=region)
    client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="AWS CIS Benchmark report - " + str(time.strftime("%c")),
        Message=json.dumps({'default': url}),
        MessageStructure='json'
    )


def lambda_handler(event, context):
    """Summary

    Args:
        event (TYPE): Description
        context (TYPE): Description

    Returns:
        TYPE: Description
    """
    # Run all control validations.
    # The control object is a dictionary with the value
    # result : Boolean - True/False
    # failReason : String - Failure description
    # scored : Boolean - True/False
    # Check if the script is initiade from AWS Config Rules
    try:
        if event['configRuleId']:
            config_rule = True
            # Verify correct format of event
            invoking_event = json.loads(event['invokingEvent'])
    except:
        config_rule = False

    # Globally used resources
    region_list = get_regions()
    cred_report = get_cred_report()
    password_policy = get_account_password_policy()
    cloud_trails = get_cloudtrails(region_list)
    account_number = get_account_number()


    global_resources = {
        "regions": region_list,
        "credreport": cred_report,
        "passwordpolicy": password_policy,
        "cloudtrails": cloud_trails,
        "accountnumber": account_number
    }

    controls_map = {
        "control1": [
        control_1_1_root_use,
        control_1_2_mfa_on_password_enabled_iam,
        control_1_3_unused_credentials,
        control_1_4_rotated_keys,
        control_1_5_password_policy_uppercase,
        control_1_6_password_policy_lowercase,
        control_1_7_password_policy_symbol,
        control_1_8_password_policy_number,
        control_1_9_password_policy_length,
        control_1_10_password_policy_reuse,
        control_1_11_password_policy_expire,
        control_1_12_root_key_exists,
        control_1_13_root_mfa_enabled,
        control_1_14_root_hardware_mfa_enabled,
        control_1_15_security_questions_registered,
        control_1_16_no_policies_on_iam_users,
        control_1_17_maintain_current_contact_details,
        control_1_18_ensure_security_contact_details,
        control_1_19_ensure_iam_instance_roles_used,
        control_1_20_ensure_incident_management_roles,
        control_1_21_no_active_initial_access_keys_with_iam_user,
        control_1_22_no_overly_permissive_policies
        ],
        'control2': [
        control_2_1_ensure_cloud_trail_all_regions,
        control_2_2_ensure_cloudtrail_validation,
        control_2_3_ensure_cloudtrail_bucket_not_public,
        control_2_4_ensure_cloudtrail_cloudwatch_logs_integration,
        control_2_5_ensure_config_all_regions,
        control_2_6_ensure_cloudtrail_bucket_logging,
        control_2_7_ensure_cloudtrail_encryption_kms,
        control_2_8_ensure_kms_cmk_rotation,
        control_2_9_ensure_flow_logs_enabled_on_all_vpc
        ],
        'control3': [
        control_3_1_ensure_log_metric_filter_unauthorized_api_calls,
        control_3_2_ensure_log_metric_filter_console_signin_no_mfa,
        control_3_3_ensure_log_metric_filter_root_usage,
        control_3_4_ensure_log_metric_iam_policy_change,
        control_3_5_ensure_log_metric_cloudtrail_configuration_changes,
        control_3_6_ensure_log_metric_console_auth_failures,
        control_3_7_ensure_log_metric_disabling_scheduled_delete_of_kms_cmk,
        control_3_8_ensure_log_metric_s3_bucket_policy_changes,
        control_3_9_ensure_log_metric_config_configuration_changes,
        control_3_10_ensure_log_metric_security_group_changes,
        control_3_11_ensure_log_metric_nacl,
        control_3_12_ensure_log_metric_changes_to_network_gateways,
        control_3_13_ensure_log_metric_changes_to_route_tables,
        control_3_14_ensure_log_metric_changes_to_vpc
        ],
        'control4': [
        control_4_1_ensure_ssh_not_open_to_world,
        control_4_2_ensure_rdp_not_open_to_world,
        control_4_3_ensure_default_security_groups_restricts_traffic,
        control_4_4_ensure_route_tables_are_least_access
        ]
    }

    # multipreocessing per controls set
    # TODO: rework the logic in order to handle all benchmarks in one pool.map
    pool = ThreadPool(processes=10)

    def worker(func):
        return func(global_resources)

    controls = []
    controls.append(pool.map(worker, controls_map['control1']))
    controls.append(pool.map(worker, controls_map['control2']))
    controls.append(pool.map(worker, controls_map['control3']))
    controls.append(pool.map(worker, controls_map['control4']))


    # JSON result
    json_out = json_result(controls)

    # Annotation
    annotation = short_annotation(controls)

    # Build JSON structure for console output if enabled
    if SCRIPT_OUTPUT_JSON:
        print_json(json_out, annotation)

    # Create HTML report file if enabled
    if S3_WEB_REPORT:
        html_report = json2html(controls, account_number)
        if S3_WEB_REPORT_OBFUSCATE_ACCOUNT:
            for n, _ in enumerate(html_report):
                html_report[n] = re.sub(r"\d{12}", "111111111111", html_report[n])
        signed_url_list = s3report(html_report, json_out, account_number)
        if OUTPUT_ONLY_JSON is False:
            [logger.info("SignedURL: " + signed_url) if signed_url else "URL not available" for signed_url in signed_url_list]
        if SEND_REPORT_URL_TO_SNS is True:
            [send_results_to_sns(signed_url) if signed_url else "URL not available" for signed_url in signed_url_list]

    # Report back to Config if we detected that the script is initiated from Config Rules
    if config_rule:
        eval_annotation = short_annotation(controls)
        set_evaluation(invoking_event, event, eval_annotation)


if __name__ == '__main__':
    PROFILE_NAME = ''
    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:h", ["profile=", "help"])
    except getopt.GetoptError:
        print("Error: Illegal option\n")
        print("---Usage---")
        print('Run without parameters to use default profile:')
        print("python " + sys.argv[0] + "\n")
        print("Use -p or --profile to specify a specific profile:")
        print("python " + sys.argv[0] + ' -p <profile>')
        sys.exit(2)

    # Parameter options
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print("---Help---")
            print('Run without parameters to use default profile:')
            print("python " + sys.argv[0] + "\n")
            print("Use -p or --profile to specify a specific profile:")
            print("python " + sys.argv[0] + ' -p <profile>')
            sys.exit()
        elif opt in ("-p", "--profile"):
            PROFILE_NAME = arg

    # Verify that the profile exist
    if not PROFILE_NAME == "":
        try:
            boto3.setup_default_session(profile_name=PROFILE_NAME)
            # Update globals with new profile
            IAM_CLIENT = boto3.client('iam')
        except Exception as e:
            if "could not be found" in str(e):
                print("Error: " + str(e))
                print("Please verify your profile name.")
                sys.exit(2)

    # Test if default region is configured for the used profile, if not we will use us-east-1
    try:
        client = boto3.client('ec2')
    except Exception as e:
        if "You must specify a region" in str(e):
            if PROFILE_NAME == "":
                boto3.setup_default_session(region_name='us-east-1')
            else:
                boto3.setup_default_session(profile_name=PROFILE_NAME, region_name='us-east-1')
    lambda_handler("test", "test")
