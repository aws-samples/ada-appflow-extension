import base64
import datetime
import json
import logging
from os import getenv

import boto3
import requests
from botocore.exceptions import ClientError
from requests.adapters import HTTPAdapter, Retry

# Set environment variables
ADA_ACCOUNT_ID = getenv("ADA_ACCOUNT_ID")
ADA_API_BASE_URL = getenv("ADA_API_BASE_URL").rstrip("/")
ADA_API_KEY_SECRET_NAME = getenv("ADA_API_KEY_SECRET_NAME")
ADA_DOMAIN_NAME = getenv("ADA_DOMAIN_NAME")
ADA_USER_GROUP_NAME = getenv("ADA_USER_GROUP_NAME")
FLOW_METADATA_TABLE_NAME = getenv("FLOW_METADATA_TABLE_NAME")
ADA_API_TIMEOUT = 60

# Initialize the logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Create AWS service clients
ddb_client = boto3.client("dynamodb")
sm_client = boto3.client("secretsmanager")
s3_client = boto3.client('s3')

# Create requests session with retry configuration
session = requests.Session()
retries = Retry(
    total=5,
    backoff_factor=1,
    status_forcelist=[
        400,
        500,
        502,
        503,
        504])
session.mount("https://", HTTPAdapter(max_retries=retries))


def set_bucket_policy(data_product_bucket: str) -> None:
    """
    Calls S3 API to set bucket policy for ADA data access.

    :param data_product_bucket: The name of the data product bucket.
    """
    logger.info("Setting bucket policy to allow ADA data access.")
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Grant Automated Data Analytics on AWS Group access in one of group",
                "Effect": "Allow",
                "Action": "s3:Get*",
                "Resource": f"arn:aws:s3:::{data_product_bucket}/*",
                "Principal": {
                    "AWS": [f"arn:aws:iam::{ADA_ACCOUNT_ID}:root"]
                },
                "Condition": {
                    "ForAnyValue:StringLike": {
                        "aws:PrincipalTag/ada:groups": ["*:power-user:*", f"*:{ADA_USER_GROUP_NAME}:*"]
                    }
                }
            }, {
                "Sid": "Grant Automated Data Analytics on AWS Federated Query access",
                "Effect": "Allow",
                "Action": "s3:Get*",
                "Resource": f"arn:aws:s3:::{data_product_bucket}/*",
                "Principal": {
                    "AWS": [f"arn:aws:iam::{ADA_ACCOUNT_ID}:root"]
                },
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalTag/ada:service": "query"
                    }
                }
            }
        ]
    }

    # Check for existing bucket policy and append new statements if policy
    # already exists
    try:
        existing_policy = s3_client.get_bucket_policy(
            Bucket=data_product_bucket)
        policy_document = json.loads(existing_policy['Policy'])
        for statement in bucket_policy["Statement"]:
            if statement not in policy_document["Statement"]:
                policy_document["Statement"].append(statement)
    except s3_client.exceptions.NoSuchBucketPolicy:
        policy_document = bucket_policy
    except ClientError as e:
        logger.error(
            f"Failed to check for existing bucket policy.\nError: {e}")
        raise e

    # Set bucket policy
    try:
        s3_client.put_bucket_policy(
            Bucket=data_product_bucket,
            Policy=json.dumps(policy_document))
    except ClientError as e:
        logger.error(f"Failed to set bucket policy.\nError: {e}")
        raise e


def get_secret() -> str:
    """
    Retrieves ADA API call from AWS Secrets Manager.

    :return: Secret string for ADA API key.
    """
    logger.info("Getting API key value for ADA connection.")
    try:
        get_secret_value_response = sm_client.get_secret_value(
            SecretId=ADA_API_KEY_SECRET_NAME
        )
        if "SecretBinary" in get_secret_value_response:
            secret = base64.b64decode(
                get_secret_value_response["SecretBinary"])
        elif "SecretString" in get_secret_value_response:
            secret = get_secret_value_response["SecretString"]
        else:
            raise ValueError("Secret value not found in response.")
    except ClientError as e:
        logger.error(f"Failed to get secret value.\nError: {e}")
        raise e
    else:
        logger.info("Successfully retrieved API key.")
        return secret


def update_flow_item(data_product_id: str, flow_name: str) -> None:
    """
    Updates flow item in Amazon DynamoDB to add information on ADA data product.

    :param data_product_id: Information on ADA data product to add to flow item.
    :param flow_name: Name of flow to update.
    """
    logger.info("Adding ADA data product information to flow item.")
    data_product_info = {
        "id": {"S": data_product_id},
        "created-time": {"S": datetime.datetime.now().isoformat()},
        "domain-id": {"S": ADA_DOMAIN_NAME},
    }

    try:
        ddb_client.update_item(
            TableName=FLOW_METADATA_TABLE_NAME,
            Key={"flow-name": {"S": flow_name}},
            UpdateExpression="SET #dp = :d",
            ExpressionAttributeValues={":d": {"M": data_product_info}},
            ExpressionAttributeNames={"#dp": "data-product-info"},
            ReturnValues="NONE",
        )
        logger.info(
            "Successfully added ADA data product information to flow item.")
    except ClientError as e:
        logger.error(f"Failed to get secret value.\nError: {e}")
        raise e


def create_data_product(
    api_key: str, flow_name: str, data_product_bucket: str, data_product_key: str
) -> str:
    """
    Calls ADA API for creation of new data product.

    :param api_key: Secret string for ADA API key.
    :param flow_name: Name of flow corresponding to data product.
    :param data_product_bucket: The name of the data product bucket.
    :param data_product_key: The name of the data product key.
    :return: ID of newly created ADA data product.
    """
    logger.info("Creating ADA data product")
    data_product_id = f"ada_appflow_ext_{flow_name}"
    url = f"{ADA_API_BASE_URL}/data-product/domain/{ADA_DOMAIN_NAME}/data-product/{data_product_id}"
    headers = {
        "Authorization": f"api-key {api_key}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
    }
    payload = json.dumps(
        {
            "name": data_product_id,
            "description": f"Data Product created by Ada AppFlow Extension for flow: {flow_name}",
            "sourceType": "S3",
            "sourceDetails": {"bucket": data_product_bucket, "key": data_product_key},
            "transforms": [],
            "enableAutomaticPii": True,
            "updateTrigger": {"updatePolicy": "APPEND", "triggerType": "ON_DEMAND"},
            "tags": [{"key": "appFlowExtension", "value": "1"}],
        }
    )
    try:
        create_data_product = session.post(
            url, headers=headers, data=payload, timeout=ADA_API_TIMEOUT
        )
        create_data_product.raise_for_status()
    except requests.exceptions.Timeout:
        logger.info(
            "ADA did not confirm start of data creation within timeout window. Running check if creation was still successfully launched.")
        if data_product_exists(api_key, data_product_id):
            logger.info(
                f"Successfully confirmed existence of ADA data product with id: {data_product_id}")
            return data_product_id
        else:
            logger.error("ADA data product creation was not successful.")
            raise Exception("Could not confirm ADA data product creation.")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to create ADA data product.\nError: {e}")
        raise e
    else:
        logger.info(
            f"Successfully created ADA data product with id: {data_product_id}")
        return data_product_id


def data_product_exists(
    api_key: str, data_product_id: str
) -> str:
    """
    Calls ADA API to check if data product exists.

    :param api_key: Secret string for ADA API key.
    :param data_product_id: ID of ADA data product.
    :return: True if the data product exists (status code is 200), False otherwise.
    """
    logger.info("Getting status of ADA data product")
    url = f"{ADA_API_BASE_URL}/data-product/domain/{ADA_DOMAIN_NAME}/data-product/{data_product_id}"
    headers = {
        "Authorization": f"api-key {api_key}",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
    }
    try:
        get_data_product = session.get(
            url, headers=headers, timeout=ADA_API_TIMEOUT
        )
        status_code = get_data_product.status_code
        if status_code == 200:
            logger.info(
                f"Successfully verified existence of ADA data product: {data_product_id}")
            return True
        else:
            logger.info(
                f"ADA data product not found. Status code: {status_code}")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to get ADA data product.\nError: {e}")
        raise e


def delete_data_product_permissions(api_key, data_product_id) -> None:
    """
    Calls ADA API to delete permissions for data product as a prerequisite to setting permissions for ADA_USER_GROUP_NAME.

    :param api_key: Secret string for ADA API key.
    :param data_product_id: ID of ADA data product to update.
    """
    logger.info("Deleting ADA data product permissions.")
    url = f"{ADA_API_BASE_URL}/governance/policy/domain/{ADA_DOMAIN_NAME}/data-product/{data_product_id}"
    headers = {
        "Authorization": f"api-key {api_key}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
    }
    try:
        delete_permissions = session.delete(
            url, headers=headers, timeout=ADA_API_TIMEOUT)
        if delete_permissions.status_code == 404:
            logger.info(f"No permissions to delete.")
            return
        delete_permissions.raise_for_status()
        logger.info("Successfully deleted ADA data product permissions.")
    except requests.exceptions.RequestException as e:
        logger.error(
            f"Failed to delete permissions for ADA data product.\nError: {e}")
        raise e


def set_data_product_permissions(api_key, data_product_id) -> None:
    """
    Calls ADA API to set ADA_USER_GROUP_NAME permissions for data product.

    :param api_key: Secret string for ADA API key.
    :param data_product_id: ID of ADA data product to update.
    """
    logger.info(
        f"Updating ADA data product permissions to allow user group: {ADA_USER_GROUP_NAME}"
    )
    url = f"{ADA_API_BASE_URL}/governance/policy/domain/{ADA_DOMAIN_NAME}/data-product/{data_product_id}"

    headers = {
        "Authorization": f"api-key {api_key}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
    }
    payload = json.dumps(
        {
            "dataProductId": data_product_id,
            "domainId": ADA_DOMAIN_NAME,
            "permissions": {
                ADA_USER_GROUP_NAME: {"access": "FULL"},
                "admin": {"access": "FULL"},
            },
        }
    )

    try:
        set_permissions = session.put(
            url, headers=headers, data=payload, timeout=ADA_API_TIMEOUT)
        set_permissions.raise_for_status()
        logger.info("Successfully updated ADA data product permissions.")
    except requests.exceptions.RequestException as e:
        logger.error(
            f"Failed to set permissions for ADA data product.\nError: {e}")
        raise e


def lambda_handler(event, context):
    flow_name = event["flow-name"]
    data_product_bucket = event["destination-details"]["bucket"]
    data_product_key = event["destination-details"]["key"]

    set_bucket_policy(data_product_bucket)
    api_key = get_secret()
    data_product_id = create_data_product(
        api_key, flow_name, data_product_bucket, data_product_key
    )

    update_flow_item(data_product_id, flow_name)
    delete_data_product_permissions(api_key, data_product_id)
    set_data_product_permissions(api_key, data_product_id)

    return {
        "statusCode": 200,
        "body": {
            "request-type": "create-data-product",
            "data-product-id": data_product_id,
            "flow-name": flow_name,
        },
    }
