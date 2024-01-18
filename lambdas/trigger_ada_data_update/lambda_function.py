import json
import logging
from os import getenv

import requests
import boto3
from botocore.exceptions import ClientError

ADA_API_BASE_URL = getenv("ADA_API_BASE_URL").rstrip("/")
ADA_API_KEY_SECRET_NAME = getenv("ADA_API_KEY_SECRET_NAME")
ADA_DOMAIN_NAME = getenv("ADA_DOMAIN_NAME")
ADA_API_TIMEOUT = 10

logger = logging.getLogger()
logger.setLevel(logging.INFO)

secretsmanager_client = boto3.client("secretsmanager")

def get_secret() -> str:
    """
    Retrieves ADA API call from AWS Secrets Manager.

    :return: Secret string for ADA API key.
    """
    try:
        get_secret_value_response = secretsmanager_client.get_secret_value(
            SecretId=ADA_API_KEY_SECRET_NAME
        )
        secret = get_secret_value_response["SecretString"]
    except ClientError as e:
        logger.error(f"Failed to get secret value.\nError: {e}")
        raise e
    return secret

def lambda_handler(event, context):
    """
    Lambda function to trigger ADA API call to start data update.
    
    :param event: Event object.
    :param context: Context object.
    :return: Response object.
    """
    
    logger.debug(f"Event: {event}")
    api_key = get_secret()
    flow_name = event["flow-name"]
    data_product_id = event["data_product_id"]
    url = f"{ADA_API_BASE_URL}/data-product/domain/{ADA_DOMAIN_NAME}/data-product/{data_product_id}"
    headers = {
        "Authorization": f"api-key {api_key}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
    }
    try:
        r = requests.get(url, headers=headers, timeout=ADA_API_TIMEOUT)
        r.raise_for_status()
        if r.json()["dataStatus"] != "READY":
            logger.info(
                f"Data product not in READY state, cannot trigger data product update."
            )
            return {
                "statusCode": 200,
                "body": {
                    "request-type": "trigger-data-update",
                    "trigger-data-update": "SKIPPED",
                    "flow-name": flow_name,
                    "data-product-id": data_product_id
                }
            }
        data_update_r = requests.put(f"{url}/start-data-update", headers=headers, timeout=ADA_API_TIMEOUT)
        data_update_r.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error(
            f"Failed to trigger data update.\n Error: {e}"
        )

    return {
        "statusCode": 200, 
        "body": {
            "request-type": "trigger-data-update",
            "trigger-data-update": "DONE",
            "flow-name": flow_name,
            "data-product-id": data_product_id
        }
    }
