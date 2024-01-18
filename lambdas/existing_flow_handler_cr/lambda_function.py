import json
import logging
from os import getenv

import boto3
import requests
from botocore.exceptions import ClientError
from requests.adapters import HTTPAdapter, Retry

ADA_API_BASE_URL = getenv("ADA_API_BASE_URL").rstrip("/")
ADA_API_KEY_SECRET_NAME = getenv("ADA_API_KEY_SECRET_NAME")
ADA_DOMAIN_NAME = getenv("ADA_DOMAIN_NAME")
ADA_USER_GROUP_NAME = getenv("ADA_USER_GROUP_NAME")
STATE_MACHINE_ARN = getenv("STATE_MACHINE_ARN")
ADA_API_TIMEOUT = 60

logger = logging.getLogger()
logger.setLevel(logging.INFO)

appflow_client = boto3.client("appflow")
secretsmanager_client = boto3.client("secretsmanager")
sfn_client = boto3.client("stepfunctions")

# requests session
session = requests.Session()
retries = Retry(total=5, backoff_factor=1, status_forcelist=[400, 500, 502, 503, 504])
session.mount("https://", HTTPAdapter(max_retries=retries))


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


def create_ada_domain(api_key: str) -> str:
    """
    Calls ADA API for creating ADA Domain.

    :param api_key: Secret string for ADA API key.
    :return: ADA Domain object string.

    """
    url = f"{ADA_API_BASE_URL}/data-product/domain/{ADA_DOMAIN_NAME}"
    headers = {
        "Authorization": f"api-key {api_key}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
    }
    data = json.dumps(
        {
            "name": "ADA AppFlow Extension Domain",
            "description": "ADA domain for AppFlow extension",
        }
    )
    try:
        check_domain = session.get(url, headers=headers, timeout=ADA_API_TIMEOUT)
        if check_domain.status_code == 404:
            create_domain = session.put(url, headers=headers, data=data, timeout=ADA_API_TIMEOUT)
            create_domain.raise_for_status()
            return create_domain.text
        elif check_domain.status_code == 200:
            logger.info(f"{ADA_DOMAIN_NAME} domain already exists.")
            return check_domain.text
        else:
            raise SystemExit(f'Failed to get ADA Domain.\nResponse"{check_domain.text}')
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to create ADA domain.\nError: {e}")
        raise e


def create_ada_user_group(api_key: str) -> str:
    """
    Calls ADA API for creating ADA User Group.

    :param api_key: Secret string for ADA API key.
    :return: ADA User Group object string.
    
    """
    url = f"{ADA_API_BASE_URL}/identity/group/{ADA_USER_GROUP_NAME}"
    headers = {
        "Authorization": f"api-key {api_key}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
    }
    data = json.dumps(
        {
            "description": "ADA AppFlow extension user group",
            "apiAccessPolicyIds": ["default", "manage_data_products"],
            "claims": [],
            "members": [],
        }
    )
    try:
        check_usergroup = session.get(url, headers=headers, timeout=ADA_API_TIMEOUT)
        if check_usergroup.status_code == 404:
            create_usergroup = session.put(url, headers=headers, data=data, timeout=ADA_API_TIMEOUT)
            create_usergroup.raise_for_status()
            return create_usergroup.text
        elif check_usergroup.status_code == 200:
            logger.info(f"{ADA_USER_GROUP_NAME} user group already exists.")
            return check_usergroup.text
        else:
            raise SystemExit(
                f'Failed to get ADA usergroup.\nResponse"{check_usergroup.text}'
            )
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to create ADA user group.\nError: {e}")
        raise e


def get_flows() -> list:
    """
    Calls AppFlow API for listing flows.

    :return: List of existing flows.
    """
    try:
        response = appflow_client.list_flows()
        flows = response["flows"]
        # custom loop as paginator not supported
        while "NextToken" in response:
            response = appflow_client.list_flows(NextToken=response["NextToken"])
            flows.extend(response["flows"])
        logger.debug(f"Existing flows: {flows}")

        target_flows = []
        for flow in flows:
            if (
                flow["destinationConnectorType"] == "S3"
                and flow["flowStatus"] == "Active"
            ):
                flow_detail = appflow_client.describe_flow(flowName=flow["flowName"])
                flow_name = flow_detail["flowName"]
                destination_bucket_name = flow_detail["destinationFlowConfigList"][0][
                    "destinationConnectorProperties"
                ]["S3"]["bucketName"]
                destination_bucket_prefix = flow_detail["destinationFlowConfigList"][0][
                    "destinationConnectorProperties"
                ]["S3"].get("bucketPrefix")
                if destination_bucket_prefix is None:
                    destination_object = f"s3://{destination_bucket_name}"
                else:
                    destination_object = f"s3://{destination_bucket_name}/{destination_bucket_prefix}"

                target_flow_detail = {
                    "flow-name": flow_name,
                    "flow-arn": flow_detail["flowArn"],
                    "created-by": flow_detail["createdBy"],
                    "trigger-type": flow_detail["triggerConfig"]["triggerType"],
                    "status": flow_detail["flowStatus"],
                    "source": flow_detail["sourceFlowConfig"]["connectorType"],
                    "source-object": flow_detail.get("sourceFlowConfig", {}),
                    "destination": flow_detail["destinationFlowConfigList"][0][
                        "connectorType"
                    ],
                    "destination-object": destination_object,
                }
                target_flows.append(target_flow_detail)
        logger.debug(f"Target existing flows detail: {target_flows}")

    except ClientError as e:
        logger.error(f"Failed to get AppFlow flows.\nError: {e}")
        raise e
    except KeyError as key_err:
        logger.error(f"Missing key.\nError: {key_err}")
    return target_flows


def trigger_sm(flows: list) -> None:
    """
    Triggers state machine execution for the list of flows.

    :param flows: List of flows.
    :return: None
    
    """
    for flow in flows:
        flow_name = flow["flow-name"]
        logger.info(f"Triggering state machine execution for the flow: {flow_name}")
        input_doc = {
            "version": "0",
            "source": "ada-appflow-extension-cr",
            "detail": flow,
        }
        try:
            sm_response = sfn_client.start_execution(
                stateMachineArn=STATE_MACHINE_ARN, input=json.dumps(input_doc)
            )
        except ClientError as e:
            logger.error(
                f"Failed to trigger state machine execution for the flow: {flow_name}. Error: {e}"
            )
        logger.info(
            f"Successfully triggered state machine execution for the flow: {flow_name}"
        )

    return


def lambda_handler(event, context):
    if event["RequestType"] == "Create":
        api_key = get_secret()

        logger.info(f"Creating ADA Domain, domain_id:{ADA_DOMAIN_NAME}")
        ada_domain_response = create_ada_domain(api_key)
        logger.info(
            f"ADA domain created successfully.\nResponse: {ada_domain_response}"
        )

        logger.info(f"Creating ADA User group, user_group_id:{ADA_USER_GROUP_NAME}")
        ada_user_group_response = create_ada_user_group(api_key)
        logger.info(
            f"ADA user group created successfully.\nResponse: {ada_user_group_response}"
        )

        logger.info("Getting list of existing target AppFlow flows.")
        flows = get_flows()
        logger.info("Target AppFlow flows collected successfully.\nResponse: {flows}")

        logger.info(
            f"Triggering state machine for target flows, state_machine_arn: {STATE_MACHINE_ARN}"
        )
        trigger_sm(flows)
        logger.info(f"State machine execution triggering complete successfully.")

    else:
        logger.info(f'Ignoring RequestType: {event["RequestType"]}.')

    return
