"""This lambda function is invoked as part of step function workflow.
This lambda function receives the flow events from Appflow and checks whether data
product exists for this flow or not and inserts the flow information into MetaData Store.
"""
import logging
import os

import boto3
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """
    Entry point for lambda function.

    :return: flow and existing data product information in a json.
    """
    return update_flow_metadata(event)


def update_flow_metadata(event):
    """
    Validates whether data product exists and inserts/updates the flow information into MetaData store.

    :return: flow information along with data product exists or not.
    """
    logging.info("[Start] - update flow metadata")
    detail = event["detail"]
    flow_name = detail["flow-name"]
    table_name = os.environ["FLOW_METADATA_TABLE_NAME"]
    flow_table = dynamodb.Table(table_name)
    is_data_product_exists = False
    data_product_id = None

    try:
        response = flow_table.get_item(Key={"flow-name": flow_name})
    except ClientError as e:
        logging.error(
            e.response["Error while retrieving flow information from DynamoDB"]
        )
    else:
        if "Item" in response:
            logging.info("Flow information exists in Metadata store !")

            if "data-product-info" in response["Item"]:
                logging.info("Data product information exists in Metadata store !")
            
                if response["Item"]["data-product-info"]["id"] is not None:
                    is_data_product_exists = True
                    data_product_id = response["Item"]["data-product-info"]["id"]
                    bucket_name, key = read_bucket_name_and_key(
                        detail["flow-name"], detail["destination-object"]
                    )
                    destination_details = {"bucket": bucket_name, "key": key}
        else:
            logging.info("Flow information does not exist in Metadata store !")
            
            item = persist_flow_information(detail, flow_table)
            destination_details = item["destination-details"]

    logging.info("[End] - update flow metadata")
    return {
        "data_product_exists": is_data_product_exists,
        "data_product_id": data_product_id,
        "flow-name": flow_name,
        "destination-details": destination_details,
    }


def persist_flow_information(detail, flow_table):
    """
    Prepare the flow object and persists flow object into DynamoDB.

    :return: flow object which has been persisted into DynamoDB
    """
    logging.info("[Start] - persist flow information in DynamoDB")
    bucket_name, key = read_bucket_name_and_key(
        detail["flow-name"], detail["destination-object"]
    )
    item = {
        "flow-name": detail["flow-name"],
        "flow-arn": detail["flow-arn"],
        "source": detail["source"],
        "destination": detail["destination"],
        "source-object": detail["source-object"],
        "destination-details": {"bucket": bucket_name, "key": key},
        "trigger-type": detail["trigger-type"],
        "status": detail["status"],
    }
    flow_table.put_item(Item=item)
    logging.info("[End] - persist flow information in DynamoDB")
    return item


def read_bucket_name_and_key(flow_name, destination_object):
    """
    Extracts the S3 bucket name and key from the flow info contained in the event

    :return: key from destination S3 bucket.If destination S3 bucket does not have a key, then returns empty string
    """
    if "s3://" not in destination_object:
        raise Exception("Destination object is not an S3 URI")
    path_parts = destination_object.replace("s3://", "").split("/")
    bucket = path_parts.pop(0)
    key = "/".join(path_parts)
    key = flow_name if key == "" else f"{key}/{flow_name}"
    return bucket, key
