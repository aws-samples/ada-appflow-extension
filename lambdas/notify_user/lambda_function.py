import json
from os import getenv

import boto3
import logging

ADA_NOTIFICATION_TOPIC_ARN = getenv("NOTIFICATION_TOPIC_ARN")

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns_client = boto3.client("sns")

def lambda_handler(event, context):
    """
    Publish message to SNS topic for email notification.

    :param event: Output event from ADA data product create/update trigger step.
    :return: Publish call response.
    
    """
    logger.debug(f"Event: {event}")
    try:
        info_text = f"""Data Product Id: {event['body']['data-product-id']}
        AppFlow Flow Name: {event['body']['flow-name']}\n
        Check ADA console for data product details.
        """

        if event["body"]["request-type"] == "create-data-product":
            subject = "[ADA AppFlow Extension]Data product creation failed!"
            message = f"Failed to create data product for an AppFlow flow."

            if event["statusCode"] == 200:
                message = f"Successfully created data product for an AppFlow flow. Please find the details below:\n{info_text}"
                subject = "[ADA AppFlow Extension]Data product creation success!"

        elif event["body"]["request-type"] == "trigger-data-update":
            subject = "[ADA AppFlow Extension]Data product data-update failed!"
            message = f"Failed to trigger data product data-update for an AppFlow flow run."
            
            if event["statusCode"] == 200:
                if event["body"]["trigger-data-update"] == "SKIPPED":
                    message = f"Skipped data product data-update for an AppFlow flow run as data-product is not in READY state. Please find the details below:\n{info_text}"
                    subject = "[ADA AppFlow Extension]Data product data-update skipped!"
                else:
                    message = f"Successfully triggered data product data-update for an AppFlow flow run. Please find the details below:\n{info_text}"
                    subject = "[ADA AppFlow Extension]Data product data-update success!"
        else:
            logger.error(
                f"Invalid request type: {event['body']['request-type']}"
            )
            return {
                "statusCode": 400, 
                "body": "Invalid request type."    
            }
        response = sns_client.publish(
            TopicArn = ADA_NOTIFICATION_TOPIC_ARN,
            Message = message,
            Subject = subject
        )
    except KeyError as keyerr:
        logger.error(
            f"Missing data product info. KeyError: {keyerr}"
        )
        return {
            "statusCode": 400, 
            "error": f"[KeyError]Missing key: {str(keyerr)}"
    }
    except Exception as e:
        logger.error(
            f"Failed to publish message to SNS topic. Error: {e}"
        )

    return {
        "statusCode": 200, 
        "body": response
    }
