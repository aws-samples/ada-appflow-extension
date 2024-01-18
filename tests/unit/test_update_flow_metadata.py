import os

import boto3
import moto
import pytest

from lambdas.update_flow_metadata import lambda_function

TABLE_NAME = "flow_info_mock"


@pytest.fixture
def lambda_environment():
    os.environ["FLOW_METADATA_TABLE_NAME"] = TABLE_NAME


@pytest.fixture
def sample_flow_run_complete_event():
    return {
        "version": "0",
        "id": "febf499e-03d1-4878-8ef8-6cc73fa7fdty",
        "detail-type": "AppFlow End Flow Run Report",
        "source": "aws.appflow",
        "account": "1234567890xx",
        "time": "2023-08-29T12:55:32Z",
        "region": "eu-west-1",
        "resources": ["bd3275d267f032646f926d73a98d12c2"],
        "detail": {
            "flow-name": "test",
            "created-by": "arn:aws:sts::123456789:assumed-role/ABC/ABC-ROLE",
            "flow-arn": "arn:aws:appflow:eu-west-1:1234567890xx:flow/test",
            "source": "S3",
            "destination": "S3",
            "source-object": "s3://appflow-input-test-bucket/input",
            "destination-object": "s3://appflow-output-test-bucket/input",
            "trigger-type": "ONDEMAND",
            "num-of-records-processed": "63000",
            "execution-id": "2c07e424-21e4-4ee3-b70f-4fb55b2ecf79",
            "num-of-records-filtered": "0",
            "start-time": "2023-08-29T12:55:23.835Z[UTC]",
            "num-of-documents-processed": "0",
            "end-time": "2023-08-29T12:55:32.049Z[UTC]",
            "num-of-record-failures": "0",
            "data-processed": "10226699",
            "status": "Execution Successful",
        },
    }


@pytest.fixture
def metadata_table():
    with moto.mock_dynamodb():
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.create_table(
            TableName=TABLE_NAME,
            AttributeDefinitions=[{"AttributeName": "flow-name", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "flow-name", "KeyType": "HASH"}],
            ProvisionedThroughput={"ReadCapacityUnits": 10, "WriteCapacityUnits": 10},
        )
        table.wait_until_exists()
        yield TABLE_NAME


@pytest.fixture
def metadata_table_with_data_product_exists(metadata_table):
    table = boto3.resource("dynamodb").Table(metadata_table)
    sample_item_with_data_product = {
        "flow-name": "test",
        "flow-arn": "arn:aws:appflow:eu-west-1:1234567890xx:flow/test",
        "source": "S3",
        "destination": "S3",
        "source-object": "s3://appflow-input-test-bucket/input",
        "destination-details": {
            "bucket": "appflow-output-test-bucket",
            "key": "input-key",
        },
        "trigger-type": "ONDEMAND",
        "start-time": "2023-08-29T12:55:23.835Z[UTC]",
        "end-time": "2023-08-29T12:55:32.049Z[UTC]",
        "status": "Execution Successful",
        "data-product-info": {
            "id": "12345",
            "created-time": "",
            "updated-time": "",
            "domain-id": "ABCD",
        },
    }
    table.put_item(Item=sample_item_with_data_product)


# Test 1 - testing a valid S3 URI with bucket name and key
def test_read_bucket_name_and_key_with_key():
    flow_name = "Test"
    destination_object = "s3://appflow-output-test-bucket/dummy-key"
    bucket_name, key = lambda_function.read_bucket_name_and_key(
        flow_name, destination_object
    )
    assert bucket_name == "appflow-output-test-bucket"
    assert key == "dummy-key/Test"


# Test 2 - testing a valid S3 URI with bucket name and no key present
def test_read_bucket_name_and_key_without_key():
    flow_name = "Test"
    destination_object = "s3://appflow-output-test-bucket"
    bucket_name, key = lambda_function.read_bucket_name_and_key(
        flow_name, destination_object
    )
    assert bucket_name == "appflow-output-test-bucket"
    assert key == flow_name


# Test 3 - testing a valid S3 URI with bucket name and key being multiple folders
def test_read_bucket_name_and_key_with_multi_folder_key():
    flow_name = "Test"
    destination_object = (
        "s3://appflow-output-test-bucket/dummy-folder-1/dummy-folder-2/dummy-folder-3"
    )
    bucket_name, key = lambda_function.read_bucket_name_and_key(
        flow_name, destination_object
    )
    assert bucket_name == "appflow-output-test-bucket"
    assert key == "dummy-folder-1/dummy-folder-2/dummy-folder-3/Test"


# Test 4 - testing an invalid URI not being an S3 URI
def test_read_bucket_name_and_key_with_invalid_s3_uri():
    flow_name = "Test"
    destination_object = "invalid-s3-uri"
    with pytest.raises(Exception):
        lambda_function.read_bucket_name_and_key(flow_name, destination_object)


# Test 5 - testing the lambda function with a sample event, where flow does not exist
def test_update_flow_metadata_with_no_flow_exists(
    lambda_environment, sample_flow_run_complete_event, metadata_table
):
    response = lambda_function.update_flow_metadata(sample_flow_run_complete_event)
    assert response["data_product_exists"] is False
    assert response["data_product_id"] is None


# Test 6 - testing the lambda function with a sample event, where flow already exists with associated data product
def test_update_flow_metadata_with_flow_and_data_product_exists(
    lambda_environment,
    sample_flow_run_complete_event,
    metadata_table_with_data_product_exists,
):
    response = lambda_function.update_flow_metadata(sample_flow_run_complete_event)
    assert response["data_product_exists"] is True
    assert response["data_product_id"] == "12345"
