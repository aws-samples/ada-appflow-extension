from os import path

from aws_cdk import (
    Fn,
    Stack,
    Duration,
    CfnParameter,
    CustomResource,
    SecretValue,
    BundlingOptions,
    RemovalPolicy,
    aws_lambda as _lambda,
    aws_sns as sns,
    aws_sns_subscriptions as sns_subs,
    aws_logs as logs,
    aws_dynamodb as dynamodb,
    aws_stepfunctions as _aws_stepfunctions,
    aws_stepfunctions_tasks as _aws_stepfunctions_tasks,
    aws_events as events,
    aws_events_targets as events_targets,
    aws_iam as iam,
    aws_secretsmanager as secretsmanager,
    aws_kms as kms,
    custom_resources as cr,
)
from constructs import Construct

LAMBDA_DIR = path.join(path.dirname(path.realpath(__file__)), "..", "lambdas")


class AdaAppflowExtensionStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Parameters

        # ADA API Base URL
        ada_api_base_url = CfnParameter(
            self, "AdaApiBaseUrl", type="String", description="Ada api base url"
        ).value_as_string

        # ADA API Key
        ada_api_key = CfnParameter(
            self,
            "AdaApiKey",
            type="String",
            description="Ada api access key",
            no_echo=True,
        )

        # ADA Account Id
        ada_account_id = CfnParameter(
            self,
            "AdaAccountId",
            type="String",
            description="Ada account id",
        ).value_as_string

        # ADA AppFlow Extension Domain name
        ada_appflow_ext_domain_name = CfnParameter(
            self,
            "AdaAppflowExtDomainName",
            default="ada_appflow_extension_domain",
            min_length=3,
            max_length=255,
            allowed_pattern="^[a-z][a-z_0-9]*$",
        ).value_as_string

        # ADA AppFlow Extension User Group name
        ada_appflow_ext_usergroup_name = CfnParameter(
            self,
            "AdaAppflowExtUserGroupName",
            default="ada_appflow_extension_usergroup",
            min_length=3,
            max_length=100,
            allowed_pattern="^[a-z][a-z_0-9]*$",
        ).value_as_string

        # ADA AppFlow Extension Notification Email
        ada_appflow_ext_notification_email = CfnParameter(
            self,
            "AdaAppflowExtNotificationEmail",
        ).value_as_string

        # SNS AWS KMS key
        sns_aws_key = kms.Key.from_lookup(
            self, 
            'snsAwsKey',
            alias_name='alias/aws/sns'
        )

        # ADA Api access key secret
        ada_api_key_secret = secretsmanager.Secret(
            self,
            "AdaApiKeySecret",
            secret_string_value=SecretValue.unsafe_plain_text(
                ada_api_key.value_as_string
            ),
        )

        # Metadata DDB Table
        flow_metadata_table = dynamodb.Table(
            self,
            "AdaAppFlowExtensionFlowMetadataTable",
            partition_key=dynamodb.Attribute(
                name="flow-name", type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY
        )
        flow_metadata_table_name = flow_metadata_table.table_name

        # Extension Notification topic
        notification_topic = sns.Topic(
            self,
            "AdaAppFlowExtensionNotificationTopic",
            display_name="ADA AppFlow Extension Notification",
            master_key=sns_aws_key
        )
        notification_topic.add_subscription(sns_subs.EmailSubscription(email_address=ada_appflow_ext_notification_email))


        # Lambda handler definitions

        # update-flow-metadata lambda
        update_flow_metadata_function = _lambda.Function(
            self,
            "updateFlowMetadataFunction",
            description="Update flow metadata function",
            handler="lambda_function.lambda_handler",
            runtime=_lambda.Runtime.PYTHON_3_11,
            timeout=Duration.seconds(300),
            code=_lambda.Code.from_asset(path.join(LAMBDA_DIR, "update_flow_metadata")),
            environment={
                "FLOW_METADATA_TABLE_NAME": flow_metadata_table_name,
                "ADA_DOMAIN_NAME": ada_appflow_ext_domain_name,
            },
        )

        # create_ada_dataproduct lambda        
        create_ada_dataproduct_function = _lambda.Function(
            self,
            "createAdaDataProductFunction",
            description="Create Ada data product function",
            handler="lambda_function.lambda_handler",
            runtime=_lambda.Runtime.PYTHON_3_11,
            timeout=Duration.seconds(300),
            code=_lambda.Code.from_asset(
                path.join(LAMBDA_DIR, "create_ada_dataproduct"),
                bundling=BundlingOptions(
                    image=_lambda.Runtime.PYTHON_3_11.bundling_image,
                    command=[
                        "bash",
                        "-c",
                        "pip install --no-cache -r requirements.txt -t /asset-output && cp -au . /asset-output",
                    ],
                ),
            ),
            environment={
                "ADA_API_BASE_URL": ada_api_base_url,
                "ADA_API_KEY_SECRET_NAME": ada_api_key_secret.secret_name,
                "ADA_ACCOUNT_ID": ada_account_id,
                "FLOW_METADATA_TABLE_NAME": flow_metadata_table_name,
                "ADA_DOMAIN_NAME": ada_appflow_ext_domain_name,
                "ADA_USER_GROUP_NAME": ada_appflow_ext_usergroup_name,
            },
            log_retention=logs.RetentionDays.ONE_YEAR,
        )

        create_ada_dataproduct_function.add_to_role_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["s3:ListAllMyBuckets", "s3:GetBucketPolicy", "s3:PutBucketPolicy"],
                resources=["*"]
           )
        )
        
        # trigger_ada_data_update lambda
        trigger_ada_data_update_function = _lambda.Function(
            self,
            "triggerAdaDataUpdateFunction",
            description="Trigger Ada data update function",
            handler="lambda_function.lambda_handler",
            runtime=_lambda.Runtime.PYTHON_3_11,
            timeout=Duration.seconds(300),
            code=_lambda.Code.from_asset(
                path.join(LAMBDA_DIR, "trigger_ada_data_update"),
                bundling=BundlingOptions(
                    image=_lambda.Runtime.PYTHON_3_11.bundling_image,
                    command=[
                        "bash",
                        "-c",
                        "pip install --no-cache -r requirements.txt -t /asset-output && cp -au . /asset-output",
                    ],
                ),
            ),
            environment={
                "ADA_API_BASE_URL": ada_api_base_url,
                "ADA_API_KEY_SECRET_NAME": ada_api_key_secret.secret_name,
                "FLOW_METADATA_TABLE_NAME": flow_metadata_table_name,
                "ADA_DOMAIN_NAME": ada_appflow_ext_domain_name,
                "ADA_USER_GROUP_NAME": ada_appflow_ext_usergroup_name,
            },
            log_retention=logs.RetentionDays.ONE_YEAR,
        )

        # notify_user lambda
        notify_user_function = _lambda.Function(
            self,
            "notifyUserFunction",
            handler="lambda_function.lambda_handler",
            description="Notify user function",
            runtime=_lambda.Runtime.PYTHON_3_11,
            timeout=Duration.seconds(300),
            code=_lambda.Code.from_asset(path.join(LAMBDA_DIR, "notify_user")),
            environment={
                "FLOW_METADATA_TABLE_NAME": flow_metadata_table_name,
                "ADA_DOMAIN_NAME": ada_appflow_ext_domain_name,
                "ADA_USER_GROUP_NAME": ada_appflow_ext_usergroup_name,
                "NOTIFICATION_TOPIC_ARN": notification_topic.topic_arn
            },
            log_retention=logs.RetentionDays.ONE_YEAR,
        )

        # notification function permission for sns
        notification_topic.grant_publish(notify_user_function)

        # lambda permissions for ddb r/w
        for fn in (
            update_flow_metadata_function,
            create_ada_dataproduct_function,
            trigger_ada_data_update_function,
            notify_user_function,
        ):
            flow_metadata_table.grant_read_write_data(fn)

        # lambda permissions for secret read
        for fn in create_ada_dataproduct_function, trigger_ada_data_update_function:
            ada_api_key_secret.grant_read(fn)

        # step function steps definition

        # update-flow-metadata step
        update_flow_metadata_step = _aws_stepfunctions_tasks.LambdaInvoke(
            self,
            "updateFlowMetadataStep",
            lambda_function=update_flow_metadata_function,
            output_path="$.Payload",
        )

        # create-ada-dataproduct step
        create_ada_dataproduct_step = _aws_stepfunctions_tasks.LambdaInvoke(
            self,
            "createAdaDataProductStep",
            lambda_function=create_ada_dataproduct_function,
            output_path="$.Payload",
        )

        # trigger-ada-data-product step
        trigger_ada_data_update_step = _aws_stepfunctions_tasks.LambdaInvoke(
            self,
            "triggerAdaDataUpdateStep",
            lambda_function=trigger_ada_data_update_function,
            output_path="$.Payload",
        )

        # notify-user step
        notify_user_step = _aws_stepfunctions_tasks.LambdaInvoke(
            self,
            "notifyUserStep",
            lambda_function=notify_user_function,
            output_path="$.Payload",
        )

        # succeed step
        succeed_step = _aws_stepfunctions.Succeed(
            self, "succeed", comment="Extension flow succeeded"
        )

        # failed step
        failed_step = _aws_stepfunctions.Fail(
            self, "failed", comment="Extension flow failed"
        )

        # step function chain
        chain = update_flow_metadata_step.next(
            _aws_stepfunctions.Choice(self, "dataProductExists?")
            .when(
                _aws_stepfunctions.Condition.boolean_equals(
                    "$.data_product_exists", False
                ),
                create_ada_dataproduct_step.next(notify_user_step),
            )
            .when(
                _aws_stepfunctions.Condition.boolean_equals(
                    "$.data_product_exists", True
                ),
                trigger_ada_data_update_step.next(notify_user_step.next(succeed_step)),
            )
            .otherwise(failed_step)
        )

        # step function log group
        sm_log_group = logs.LogGroup(
            self,
            "AdaAppFlowExtensionStateMachineLogGroup",
            log_group_name=f'/aws/vendedlogs/states/AdaAppFlowExtSmLogGroup-{Fn.select(4, Fn.split("-", Fn.select(2, Fn.split("/", self.stack_id))))}',
            retention=logs.RetentionDays.ONE_YEAR,
        )

        # step function state machine
        state_machine = _aws_stepfunctions.StateMachine(
            self,
            "AdaAppFlowExtensionStateMachine",
            definition_body=_aws_stepfunctions.DefinitionBody.from_chainable(chain),
            logs=_aws_stepfunctions.LogOptions(
                destination=sm_log_group, level=_aws_stepfunctions.LogLevel.ALL
            ),
            tracing_enabled=True,
        )

        # existing-flow-handler custom-resource lambda
        existing_flow_handler_cr_function = _lambda.Function(
            self,
            "existingFlowHandlerCrFunction",
            description="Existing flow handler custom resource function",
            handler="lambda_function.lambda_handler",
            runtime=_lambda.Runtime.PYTHON_3_11,
            timeout=Duration.seconds(300),
            code=_lambda.Code.from_asset(
                path.join(LAMBDA_DIR, "existing_flow_handler_cr"),
                bundling=BundlingOptions(
                    image=_lambda.Runtime.PYTHON_3_11.bundling_image,
                    command=[
                        "bash",
                        "-c",
                        "pip install --no-cache -r requirements.txt -t /asset-output && cp -au . /asset-output",
                    ],
                ),
            ),
            environment={
                "ADA_API_BASE_URL": ada_api_base_url,
                "ADA_API_KEY_SECRET_NAME": ada_api_key_secret.secret_name,
                "ADA_DOMAIN_NAME": ada_appflow_ext_domain_name,
                "ADA_USER_GROUP_NAME": ada_appflow_ext_usergroup_name,
                "STATE_MACHINE_ARN": state_machine.state_machine_arn,
            },
            log_retention=logs.RetentionDays.ONE_YEAR,
        )

        # lambda permissions for secret read
        ada_api_key_secret.grant_read(existing_flow_handler_cr_function)

        # allow appflow access iam policy
        existing_flow_handler_cr_function.add_to_role_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["appflow:ListFlows", "appflow:DescribeFlow"],
                resources=["*"],
            )
        )

        # allow triggering state machine
        existing_flow_handler_cr_function.add_to_role_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["states:StartExecution"],
                resources=[state_machine.state_machine_arn],
            )
        )

        # existing-flow-handler custom-resource  provider
        existing_flow_handler_cr_provider = cr.Provider(
            self,
            "existingFlowHandlerCrProvider",
            on_event_handler=existing_flow_handler_cr_function,
        )

        existing_flow_handler_cr = CustomResource(
            self,
            "existingFlowHandlerCr",
            service_token=existing_flow_handler_cr_provider.service_token,
        )
        existing_flow_handler_cr.node.add_dependency(state_machine)

        # event rules

        # AppFlow flow run report rule: Flow with s3 destination ended successfully
        flow_run_report_rule = events.Rule(
            self,
            "FlowRunReportRule",
            event_pattern=events.EventPattern(
                source=["aws.appflow"],
                detail_type=["AppFlow End Flow Run Report"],
                detail={"destination": ["S3"], "status": ["Execution Successful"]},
            ),
        )

        # rule target
        flow_run_report_rule.add_target(events_targets.SfnStateMachine(state_machine))
