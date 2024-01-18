#!/usr/bin/env python3
from os import getenv

import aws_cdk as cdk
from ada_appflow_extension.ada_appflow_extension_stack import AdaAppflowExtensionStack
from cdk_nag import AwsSolutionsChecks, NagSuppressions, NagPackSuppression

app = cdk.App()
ada_appflow_extension_stack = AdaAppflowExtensionStack(
    app,
    app.node.try_get_context("stack-name"),
    env=cdk.Environment(
        region=getenv("AWS_REGION", getenv("CDK_DEFAULT_REGION")),
        account=getenv("AWS_ACCOUNT_ID", getenv("CDK_DEFAULT_ACCOUNT")),
    ),
    description="AppFlow extension stack for ADA (uksb-xxxx) ",
)

tags = {
    "SolutionName": "ADAAppFlowExtension",
    "SolutionVersion": "v1.0.0",
    "SolutionIaC": "CDK v2",
}

for k, v in tags.items():
    cdk.Tags.of(ada_appflow_extension_stack).add(k, v)

# cdk-nag checks
nag_suppressions = [
    {"id":"AwsSolutions-SMG4", "reason":"ADA api key stored in secrets manager, does not require automatic rotation."},
    {"id":"AwsSolutions-DDB3", "reason":"DynamoDB table is used as metadata store, does not need PITR."},
    {"id":"AwsSolutions-IAM4", "reason":"AWSLambdaBasicExecutionRole is restrictive role."},
    {"id":"AwsSolutions-IAM5", "reason":"S3 permissions are specific to bucket policy only and are required for the solution."}
]
for supression in nag_suppressions:
    NagSuppressions.add_stack_suppressions(ada_appflow_extension_stack, [
        NagPackSuppression(
            id=supression["id"],
            reason=supression["reason"]
        )
    ])
cdk.Aspects.of(app).add(AwsSolutionsChecks(verbose=True))

app.synth()
