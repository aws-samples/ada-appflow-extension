import aws_cdk as core
import aws_cdk.assertions as assertions

from ada_appflow_extension.ada_appflow_extension_stack import AdaAppflowExtensionStack


# example tests. To run these tests, uncomment this file along with the example
# resource in ada_appflow_extension/ada_appflow_extension_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = AdaAppflowExtensionStack(app, "ada-appflow-extension")
    template = assertions.Template.from_stack(stack)


#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
