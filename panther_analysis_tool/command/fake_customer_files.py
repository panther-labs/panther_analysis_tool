BASE_YAML = """
AnalysisType: rule
Filename: aws_add_malicious_lambda_extension.py
RuleID: "AWS.Lambda.UpdateFunctionConfiguration"
DisplayName: "Lambda Update Function Configuration with Layers"
Enabled: false
LogTypes:
  - AWS.CloudTrail
Reports:
  MITRE ATT&CK:
    - TA0007:T1078
Severity: Info
Tags:
  - Beta
CreateAlert: false
Description: >
  Identifies when a Lambda function configuration is updated with layers, which could indicate a potential security risk.
Runbook: Make sure that the Lambda function configuration update is expected and authorized. If not, investigate the event further.
Reference: https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.lambda-layer-extension/
Tests:
  - Name: Lambda Update Function Configuration with Layers
    ExpectedResult: true
    Log:
      {
        "eventVersion": "1.05",
        "userIdentity": {
          "type": "AssumedRole",
          "principalId": "tester",
          "arn": "arn:aws:sts::123456789012:assumed-role/tester",
          "accountId": "123456789012",
          "accessKeyId": "1",
          "sessionContext": {
            "sessionIssuer": {
              "type": "Role",
              "principalId": "1111",
              "arn": "arn:aws:iam::123456789012:role/tester",
              "accountId": "123456789012",
              "userName": "Tester"
            },
            "webIdFederationData": {},
            "attributes": {
              "mfaAuthenticated": "true",
              "creationDate": "2019-01-01T00:00:00Z"
            }
          }
        },
        "eventTime": "2019-01-01T00:00:00Z",
        "eventSource": "lambda.amazonaws.com",
        "eventName": "UpdateFunctionConfiguration20150331v2",
        "awsRegion": "us-west-2",
        "sourceIPAddress": "111.111.111.111",
        "userAgent": "console.amazonaws.com",
        "requestParameters": {
          "functionName": "my-lambda-function"
        },
        "responseElements": {
          "layers": [
            {
              "arn": "arn:aws:lambda:us-west-2:123456789012:layer:my-layer:1"
            }
          ]
        },
        "requestID": "1",
        "eventID": "1",
        "readOnly": false,
        "eventType": "AwsApiCall",
        "recipientAccountId": "123456789012",
        "p_log_type": "AWS.CloudTrail"
      }
  - Name: Lambda Update Function Configuration without Layers
    ExpectedResult: false
    Log:
      {
        "eventVersion": "1.05",
        "userIdentity": {
          "type": "AssumedRole",
          "principalId": "tester",
          "arn": "arn:aws:sts::123456789012:assumed-role/tester",
          "accountId": "123456789012",
          "accessKeyId": "1",
          "sessionContext": {
            "sessionIssuer": {
              "type": "Role",
              "principalId": "1111",
              "arn": "arn:aws:iam::123456789012:role/tester",
              "accountId": "123456789012",
              "userName": "Tester"
            },
            "webIdFederationData": {},
            "attributes": {
              "mfaAuthenticated": "true",
              "creationDate": "2019-01-01T00:00:00Z"
            }
          }
        },
        "eventTime": "2019-01-01T00:00:00Z",
        "eventSource": "lambda.amazonaws.com",
        "eventName": "UpdateFunctionConfiguration20150331v2",
        "awsRegion": "us-west-2",
        "sourceIPAddress": "111.111.111.111",
        "userAgent": "console.amazonaws.com",
        "requestParameters": {
          "functionName": "my-lambda-function"
        },
        "responseElements": {},
        "requestID": "1",
        "eventID": "1",
        "readOnly": false,
        "eventType": "AwsApiCall",
        "recipientAccountId": "123456789012",
        "p_log_type": "AWS.CloudTrail"
      }
"""

PANTHER_YAML = """
Filename: aws_add_malicious_lambda_extension.py
RuleID: "AWS.Lambda.UpdateFunctionConfiguration"

Enabled: false
AnalysisType: rule
LogTypes:
  - AWS.CloudTrail
Reports:
  MITRE ATT&CK:
    - TA0007:T1078
Severity: Info
DisplayName: "DESC: Lambda Update Function Configuration with Layers"
Tags:
  - BetaAAAAAAA
CreateAlert: false
Description: >
  Identifies when a Lambda function configuration is updated with layers, which could indicate a potential security risk.
Runbook: Make sure that the Lambda function configuration update is expected and authorized. If not, investigate the event further.
Reference: https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.lambda-layer-extension/
Tests:
  - Name: Lambda Update Function Configuration with Layers
    ExpectedResult: true
    Log:
      {
        "eventVersion": "1.05",
        "userIdentity": {
          "type": "AssumedRole",
          "principalId": "tester",
          "arn": "arn:aws:sts::123456789012:assumed-role/tester",
          "accountId": "123456789012",
          "accessKeyId": "1",
          "sessionContext": {
            "sessionIssuer": {
              "type": "Role",
              "principalId": "1111",
              "arn": "arn:aws:iam::123456789012:role/tester",
              "accountId": "123456789012",
              "userName": "Tester"
            },
            "webIdFederationData": {},
            "attributes": {
              "mfaAuthenticated": "true",
              "creationDate": "2019-01-01T00:00:00Z"
            }
          }
        },
        "eventTime": "2019-01-01T00:00:00Z",
        "eventSource": "lambda.amazonaws.com",
        "eventName": "UpdateFunctionConfiguration20150331v2",
        "awsRegion": "us-west-2",
        "sourceIPAddress": "111.111.111.111",
        "userAgent": "console.amazonaws.com",
        "requestParameters": {
          "functionName": "my-lambda-function"
        },
        "responseElements": {
          "layers": [
            {
              "arn": "arn:aws:lambda:us-west-2:123456789012:layer:my-layer:1"
            }
          ]
        },
        "requestID": "1",
        "eventID": "1",
        "readOnly": false,
        "eventType": "AwsApiCall",
        "recipientAccountId": "123456789012",
        "p_log_type": "AWS.CloudTrail"
      }
  - Name: Lambda Update Function Configuration without Layers
    ExpectedResult: false
    Log:
      {
        "eventVersion": "1.05",
        "userIdentity": {
          "type": "AssumedRole",
          "principalId": "tester",
          "arn": "arn:aws:sts::123456789012:assumed-role/tester",
          "accountId": "123456789012",
          "accessKeyId": "1",
          "sessionContext": {
            "sessionIssuer": {
              "type": "Role",
              "principalId": "1111",
              "arn": "arn:aws:iam::123456789012:role/tester",
              "accountId": "123456789012",
              "userName": "Tester"
            },
            "webIdFederationData": {},
            "attributes": {
              "mfaAuthenticated": "true",
              "creationDate": "2019-01-01T00:00:00Z"
            }
          }
        },
        "eventTime": "2019-01-01T00:00:00Z",
        "eventSource": "lambda.amazonaws.com",
        "eventName": "UpdateFunctionConfiguration20150331v2",
        "awsRegion": "us-west-2",
        "sourceIPAddress": "111.111.111.111",
        "userAgent": "console.amazonaws.com",
        "requestParameters": {
          "functionName": "my-lambda-function"
        },
        "responseElements": {},
        "requestID": "1",
        "eventID": "1",
        "readOnly": false,
        "eventType": "AwsApiCall",
        "recipientAccountId": "123456789012",
        "p_log_type": "AWS.CloudTrail"
      }
other: panther
"""

PANTHER_PYTHON = """
from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):
    if (
        aws_cloudtrail_success(event)
        and event.get("eventSource") == "lambda.amazonaws.com"
        and event.get("eventName") == "UpdateFunctionConfiguration20150331v2"
        and event.deep_get("responseElements", "layers")
    ):
        return True
    return False


def title(event):
    lambda_name = event.deep_get(
        "responseElements", "functionName", default="LAMBDA_NAME_NOT_FOUND"
    )
    return (
        f"[AWS.CloudTrail] User [{event.udm('actor_user')}] "
        f"updated Lambda function configuration with layers for [{lambda_name}]"
    )


def alert_context(event):
    return aws_rule_context(event)

"""

CUSTOMER_YAML = """
RuleID: "AWS.Lambda.UpdateFunctionConfiguration" # rule id comment
AnalysisType: rule # analysis type comment
Filename: aws_add_malicious_lambda_extension.py
DisplayName: "Lambda Update Function Configuration with Layers WITH MORE"
Enabled: true # enabled comment
# log types comment above
LogTypes:
  - AWS.CloudTrail
Reports:
  MITRE ATT&CK:
    - TA0007:T1078
Severity: Info
Tags:
  - BetaBBB
  - New
CreateAlert: false
Description: >
  Identifies when a Lambda function configuration is updated with layers, which could indicate a potential security risk.
Runbook: Make sure that the Lambda function configuration update is expected and authorized. If not, investigate the event further.
Reference: https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.lambda-layer-extension/
Tests:
  - Name: Lambda Update Function Configuration without Layers
    ExpectedResult: false
    Log:
      {
        "eventVersion": "1.05",
        "userIdentity": {
          "type": "AssumedRole",
          "principalId": "tester",
          "arn": "arn:aws:sts::123456789012:assumed-role/tester",
          "accountId": "123456789012",
          "accessKeyId": "1",
          "sessionContext": {
            "sessionIssuer": {
              "type": "Role",
              "principalId": "1111",
              "arn": "arn:aws:iam::123456789012:role/tester",
              "accountId": "123456789012",
              "userName": "Tester"
            },
            "webIdFederationData": {},
            "attributes": {
              "mfaAuthenticated": "true",
              "creationDate": "2019-01-01T00:00:00Z"
            }
          }
        },
        "eventTime": "2019-01-01T00:00:00Z",
        "eventSource": "lambda.amazonaws.com",
        "eventName": "UpdateFunctionConfiguration20150331v2",
        "awsRegion": "us-west-2",
        "sourceIPAddress": "111.111.111.111",
        "userAgent": "console.amazonaws.com",
        "requestParameters": {
          "functionName": "my-lambda-function"
        },
        "responseElements": {},
        "requestID": "1",
        "eventID": "1",
        "readOnly": false,
        "eventType": "AwsApiCall",
        "recipientAccountId": "123456789012",
        "p_log_type": "AWS.CloudTrail"
      }
other: your
"""

CUSTOMER_PYTHON = """
from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):
    if (
        aws_cloudtrail_success(event)
        and event.get("eventSource") == "lambda.amazonaws.com"
        and event.get("eventName") == "UpdateFunctionConfiguration20150331v2"
        and event.deep_get("responseElements", "layers")
    ):
        return True
    return False


def title(event):
    lambda_name = event.deep_get(
        "responseElements", "functionName", default="LAMBDA_NAME_NOT_FOUND"
    )
    return (
        f"[AWS.CloudTrail] User [{event.udm('actor_user')}] "
        f"updated Lambda function configuration with layers for [{lambda_name}]"
    )


def alert_context(event):
    return aws_rule_context(event)

"""
