<h1 align="center">Panther Analysis Tool</h1>

<p align="center">
  <i>Command Line Panther Analysis Management</i>
</p>

<p align="center">
  <a href="https://docs.runpanther.io">Documentation</a> |
  <a href="https://docs.runpanther.io/quick-start">Quick Start</a>
</p>

<p align="center">
  <a href="https://gitter.im/runpanther/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge"><img src="https://badges.gitter.im/runpanther/community.svg" alt="Gitter"/></a>
  <a href="https://circleci.com/gh/panther-labs/panther-analysis"><img src="https://circleci.com/gh/panther-labs/panther-analysis.svg?style=svg" alt="CircleCI"/></a>
  <a href="https://cla-assistant.io/panther-labs/panther-analysis" alt="CLA Assistant"><img src="https://cla-assistant.io/readme/badge/panther-labs/panther-analysis"/></a>
</p>

---

This repository contains a CLI tool for testing and packaging Panther policies and rules.

See the [Panther documentation](https://docs.runpanther.io/quick-start) for more details on Panther.

## Panther Analysis Tool

`panther-cli` is a Python command line interface for testing, packaging, and deploying Panther Policies and Rules. This enables policies and rules to be managed in code and tracked via version control systems such as git or svn. This is also useful for devops and security personnel who prefer CLI management and configuration over web interfaces.

### Installation

Setup your environment:

```bash
$ make install
$ make venv
$ source venv/bin/activate
$ pipenv run -- make deps
```

Use the [pip](https://pip.pypa.io/en/stable/) package manager (locally for now) to install `panther-cli`.

```bash
$ pipenv run -- pip3 install -e .
```

If you want to use the `panther-cli` tool outside of the virtual environment, install it to the host directly.

```bash
$ make deps
$ pip3 install -e .
```

### Commands and Usage

It is important to note that wherever the `panther-cli` refers to policies, it is actually referring to both policies and rules. So the `--policies` flag can be passed either a directory of policies, rules, or both.

View available commands:

```bash
$ panther-cli --help
usage: panther_cli [-h] [--version] {test,zip,upload} ...

Panther CLI: A tool for writing, testing, and packaging Panther Policies/Rules

positional arguments:
  {test,zip,upload}
    test             Validate policy specifications and run policy tests.
    zip              Create an archive of local policies for uploading to
                     Panther.
    upload           Upload specified policies to a Panther deployment.

optional arguments:
  -h, --help         show this help message and exit
  --version          show program's version number and exit
```

Run tests:

```bash
$ panther-cli test --policies tests/fixtures/valid_policies/

[INFO]: Testing Policies in tests/fixtures/valid_policies/

Testing policy 'AWS.IAM.MFAEnabled'
	[PASS] Root MFA not enabled fails compliance
	[PASS] User MFA not enabled fails compliance
```

Create packages to upload via the Panther UI:

```bash
$ panther-cli zip --policies tests/fixtures/valid_policies/ --output-path tmp

[INFO]: Testing Policies in tests/fixtures/valid_policies/

Testing policy 'AWS.IAM.MFAEnabled'
	[PASS] Root MFA not enabled fails compliance
	[PASS] User MFA not enabled fails compliance

[INFO]: Zipping policies in tests/fixtures/valid_policies/ to tmp
[INFO]: /Users/user_name/panther-cli/tmp/panther-policies-2019-01-01T16-00-00.zip
```

Upload packages to Panther directly. Note, this expects your environment to be setup the same way as if you were using the AWS CLI, see the setup instructions [here](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html). We also recommend using a credentials manager such as [aws-vault](https://github.com/99designs/aws-vault).

```bash
$ panther-cli upload --policies tests/fixtures/valid_policies/ --output-path tmp

[INFO]: Testing Policies in tests/fixtures/valid_policies/

AWS.IAM.MFAEnabled
	[PASS] Root MFA not enabled fails compliance
	[PASS] User MFA not enabled fails compliance

AWS.IAM.BetaTest
	[PASS] Root MFA not enabled fails compliance
	[PASS] User MFA not enabled fails compliance

AWS.CloudTrail.MFAEnabled
	[PASS] Root MFA not enabled fails compliance
	[PASS] User MFA not enabled fails compliance

[INFO]: Zipping policies in tests/fixtures/valid_policies/ to tmp
[INFO]: Found credentials in environment variables.
[INFO]: Uploading pack to Panther
[INFO]: Upload success.
[INFO]: API Response:
{
  "modifiedPolicies": 0,
  "modifiedRules": 0,
  "newPolicies": 2,
  "newRules": 1,
  "totalPolicies": 2,
  "totalRules": 1
}
```

In order to upload all currently available policies and rules to your Panther deployment, run the following command. This command will recursively traverse all directories under `analysis` and package all rules and policies it finds into one package and then upload them:

```bash
$ panther-cli upload --policies analysis/ --output-path tmp
```

## Writing Policies

Each Panther Policy consists of a Python body and a YAML or JSON specification file.

In the Python body, returning a value of `True` indicates the resource being evaluated is compliant. Returning a value of `False` indicates the resource is non-compliant, and an alert may be sent or an auto-remediation may be performed as a result.

The specification file defines the attributes of the Policy. This includes settings such as `Enabled`, `Severity`, and `ResourceTypes`, as well as metadata such as `DisplayName`, `Tags`, and `Runbook`. See the [Writing Local Policies](https://docs.runpanther.io/policies/writing-local) documentation for more details on what fields may be present, and how they are configured.

`example_policy.py`
```python
def policy(resource):
  return True
```

`example_policy.yml`
```yaml
AnalysisType: policy
Enabled: true
Filename: example_policy.py
PolicyID: Example.Policy.01
ResourceTypes:
  - Resource.Type.Here
Severity: Low
DisplayName: Example Policy to Check the Format of the Spec
Tags:
  - Tags
  - Go
  - Here
Runbook: Find out who changed the spec format.
Reference: https://www.link-to-info.io
Tests:
  -
    Name: Name to describe our first test.
    Schema: Resource.Type.Here
    ExpectedResult: true/false
    Resource:
      Key: Values
      For: Our Resource
      Based: On the Schema
```

The requirements for the Policy body and specification files are listed below.

The Python body MUST:
  - Be valid Python3
  - Define a function `policy` that accepts one argument
  - Return a `bool` from the `policy` function

The Python body SHOULD:
  - Name the argument to the `policy` function `resource`

The Python body MAY:
  - Import standard Python3 libraries
  - Define additional helper functions as needed
  - Define variables and classes outside the scope of the `policy` function

The specification file MUST:
  - Be valid JSON/YAML
  - Define an `AnalysisType` field with the value `policy`
  - Define the additional following fields:
    - Enabled
    - FileName
    - PolicyID
    - ResourceTypes
    - Severity


## Writing Rules

Rules are very similar to Policies, and require a similar Python body and JSON or YAML specification file as Policies require.

One very important distinction between Policies and Rules is the meaning of the return value. For Rules, returning a value of `False` indicates that the event being evaluated should not be alerted on. Returning a value of `True` indicates that the event is suspicious, and an alert may be sent or an auto-remediation may be performed as a result.

`example_rule.py`
```python
def rule(event):
  return False
```

`example_rule.yml`
```yaml
AnalysisType: rule
Enabled: true
Filename: example_rule.py
PolicyID: Example.Rule.01
ResourceTypes:
  - Log.Type.Here
Severity: Low
DisplayName: Example Rule to Check the Format of the Spec
Tags:
  - Tags
  - Go
  - Here
Runbook: Find out who changed the spec format.
Reference: https://www.link-to-info.io
Tests:
  -
    Name: Name to describe our first test.
    ResourceType: Log.Type.Here
    ExpectedResult: true/false
    Resource:
      Key: Values
      For: Our Log
      Based: On the Schema
```

The requirements for the Rule body and specification files are listed below.

The Python body MUST:
  - Be valid Python3
  - Define a function `rule` that accepts one argument
  - Return a `bool` from the `rule` function

The Python body SHOULD:
  - Name the argument to the `rule` function `event`

The Python body MAY:
  - Import standard Python3 libraries
  - Define additional helper functions as needed
  - Define variables and classes outside the scope of the `rule` function

The specification file MUST:
  - Be valid JSON/YAML
  - Define an `AnalysisType` field with the value `rule`
  - Define the additional following fields:
    - Enabled
    - FileName
    - PolicyID
    - ResourceTypes
    - Severity

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## Contributing

We welcome all contributions! Please read the [contributing guidelines](https://github.com/panther-labs/panther-analysis/blob/master/CONTRIBUTING.md) before submitting pull requests.

## License

This repository is licensed under the Apache-2.0 [license](https://github.com/panther-labs/panther-analysis/blob/master/LICENSE).
