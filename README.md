<h1 align="center">Panther Analysis Tool</h1>

<p align="center">
  <i>Command Line Panther Analysis Management</i>
</p>

<p align="center">
  <a href="https://docs.runpanther.io">Documentation</a> |
  <a href="https://docs.runpanther.io/quick-start">Quick Start</a>
</p>

<p align="center">
  <a href="https://slack.runpanther.io/">Chat with us on Slack!</a>
  <a href="https://circleci.com/gh/panther-labs/panther_analysis_tool"><img src="https://circleci.com/gh/panther-labs/panther_analysis_tool.svg?style=svg" alt="CircleCI"/></a>
</p>

---

`panther_analysis_tool` is a Python CLI for testing, packaging, and deploying Panther Detections defined in code. See the [Panther documentation](https://docs.runpanther.io/quick-start) for more details on Panther.

# Installation

Install simply with pip:

```bash
$ pip3 install panther_analysis_tool
```

## Build From Source

If you'd prefer instead to run from source for development reasons, first setup your environment:

```bash
$ make install
$ make venv
$ source venv/bin/activate
$ pipenv run -- make deps
$ pipenv run -- pip3 install -e .
```

If you would rather use the `panther_analysis_tool` outside of the virtual environment, install it  directly:

```bash
$ make deps
$ pip3 install -e .
```

# Commands and Usage

View available commands:

```bash
$ panther_analysis_tool --help
usage: panther_analysis_tool [-h] [--version] {test,zip,upload} ...

Panther Analysis Tool: A command line tool for managing Panther policies and
rules.

positional arguments:
  {test,zip,upload}
    test             Validate analysis specifications and run policy and rule
                     tests.
    zip              Create an archive of local policies and rules for
                     uploading to Panther.
    upload           Upload specified policies and rules to a Panther
                     deployment.

optional arguments:
  -h, --help         show this help message and exit
  --version          show program's version number and exit
```

Run tests:

```bash
$ panther_analysis_tool test --path tests/fixtures/valid_policies/
[INFO]: Testing analysis packs in tests/fixtures/valid_policies/

AWS.IAM.MFAEnabled
	[PASS] Root MFA not enabled fails compliance
	[PASS] User MFA not enabled fails compliance
```

Create packages to upload via the Panther UI:

```bash
$ panther_analysis_tool zip --path tests/fixtures/valid_policies/ --out tmp
[INFO]: Testing analysis packs in tests/fixtures/valid_policies/

AWS.IAM.MFAEnabled
	[PASS] Root MFA not enabled fails compliance
	[PASS] User MFA not enabled fails compliance

[INFO]: Zipping analysis packs in tests/fixtures/valid_policies/ to tmp
[INFO]: <current working directory>/tmp/panther-analysis-2020-03-23T12-48-18.zip
```

Upload packages to Panther directly. Note, this expects your environment to be setup the same way as if you were using the AWS CLI, see the setup instructions [here](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html). We also recommend using a credentials manager such as [aws-vault](https://github.com/99designs/aws-vault).

```bash
$ panther_analysis_tool upload --path tests/fixtures/valid_policies/ --out tmp
[INFO]: Testing analysis packs in tests/fixtures/valid_policies/

AWS.IAM.MFAEnabled
	[PASS] Root MFA not enabled fails compliance
	[PASS] User MFA not enabled fails compliance

AWS.IAM.BetaTest
	[PASS] Root MFA not enabled fails compliance
	[PASS] User MFA not enabled fails compliance

AWS.CloudTrail.MFAEnabled
	[PASS] Root MFA not enabled fails compliance
	[PASS] User MFA not enabled fails compliance

[INFO]: Zipping analysis packs in tests/fixtures/valid_policies/ to tmp
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

The `test`, `zip`, and `upload` commands all support filtering. Filtering works by passing the `--filter` argument with a list of filters specified in the format `KEY=VALUE1,VALUE2`. The keys can be any valid field in a policy or rule. When using a filter, only anaylsis that matches each filter specified will be considered. For example, the following command will test only items with the AnalysisType of policy AND the severity of High:

```
panther_analysis_tool test --path tests/fixtures/valid_policies --filter AnalysisType=policy Severity=High
[INFO]: Testing analysis packs in tests/fixtures/valid_policies

AWS.IAM.BetaTest
	[PASS] Root MFA not enabled fails compliance
	[PASS] User MFA not enabled fails compliance
```

Whereas the following command will test items with the AnalysisType policy OR rule, AND the severity High:

```
panther_analysis_tool test --path tests/fixtures/valid_policies --filter AnalysisType=policy,rule Severity=High
[INFO]: Testing analysis packs in tests/fixtures/valid_policies

AWS.IAM.BetaTest
	[PASS] Root MFA not enabled fails compliance
	[PASS] User MFA not enabled fails compliance

AWS.CloudTrail.MFAEnabled
	[PASS] Root MFA not enabled fails compliance
	[PASS] User MFA not enabled fails compliance
```

When writing policies or rules that refer to the `global` analysis types, be sure to include them in your filter. You can include an empty string as a value in a filter, and it will mean the filter is only applied if the field exists. The following command will return an error, because the policy in question imports a global but the global does not have a severity so it is excluded by the filter:

```
panther_analysis_tool test --path tests/fixtures/valid_policies --filter AnalysisType=policy,global Severity=Critical
[INFO]: Testing analysis packs in tests/fixtures/valid_policies

AWS.IAM.MFAEnabled
	[ERROR] Error loading module, skipping

Invalid: tests/fixtures/valid_policies/example_policy.yml
	No module named 'panther'

[ERROR]: [('tests/fixtures/valid_policies/example_policy.yml', ModuleNotFoundError("No module named 'panther'"))]
```

If you want this query to work, you need to allow for the severity field to be absent like this:

```
panther_analysis_tool test --path tests/fixtures/valid_policies --filter AnalysisType=policy,global Severity=Critical,""
[INFO]: Testing analysis packs in tests/fixtures/valid_policies

AWS.IAM.MFAEnabled
	[PASS] Root MFA not enabled fails compliance
	[PASS] User MFA not enabled fails compliance
```

Filters work for the `zip` and `upload` commands in the exact same way they work for the `test` command.

In addition to filtering, you can set a minimum number of unit tests with the `--minimum-tests` flag. Detections that don't have the minimum number of tests will be considered failing, and if `--minimum-tests` is set to 2 or greater it will also enforce that at least one test must return True and one must return False.

```
panther_analysis_tool test --path tests/fixtures/valid_policies --minimum-tests 2
% panther_analysis_tool test --path okta_rules --minimum-tests 2
[INFO]: Testing analysis packs in okta_rules

Okta.AdminRoleAssigned
	[PASS] Admin Access Assigned

Okta.BruteForceLogins
	[PASS] Failed login

Okta.GeographicallyImprobableAccess
	[PASS] Non Login
	[PASS] Failed Login

--------------------------
Panther CLI Test Summary
	Path: okta_rules
	Passed: 0
	Failed: 3
	Invalid: 0

--------------------------
Failed Tests Summary
	Okta.AdminRoleAssigned
		['Insufficient test coverage, 2 tests required but only 1 found.', 'Insufficient test coverage: expected at least one passing and one failing test.']

	Okta.BruteForceLogins
		['Insufficient test coverage, 2 tests required but only 1 found.', 'Insufficient test coverage: expected at least one passing and one failing test.']

	Okta.GeographicallyImprobableAccess
		['Insufficient test coverage: expected at least one passing and one failing test.']
```

So in this case even though the rules passed all their tests, they're still considered failing because they do not have the correct test coverage.

# Contributing

We welcome all contributions! Please read the [contributing guidelines](https://github.com/panther-labs/panther-analysis/blob/master/CONTRIBUTING.md) before submitting pull requests.

## License

This repository is licensed under the AGPL-3.0 [license](https://github.com/panther-labs/panther-analysis/blob/master/LICENSE).
