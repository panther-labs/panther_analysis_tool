packages = panther_analysis_tool

ci:
	pipenv run $(MAKE) lint unit integration

deps:
	pip3 install -r requirements.txt

deps-update:
	pip3 install -r requirements-top-level.txt --upgrade
	pip3 freeze -r requirements-top-level.txt > requirements.txt

lint:
	yapf $(packages) --diff --parallel --recursive --style google
	mypy $(packages) --disallow-untyped-defs --ignore-missing-imports --warn-unused-ignores || true # TODO(jack) Figure out why mypy is failing on 'has no attribute' error
	bandit -r $(packages)
	pylint $(packages) --disable=missing-docstring,bad-continuation,duplicate-code,W0511,R0912 --exit-zero

venv:
	virtualenv -p python3.7 venv

fmt:
	pipenv run yapf $(packages) --in-place --recursive --parallel --style google

install:
	pip3 install --user --upgrade pip
	pip3 install pipenv --upgrade
	pipenv install

unit:
	pipenv run nosetests -v

integration:
	panther_analysis_tool test --path tests/fixtures/valid_policies/

test: unit
