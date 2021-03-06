packages = panther_analysis_tool

ci:
	$(MAKE) lint unit integration

deps:
	pip3 install -r requirements.txt

deps-update:
	pip3 install -r requirements-top-level.txt --upgrade
	pip3 freeze -r requirements-top-level.txt > requirements.txt

lint:
	pipenv run mypy $(packages) --disallow-untyped-defs --ignore-missing-imports --warn-unused-ignores || true # TODO(jack) Figure out why mypy is failing on 'has no attribute' error
	pipenv run bandit -r $(packages)
	pipenv run pylint $(packages) --disable=missing-docstring,bad-continuation,duplicate-code,W0511,R0912 --max-line-length=100

venv:
	virtualenv -p python3.7 venv

fmt:
	pipenv run isort --profile=black $(packages)
	pipenv run black --line-length=100 $(packages)

install:
	pip3 install --user --upgrade pip
	pip3 install pipenv --upgrade
	pipenv install

unit:
	pipenv run nosetests -v

integration:
	pipenv run panther_analysis_tool test --path tests/fixtures/valid_analysis/

test: unit

pypi:
	pipenv run python3 setup.py sdist
	pipenv run twine upload dist/*
