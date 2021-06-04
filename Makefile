packages = panther_analysis_tool

ci: lint unit integration

deps:
	pip3 install -r requirements.txt
	pip3 install -r dev-requirements.txt

deps-update:
	pipenv update
	pipenv lock -r --dev-only > dev-requirements.txt
	pipenv lock -r > requirements.txt

lint:
	pipenv run mypy $(packages) --disallow-untyped-defs --ignore-missing-imports --warn-unused-ignores
	pipenv run bandit -r $(packages)
	pipenv run pylint $(packages) --disable=missing-docstring,bad-continuation,duplicate-code,W0511,R0912,too-many-lines --max-line-length=100

venv:
	virtualenv -p python3.7 venv

fmt:
	pipenv run isort --profile=black $(packages)
	pipenv run black --line-length=100 $(packages)

install:
	pip3 install --upgrade pip
	pip3 install pipenv --upgrade
	pipenv install

unit:
	pipenv run nosetests -v

integration:
	pipenv run panther_analysis_tool test --path tests/fixtures/detections/valid_analysis

test: unit

pypi:
	pipenv run python3 setup.py sdist
	pipenv run twine upload dist/*
