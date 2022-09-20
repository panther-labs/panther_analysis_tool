packages = panther_analysis_tool

ci: lint test integration


deps:
	pipenv install --dev

deps-update:
	pipenv update
	pipenv lock -r  > requirements.txt

lint:
	pipenv run mypy $(packages) --disallow-untyped-defs --ignore-missing-imports --warn-unused-ignores
	pipenv run bandit -r $(packages)
	pipenv run pylint $(packages) --disable=missing-docstring,bad-continuation,duplicate-code,W0511,R0912,too-many-lines,too-few-public-methods --max-line-length=140

venv:
	pipenv install --dev

fmt:
	pipenv run isort --profile=black $(packages)
	pipenv run black --line-length=100 $(packages)

install:
	pipenv install --dev

test:
	pipenv run nosetests -v --with-coverage --cover-package=panther_analysis_tool --cover-html --cover-html-dir=htmlcov

test-fail-fast:
	pipenv run nosetests -v --stop

coverage:
	open ./htmlcov/index.html

integration:
	pipenv run panther_analysis_tool test --path tests/fixtures/detections/valid_analysis
	rm -rf panther-analysis
	git clone https://github.com/panther-labs/panther-analysis.git
	cd panther-analysis && pipenv lock
	cd panther-analysis && pipenv requirements | grep -v 'panther-analysis-tool==' > requirements.ci.txt
	cd panther-analysis && pipenv install -r requirements.ci.txt
	cd panther-analysis && pipenv install -e ..
	cd panther-analysis && pipenv run panther_analysis_tool --version && pipenv run panther_analysis_tool test --path .
	rm -rf panther-analysis

pypi:
	pipenv run python3 setup.py sdist
	pipenv run twine upload dist/*
