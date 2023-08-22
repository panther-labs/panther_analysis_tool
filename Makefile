packages = panther_analysis_tool

default: help
# via https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: ci
ci: lint test integration

.PHONY: install-pipenv
install-pipenv:
	pip install pipenv

.PHONY: deps
deps: ## Install dependencies (including dev dependencies) using pipenv
	pipenv install --dev

.PHONY: deps-update
deps-update: ## Update dependencies using pipenv
	pipenv update
	pipenv lock
	pipenv requirements > requirements.txt

.PHONY: lint
lint: ## Lint panther_analysis_tool (mypy, bandit, pylint)
	pipenv run mypy $(packages) --disallow-untyped-defs --ignore-missing-imports --warn-unused-ignores
	pipenv run bandit -r $(packages)
	pipenv run pylint $(packages) --disable=missing-docstring,bad-continuation,duplicate-code,W0511,R0912,too-many-lines,too-few-public-methods --max-line-length=140

.PHONY: venv
venv: ## Install dependencies (including dev dependencies) using pipenv
	pipenv install --dev

.PHONY: fmt
fmt: ## Format panther_analysis_tool (black)
	pipenv run isort --profile=black .
	pipenv run black --line-length=100 .

.PHONY: install
install: ## Install dependencies (including dev dependencies) using pipenv
	pipenv install --dev

.PHONY: test
test: ## Run panther_analysis_tool tests
	pipenv run nosetests -v --with-coverage --cover-package=panther_analysis_tool --cover-html --cover-html-dir=htmlcov

.PHONY: test-fail-fast
test-fail-fast: ## Run panther_analysis_tool tests, stopping as soon as a test fails
	pipenv run nosetests -v --stop

.PHONY: coverage
coverage: ## Open the coverage report generated by the test target
	open ./htmlcov/index.html

.PHONY: integration
integration: ## Run panther_analysis_tool integration tests (from included fixtures and panther-analysis repo)
	pipenv run panther_analysis_tool test --path tests/fixtures/detections/valid_analysis
	rm -rf panther-analysis
	git clone https://github.com/panther-labs/panther-analysis.git
	cd panther-analysis && pipenv lock
	cd panther-analysis && pipenv requirements | grep -v 'panther-analysis-tool==' > requirements.ci.txt
	cd panther-analysis && pipenv install -r requirements.ci.txt
	cd panther-analysis && pipenv install -e ..
	cd panther-analysis && pipenv run panther_analysis_tool --version && pipenv run panther_analysis_tool test --path .
	rm -rf panther-analysis

.PHONY: pypi
pypi: ## Publish to PyPi
	pipenv run python3 setup.py sdist
	pipenv run twine upload dist/*
