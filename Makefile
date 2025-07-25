packages = panther_analysis_tool

default: help
# via https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: ci
ci: lint test integration

.PHONY: install-poetry
install-poetry:
	which poetry || pip install poetry

.PHONY: deps
deps: ## Install dependencies (excluding dev dependencies) using poetry
	poetry sync --only main

.PHONY: deps-update
deps-update: ## Update dependencies using poetry
	poetry update
	poetry lock
	poetry export -f requirements.txt --output requirements.txt --without-hashes

.PHONY: reqs
reqs:
	poetry export -f requirements.txt --output requirements.txt --without-hashes

.PHONY: lint
lint: ## Lint panther_analysis_tool (mypy, bandit, pylint)
	poetry run mypy $(packages)
	poetry run bandit -r $(packages)
	poetry run pylint $(packages)

.PHONY: venv
venv: install-poetry install # Sets up venv from scratch

.PHONY: fmt
fmt: ## Format panther_analysis_tool (black)
	poetry run isort .
	poetry run black .

.PHONY: install
install: ## Install dependencies (including dev dependencies) using poetry
	poetry sync

.PHONY: test
test: ## Run panther_analysis_tool tests
	poetry run nose2 -v --with-coverage --coverage=panther_analysis_tool --coverage-report=html

.PHONY: test-fail-fast
test-fail-fast: ## Run panther_analysis_tool tests, stopping as soon as a test fails
	poetry run nose2 -v --stop

.PHONY: coverage
coverage: ## Open the coverage report generated by the test target
	open ./htmlcov/index.html

.PHONY: integration
integration: ## Run panther_analysis_tool integration tests (from included fixtures and panther-analysis repo)
	poetry run panther_analysis_tool test --path tests/fixtures/detections/valid_analysis
	rm -rf panther-analysis
	pip install pipenv
	git clone https://github.com/panther-labs/panther-analysis.git
	cd panther-analysis;\
		pipenv lock; \
		pipenv requirements | grep -v 'panther-analysis-tool==' > requirements.ci.txt; \
		pipenv install -r requirements.ci.txt; \
		pipenv install -e ..; \
		pip install schema==0.7.5; \
		pipenv run panther_analysis_tool --version; \
		pipenv run panther_analysis_tool test --path .
	cd ..
	rm -rf panther-analysis


.PHONY: build
build: ## Builds the package
	poetry build --clean --format sdist

.PHONY: publish
release:
	poetry publish -u __token__ -p ${PYPI_TOKEN}

.PHONY: pypi
pypi: reqs build publish ## Publish to PyPi
