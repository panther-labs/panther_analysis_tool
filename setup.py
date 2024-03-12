from pathlib import Path

from setuptools import find_packages, setup

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

PAT_VERSION = (this_directory / "VERSION").read_text().strip()

install_requires = [
    "gql",
    "aiohttp",
    "boto3",
    "dynaconf",
    "jsonpath-ng",
    "jsonschema",
    "nested_lookup",
    "packaging",
    "requests",
    "ruamel.yaml",
    "schema",
    "semver",
    "sqlfluff",
    "panther-core==0.8.1",
    "typing-extensions",
    "jsonlines",
]

setup(
    name="panther_analysis_tool",
    version=PAT_VERSION,
    packages=find_packages(),
    license="AGPL-3.0",
    description="Panther command line interface for writing, testing, and packaging policies/rules.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Panther Labs Inc",
    author_email="pypi@runpanther.io",
    url="https://github.com/panther-labs/panther_analysis_tool",
    download_url=f"https://github.com/panther-labs/panther_analysis_tool/archive/v{PAT_VERSION}.tar.gz",
    keywords=["Security", "CLI"],
    scripts=["bin/panther_analysis_tool", "bin/pat"],
    install_requires=install_requires,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python :: 3.9",
    ],
    include_package_data=True,
)
