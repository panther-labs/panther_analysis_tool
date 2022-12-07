from pathlib import Path
from setuptools import setup, find_packages

this_directory = Path(__file__).parent
PAT_VERSION = (this_directory / "VERSION").read_text().strip()

install_requires = [
    'gql',
    'aiohttp',
    'boto3',
    'dynaconf',
    'jsonpath-ng',
    'requests',
    'ruamel.yaml',
    'schema',
    'semver',
    'panther_core',
    'typing-extensions',
    'jsonlines',
]

with open('requirements.txt') as f:
    dependencies_with_versions = []
    for dependency in f.readlines():
        dependency_with_version = dependency.strip()
        package_name = dependency_with_version.split('==')[0]
        if package_name in install_requires:
            dependencies_with_versions.append(dependency_with_version)

setup(
    name='panther_analysis_tool',
    version=PAT_VERSION,
    packages=find_packages(),
    license='AGPL-3.0',
    description=
    'Panther command line interface for writing, testing, and packaging policies/rules.',
    author='Panther Labs Inc',
    author_email='pypi@runpanther.io',
    url='https://github.com/panther-labs/panther_analysis_tool',
    download_url=f'https://github.com/panther-labs/panther_analysis_tool/archive/v{PAT_VERSION}.tar.gz',
    keywords=['Security', 'CLI'],
    scripts=['bin/panther_analysis_tool'],
    install_requires=install_requires,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Programming Language :: Python :: 3.9',
    ],
    include_package_data=True,
)
