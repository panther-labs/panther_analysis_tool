from distutils.core import setup

install_requires = [
    'boto3',
    'jsonpath-ng',
    'requests',
    'ruamel.yaml',
    'schema',
    'semver',
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
    packages=['panther_analysis_tool', 'panther_analysis_tool/log_schemas'],
    package_dir={'log_schemas': 'panther_analysis_tool/log_schemas'},
    version='0.10.2',
    license='AGPL-3.0',
    description=
    'Panther command line interface for writing, testing, and packaging policies/rules.',
    author='Panther Labs Inc',
    author_email='pypi@runpanther.io',
    url='https://github.com/panther-labs/panther_analysis_tool',
    download_url = 'https://github.com/panther-labs/panther_analysis_tool/archive/v0.10.2.tar.gz',
    keywords=['Security', 'CLI'],
    scripts=['bin/panther_analysis_tool'],
    install_requires=install_requires,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Programming Language :: Python :: 3.7',
    ],
)
