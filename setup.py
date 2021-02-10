from distutils.core import setup
setup(
    name='panther_analysis_tool',
    packages=['panther_analysis_tool'],
    version='0.4.5',
    license='AGPL-3.0',
    description=
    'Panther command line interface for writing, testing, and packaging policies/rules.',
    author='Panther Labs Inc',
    author_email='pypi@runpanther.io',
    url='https://github.com/panther-labs/panther_analysis_tool',
    download_url = 'https://github.com/panther-labs/panther_analysis_tool/archive/v0.4.5.tar.gz',
    keywords=['Security', 'CLI'],
    scripts=['bin/panther_analysis_tool'],
    install_requires=[
        'jsonpath-ng',
        'ruamel.yaml',
        'schema',
        'boto3',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Programming Language :: Python :: 3.7',
    ],
)
