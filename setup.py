#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='mbclib',
    version='0.0.2',
    description='A library for querying the STIX data for the MBC (Malware Behavior Catalog).',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='Karlo Licudine',
    author_email='karlolicudine@gmail.com',
    url='https://github.com/accidentalrebel/mbclib',
    install_requires=[
        'stix2'
    ],
    packages=find_packages()
)

