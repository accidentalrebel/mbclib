#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name='mbclib',
    description='A library for querying the STIX data for the MBC (Malware Behavior Catalog).',
    author='Karlo Licudine',
    author_email='karlolicudine@gmail.com',
    url='https://github.com/accidentalrebel/mbclib',
    install_requires=[
        'stix2'
    ],
    packages=find_packages()
)

