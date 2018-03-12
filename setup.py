#!/usr/bin/env python
from setuptools import setup, find_packages

setup(name='fw-proc',
      version='1.0',
      description='pfsense firewall processor',
      author='adam pridgen',
      author_email='adam.pridgen@thecoverofnight.com',
      install_requires=['toml', 'pygrok', 'rule-chains',
                        'pymongo', 'regex'],
      packages=find_packages('src'),
      package_dir={'': 'src'},
)