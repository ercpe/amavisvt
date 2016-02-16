#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

VERSION='0.0.1'

setup(
	name='amavisvt',
	version=VERSION,
	description='Virustotal integration for amavisd-new',
	author='Johann Schmitz',
	author_email='johann@j-schmitz.net',
	url='https://code.not-your-server.de/amavisvt.git/',
	download_url='https://code.not-your-server.de/amavisvt.git/tags/%s.tar.gz' % VERSION,
	packages=find_packages(''),
	zip_safe=False,
	license='GPL-3',
)
