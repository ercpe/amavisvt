#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from amavisvt import VERSION

setup(
	name='amavisvt',
	version=VERSION,
	description='Virustotal integration for amavisd-new',
	author='Johann Schmitz',
	author_email='johann@j-schmitz.net',
	url='https://code.not-your-server.de/amavisvt.git/',
	download_url='https://code.not-your-server.de/amavisvt.git/tags/%s.tar.gz' % VERSION,
	packages=find_packages(exclude=('tests', )),
	zip_safe=False,
	license='GPL-3',
)
