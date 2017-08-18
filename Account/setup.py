# -*- coding: utf-8 -*-

"""
__author__ = "Jani Yli-Kantola"
__copyright__ = ""
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "1.3.0"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
"""

from setuptools import setup, find_packages

# https://stackoverflow.com/questions/14399534/reference-requirements-txt-for-the-install-requires-kwarg-in-setuptools-setup-py/14399775#14399775
with open('requirements.txt') as f:
    reqs = f.read().splitlines()

setup(
    name='app',
    packages=find_packages(),
    include_package_data=False,
    install_requires=reqs,
    setup_requires=[
        'pytest-runner',
    ],
    tests_require=[
        'pytest',
    ],
)
