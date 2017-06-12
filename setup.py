#!/home/user/sources/compiled/python3.4_dev/lib/python3.4

import os
import re
from setuptools import setup, find_packages

package_name = "pytos"
root_dir = os.path.abspath(os.path.dirname(__file__))


def get_version():
    file_path = os.path.join(root_dir, 'pytos', '__init__.py')
    with open(file_path, 'rt') as f:
        version = re.search('__version__ = "(\d+\.\d+\.\d+)', f.read()).group(1)
        return version


setup(
    name=package_name,
    version=get_version(),
    author="Tufin Solution Engineering",
    author_email="support@tufin.com",
    url='http://pypi.python.org/pypi/pytos',
    license="Apache License 2.0",
    description="The Tufin TOS SDK for Python",
    long_description=open('README.rst').read(),
    packages=find_packages(exclude=['tests*']),
    include_package_data=True,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6'
    ],
    install_requires=[
        'netaddr>=0.7.14',
        'paramiko>=1.15.2',
        'requests>=2.6.0',
        'requests_toolbelt==0.7.1',
        'pyinotify==0.9.6',
        'netifaces==0.10.5',
        'dnspython3==1.15.0',
        'Mako',
    ]
)