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
    name='pytos',
    version=get_version(),
    author="Tufin Solution Engineering",
    author_email="support@tufin.com",
    url='http://pypi.python.org/pypi/pytos',
    license="Apache License 2.0",
    description="The Tufin TOS SDK for Python",
    long_description=open('README.txt').read(),
    packages=find_packages(exclude=['tests*']),
    include_package_data=True,
    # package_dir={package_name: package_name},
    # package_data={'': ['conf/tufin_api.conf.orig']},
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    install_requires=[
        'netaddr>=0.7.14',
        'paramiko>=1.15.2',
        'requests>=2.6.0',
        'requests_toolbelt',
        'pyinotify',
        'cryptography',
        'pycrypto',
        'pbkdf2',
        'netifaces',
        'dnspython3',
        'Mako',
        'pyasn1'
    ]
)