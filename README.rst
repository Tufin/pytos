pytos - The Tufin Orchestration Suite SDK for Python
====================================================

|Build Status| |Version|

.. |Build Status| image:: https://travis-ci.org/tgratzi/pytos.svg?branch=master
	:target: https://travis-ci.org/Tufin/pytos|
	:alt: Build Status
.. |Version| image:: http://img.shields.io/pypi/v/pytos.svg?style=flat
	:target: https://pypi.python.org/pypi/pytos/
	:alt: Version

The pytos is the formal Python Software Development Kit (SDK) for Tufin Orchestration Suite (TOS).
Python developers can use this package to write a scripts that able to connect, retrieve and update information
in the TOS system. This SDK is an open source Python library to allow easy access to the native RESTful APIs provided
by Tufin.

Installation
************

First install the package by running the following command
::
	# pip install pytos

Running Tests
~~~~~~~~~~~~~
The package can be tested in all supported Python versions using ``tox``. The tested Python version
must be installed and including ``tox``:

	$ tox -e py34

You can also run individual tests with your default Python version by running ``nosetests`` command directly:

	$ nosetests -v tests/securetrack_test/test_secure_track_helper_unittest.py:TestGeneralSettings

SecureTrack
***********

Connecting to SecureTrack with valid username and password
::
	from pytos.securechange.Helpers import Secure_Track_Helper
	st_helper = Secure_Track_Helper("127.0.0.1", ("username", "password"))

SecureChange
************

Connecting to SecureChange with valid username and password
::
	from pytos.securechange.Helpers import Secure_Change_Helper
	sc_helper = Secure_Change_Helper("127.0.0.1", ("username", "password"))

SecureApp
*********

Connecting to SecureApp with valid username and password
::
	from pytos.securechange.Helpers import Secure_Change_Helper
	sa_helper = Secure_App_Helper("127.0.0.1", ("username", "password"))

How to use pytos logger
***********************

To use the pytos logging mechanism perform the following steps:

The following table defines the log levels and messages, in decreasing order of severity.

+---------------------+----------------------------------------------+
| Parameters          | Description                                  |
+=====================+==============================================+
| CRITICAL            | Only critical messages will present.         |
+---------------------+----------------------------------------------+
| ERROR               | Messages with error and above.               |
+---------------------+----------------------------------------------+
| WARNING             | Message with warning and above.              |
+---------------------+----------------------------------------------+
| INFO                | Messages with info and above.                |
+---------------------+----------------------------------------------+
| DEBUG               | All levels.                                  |
+---------------------+----------------------------------------------+

Create an ini like configuration file with the following sections.
::
	[common]
	log_file_path = /var/log/pytos/

	[log_levels]
	common = WARNING
	helpers = WARNING
	reports = WARNING
	requests = WARNING
	mail = WARNING
	sql = WARNING
	xml = WARNING
	web = WARNING
	third_party = WARNING

In your code call the following methods
::
	import logging
	from pytos.common.logging.Defines import COMMON_LOGGER_NAME
	from pytos.common.logging.Logger import setup_loggers
	from pytos.common.functions.Config import Secure_Config_Parser

	conf = Secure_Config_Parser(config_file_path="/ini/like/configuration/path/pytos.conf")
	logger = logging.getLogger(COMMON_LOGGER_NAME)
	setup_loggers(conf.dict("log_levels"), log_to_stdout=True)
	logger.info("Hello world")

Getting Help
************

For tracking bugs and new features please use GitHub issues. Please also use these community resources for getting
help:

* Join the `Tufin Developer Community <https://plus.google.com/communities/112366353546062524001>`__
* If it turns out that you may have found a bug, please `open an issue <https://github.com/pytos/pytos/issues/new>`__
