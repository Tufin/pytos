Pytos
=====

|Build Status| |Version|

.. |Build Status| image:: https://travis-ci.org/Tufin/pytos.svg?branch=master
	:target: https://travis-ci.org/Tufin/pytos
	:alt: Build Status
.. |Version| image:: http://img.shields.io/pypi/v/pytos.svg?style=flat
	:target: https://pypi.python.org/pypi/pytos/
	:alt: Version

Pytos is the Tufin Orchestration Suite (TOS) Software Development Kit (SDK) for Python, which allows Python developers to make use of the services provided by SecureTrack, SecureChange and SecureApp.

Common Use Cases
****************
* Get security rules or ACLs from firewalls
* Get network objects and services from firewalls
* Get security groups from cloud platforms
* Get routing tables and interfaces from routers and firewalls
* Manage security zones
* Submit and manage access requests to update firewall policies
* Manage application connectivity


Installation
************

Install the package by running the following command::

	# pip install pytos

Running Tests
~~~~~~~~~~~~~
The package can be tested in all supported Python versions using ``tox``. The tested Python version
must be installed including ``tox``:

	$ tox -e py34

You can also run individual tests with your default Python version by running ``nosetests`` command directly:

	$ nosetests -v tests/securetrack_test/test_secure_track_helper_unittest.py:TestGeneralSettings

SecureTrack
***********

Connect to SecureTrack with valid username and password::

	from pytos.securetrack.helpers import Secure_Track_Helper
	st_helper = Secure_Track_Helper("127.0.0.1", ("username", "password"))

SecureChange
************

Connect to SecureChange with valid username and password::

	from pytos.securechange.helpers import Secure_Change_Helper
	sc_helper = Secure_Change_Helper("127.0.0.1", ("username", "password"))

SecureApp
*********

Connect to SecureApp with valid username and password::

	from pytos.secureapp.helpers import Secure_App_Helper
	sa_helper = Secure_App_Helper("127.0.0.1", ("username", "password"))

How to use pytos logger
***********************

To use the pytos logging mechanism perform the following steps:

The following table defines the log levels and messages, in decreasing order of severity.

+---------------------+----------------------------------------------+
| Parameters          | Description                                  |
+=====================+==============================================+
| CRITICAL            | Only critical messages.                      |
+---------------------+----------------------------------------------+
| ERROR               | Messages with error and above.               |
+---------------------+----------------------------------------------+
| WARNING             | Message with warning and above.              |
+---------------------+----------------------------------------------+
| INFO                | Messages with info and above.                |
+---------------------+----------------------------------------------+
| DEBUG               | All levels.                                  |
+---------------------+----------------------------------------------+

Create an ini like configuration file with the following sections::

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

In your code call the following methods::

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

For tracking bugs and new feature requests please use GitHub issues. Please also use these community resources for getting
help:

* Join the `Tufin Developer Community <https://plus.google.com/communities/112366353546062524001>`__
* If you think you found a bug, please `submit an issue <https://github.com/Tufin/pytos/issues>`__
