pytos - The Tufin Orchestration Suite SDK for Python
====================================================

The pytos is the formal Python Software Development Kit (SDK) for Tufin Orchestration Suite (TOS).
Python developers can use this package to write a scripts that able to connect, retrieve and update information
in the TOS system. This SDK is an open source Python library to allow easy access to the native RESTful APIs provided
by Tufin.

Installation
************

First install the package by running the following command
::
	# pip install pytos

SecureTrack
***********

Connecting to SecureTrack
::
	from pytos.securechange.Helpers import Secure_Track_Helper
	sc_helper = Secure_Track_Helper("127.0.0.1", ("username", "passowrd"))

SecureChange
************

Connecting to SecureChange with valid username and password
::
	from pytos.securechange.Helpers import Secure_Change_Helper
	sc_helper = Secure_Change_Helper("127.0.0.1", ("username", "passowrd"))

How to use pytos Logger
***********************

To use the pytos logging mechanism perform the following steps:

* Create an ini like configuration file with that have the following section
::
	[common]
	log_file_path = /var/log/pytos/

	[log_levels]
	common = DEBUG
	helpers = WARNING
	reports = DEBUG
	requests = WARNING
	mail = WARNING
	sql = WARNING
	xml = WARNING
	web = DEBUG
	third_party = WARNING

In your code call the following methods to define and the
::
	import logging
	from pytos.common.logging.Defines import COMMON_LOGGER_NAME
	from pytos.common.logging.Logger import setup_loggers
	from pytos.common.functions.Config import Secure_Config_Parser

	conf = Secure_Config_Parser(config_file_path="/ini/like/configuration/path/pytos.conf",
								custom_config_file_path="/opt/tufin/securitysuite/ps/conf/custom.conf")
	logger = logging.getLogger(COMMON_LOGGER_NAME)
	setup_loggers(conf.dict("log_levels"), log_to_stdout=True)
	logger.info("Hello world")

Getting Help
************

For tracking bugs and new features please use GitHub issues. Please also use these community resources for getting
help:

* Join the `Tufin Developer Community <https://plus.google.com/communities/112366353546062524001>`__
* Open a support ticket with `Tufin Support <https://www.tufin.com/support/>`__
* If it turns out that you may have found a bug, please `open an issue <https://github.com/pytos/pytos/issues/new>`__