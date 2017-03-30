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

Getting Help
------------

We use GitHub issues for tracking bugs and feature requests and have limited
bandwidth to address them. Please use these community resources for getting
help:

* Come join the AWS Python community chat on `Tufin Developer Community <https://plus.google.com/communities/112366353546062524001>`__
* Open a support ticket with `Tufin Support <https://support.tufin.com>`__
* If it turns out that you may have found a bug, please `open an issue <https://github.com/pytos/pytos/issues/new>`__