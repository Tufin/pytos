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

Quick Start SecureTrack
***********************

Connecting to SecureTrack
::
	from pytos.securechange.Helpers import Secure_Change_Helper
	sc_helper = Secure_Change_Helper("127.0.0.1", ("username", "passowrd"))