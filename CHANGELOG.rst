=======
CHANGES
=======

1.2.1
=====

* Fixed a bug when creating a subnet network object

1.2.0
=====

* Added comment attribute to SecureApp network objects
* Added comment attribute to SecureApp User
* Added support both prefix and netmask in SecureApp Subnet_Network_Object
* Added support for user group in extended connections
* Added viewers attribute to to SecureApp Application

1.1.0
=====

* Added default value option to the get method in the config parser
* Added missing attributes to classes
* Added new triggers such as resolve, pre script and automatic step failed

1.0.1
=====

* Fixed a bug that causes issues with as_netaddr_obj() for Fortinet network objects

1.0.0
=====

* Added method to get file via SFTP
* Added file to POST
* Added more attributes to the designer instructions
* Added rule and server decommission
* Added NAT rules
* Added UID parameter to Base_Object
* Added pagination to rule search
* Added more parameters to the get services and get network objects methods
* Added new helper get_topology_path and get_nat_rules_by_device_id
* Bugs correction

0.0.3
=====

* Fixed a bug when calling Secure_Track_Helper.get_security_policy_violations_for_all_devices method

0.0.2
=====

* Fixed a bug in Access_Request_Generator: cidr and netmask tags will be generated correctly. pytos version bumped to 0.0.2

0.0.1
=====

* Supports SecureTrack, SecureChange and SecureApp
* Supports most of the endpoint APIs
