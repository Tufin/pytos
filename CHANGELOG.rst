=======
CHANGES
=======

1.0.0
=====

* New elements and new attributes
* Added method to get file via SFTP
* File can be sent via POST
* Added more attributes to the designer instructions
* Added rule and server decomission
* NAT rules
* UID parameter was added to Base_Object
* Added pagination to rule search
* Added more parameters to the get services and get network objects methods
* New helpers get_topology_path and get_nat_rules_by_device_id
* Bugs fix

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