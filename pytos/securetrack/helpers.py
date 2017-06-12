
# coding=utf-8
import collections
import csv
import io
import itertools
import logging
import multiprocessing.pool

from requests import RequestException

from pytos.common.helpers import Secure_API_Helper
from pytos.common.definitions.xml_tags import Elements
from pytos.common.exceptions import REST_Not_Found_Error, REST_Bad_Request_Error, \
    REST_Request_URI_Too_Long, REST_Client_Error, ItemAlreadyExists, REST_Internal_Server_Error, REST_HTTP_Exception
from pytos.common.functions import config
from pytos.common.logging.definitions import HELPERS_LOGGER_NAME
from pytos.securetrack.xml_objects.rest.cleanups import Generic_Cleanup_List
from pytos.securetrack.xml_objects.rest.device import Devices_List, Device, Device_Revisions_List, GenericDevicesList, \
    RuleSearchDeviceList, Device_Revision, InternetReferralObject
from pytos.securetrack.xml_objects.rest.domain import Domains, Domain
from pytos.securetrack.xml_objects.rest.routes import RoutesList
from pytos.securetrack.xml_objects.rest.rules import Rules_List, Cleanup_Set, Policy_List, Bindings_List, \
    Interfaces_List, Topology_Interfaces_List, Policy_Analysis_Query_Result, Network_Objects_List, Services_List, \
    Rule_Documentation, SecurityPolicyDeviceViolations, Change_Authorization
from pytos.securetrack.xml_objects.rest.security_policy import SecurityPolicyExceptionList, Security_Policy_Exception, \
    Security_Policies_List
from pytos.securetrack.xml_objects.rest.zones import Zone_Entries_List, Zone_List, \
    ZoneDescendantsList

logger = logging.getLogger(HELPERS_LOGGER_NAME)

DEVICE_TYPES = {"Cisco": ["asa", "pix", "fwsm", "nexus", "switch", "xr_router", "L3_switch", "router"],
                "Checkpoint": ["cp_cma", "cp_smrt_cntr"],
                "Netscreen": ["netscreen", "netscreen_cluster", "junos", "junosStateless"], "Fortinet": ["fortigate"],
                "PaloAltoNetworks": ["PaloAltoFW"], "Mcafee": ["mcafeeFW"], "NewF5": ["new_bigip"], "f5": ["bigip"],
                "bluecoat": ["proxysg"], "linux": ["iptables"]}

DEFAULT_DOMAIN_ID = 1
DETACH = -1


class Secure_Track_Helper(Secure_API_Helper):
    """This class  is used to interact via HTTP with SecureTrack.
    It also allows for easy sending of email messages.
    """
    CONFIG_PARSER_SECTION_NAME = "securetrack"

    def __init__(self, hostname, login_data, **kwargs):
        """
        :param hostname: The SecureChange hostname with which we will communicate via HTTP.
        :type hostname: str
        :param login_data: A tuple of (username,password) used for basic authentication with the specified hostname.
        :type login_data: tuple
        """
        super().__init__(hostname, login_data, **kwargs)

    def get_devices_list(self, custom_params=None):
        """Get the list of currently configured devices in SecureTrack.

        :param custom_params: Dictionary from param name to value, eg {'vendor': 'Cisco}
        :type custom_params: dict
        :return: List of currently configured devices in SecureTrack.
        :rtype: Devices_List
        :raise IOError: If there was a communication error while getting the devices list.
        """
        logger.info("Getting SecureTrack devices list.")

        if custom_params:
            params = '&'.join('{}={}'.format(k, v) for k, v in custom_params.items())
            params = '?' + params
        else:
            params = ''

        try:
            response_string = self.get_uri("/securetrack/api/devices/{}".format(params),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to GET devices list."
            logger.critical(message)
            raise IOError(message)
        return Devices_List.from_xml_string(response_string)

    def get_device_by_id(self, device_id):
        """Get a configured SecureTrack device by ID.

        :param device_id: The device ID for the device we want to get.
        :type device_id: int
        :return: The device with the specified ID.
        :rtype: Device
        :raise ValueError: If a device with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the device.
        """
        logger.info("Getting SecureTrack device with ID %s.", device_id)
        try:
            response_string = self.get_uri("/securetrack/api/devices/{}".format(device_id),
                                           expected_status_codes=200).response.content
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        except RequestException:
            message = "Failed to GET device with ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        return Device.from_xml_string(response_string)

    def get_rule_by_device_and_rule_id(self, device_id, rule_id, get_documentation=False):
        """Get a configured SecureTrack device by ID.

        :param device_id: The device ID for the device we want to get.
        :type device_id: int
        :param rule_id: The rule ID for the rule we want to get.
        :type rule_id: int
        :param get_documentation: Whether or not we want to also get the documentation for the rule.
        :type get_documentation: bool
        :return: A Rules_List containing the rule with the specified ID.
        :rtype: Rules_List
        :raise ValueError: If a device or rule with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the rule.
        """
        logger.info("Getting SecureTrack device with ID %s.", device_id)
        if get_documentation:
            rule_documentation_uri_suffix = "?add=documentation"
            logger.info("Getting rules with rule documentation.")
        else:
            rule_documentation_uri_suffix = ""
        try:
            response_string = self.get_uri(
                    "/securetrack/api/devices/{}/rules/{}{}".format(device_id, rule_id, rule_documentation_uri_suffix),
                    expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to GET device with ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        return Rules_List.from_xml_string(response_string)

    def get_device_revisions_by_id(self, device_id):
        """ Get a list of revisions for a SecureTrack device by ID.

        :param device_id: The device ID for the device we want to get.
        :type device_id: int|str
        :return: The revisions list for the device with the specified ID.
        :rtype: Device_Revisions_List
        :raise ValueError: If a device with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the device.
        """
        logger.info("Getting SecureTrack revisions for device with ID %s.", device_id)
        try:
            response_string = self.get_uri("/securetrack/api/devices/{}/revisions/".format(device_id),
                                           expected_status_codes=200).response.content
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        except RequestException:
            message = "Failed to GET device with ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        return Device_Revisions_List.from_xml_string(response_string)

    def get_device_config_by_id(self, device_id):
        """Get the configuration for a configured SecureTrack device by ID.

        :param device_id: The configuration for the device we want to get.
        :type device_id: int
        :return: The configuration for the device with the specified ID.
        :rtype: int|str
        :raise ValueError: If a device with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the device.
        """
        hard_coded_checksum_string = b"Cryptochecksum:0123456789ABCDEF]]></"
        logger.info("Getting SecureTrack device with ID '%s'.", device_id)
        try:
            response_string = self.get_uri("/securetrack/api/devices/{}/config".format(device_id),
                                           expected_status_codes=200).response.content
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        except RequestException:
            message = "Failed to GET configuration for device with ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        device_config_xml_string = bytes(response_string)
        if device_config_xml_string:
            device_config_xml_string = device_config_xml_string.replace(
                    b"<" + bytes(Elements.DEVICE_CONFIG, encoding="ascii") + b"><![CDATA[", b"")
            device_config_xml_string = device_config_xml_string.replace(
                    hard_coded_checksum_string + bytes(Elements.DEVICE_CONFIG, encoding="ascii") + b">\n", b"")
            return device_config_xml_string
        else:
            return device_config_xml_string

    def get_device_id_by_name(self, device_name):
        """Get the device ID for a device by name

        :param device_name: The name for the device.
        :type device_name: str
        :return: The device ID for the device with the matching name.
        :rtype: int
        :raise ValueError: If a device with the specified name does not exist.
        :raise IndexError: If more than one device with the specified name exists.
        """
        match_device = None
        devices_list = self.get_devices_list()
        for device in devices_list:
            if device.name == device_name:
                if not match_device:
                    match_device = device
                else:
                    message = "More than one device with the name '{}' exists. (Device IDs are {},{})".format(
                            device_name, match_device.id, device.id)
                    logger.error(message)
                    raise IndexError(message)
        if not match_device:
            message = "A device with the name '{}' does not exist.".format(device_name)
            logger.error(message)
            raise ValueError(message)
        else:
            return match_device.id

    def get_device_by_name(self, device_name):
        """Get a configured SecureTrack device by ID.

        :param device_name: The name of the device
        :type device_name: str
        :return: The device with the specified ID.
        :rtype: Device
        :raise ValueError: If a device with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the device.
        """
        logger.info("Getting SecureTrack device with name %s.", device_name)
        try:
           response_string = self.get_uri("/securetrack/api/devices?name={}".format(device_name),
                                          expected_status_codes=200).response.content
        except REST_Not_Found_Error:
           message = "Device {} does not exist.".format(device_name)
           logger.critical(message)
           raise ValueError(message)
        except RequestException:
           message = "Failed to GET device {}.".format(device_name)
           logger.critical(message)
           raise IOError(message)
        found_devices = [device for device in Devices_List.from_xml_string(response_string) if device.name.lower() == device_name.lower()]
        if not found_devices:
            message = "Device {} does not exist.".format(device_name)
            logger.critical(message)
            raise ValueError(message)
        elif len(found_devices) > 1:
            message = "Multiple devices with name '{}' found".format(device_name)
            logger.critical(message)
            raise ValueError(message)
        return found_devices[0]

    def get_generic_devices(self, domain_id=DEFAULT_DOMAIN_ID):
        """Get the list of generic devices

        :param domain_id: The ID of the domain
        :type domain_id: int|str
        :return: GenericDevicesList
        """
        logger.debug("Getting the list of the generic device for domain {}".format(domain_id))
        try:
            response_string = self.get_uri("/securetrack/api/generic_devices?context={}".format(domain_id),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to GET generic devices on domain {}.".format(domain_id)
            logger.critical(message)
            raise IOError(message)
        return GenericDevicesList.from_xml_string(response_string)

    def get_generic_device_by_name(self, generic_device_name, domain_id=DEFAULT_DOMAIN_ID):
        """Get generic device by name on specified domain

        :param generic_device_name: The name of the generic device
        :type generic_device_name: str
        :param domain_id: Domain ID of the generic device
        :type domain_id: int|str
        :return: GenericDevice
        """
        logger.debug("Getting generic device with name '{}' on domain {}".format(generic_device_name, domain_id))
        try:
            response_string = self.get_uri(
                    "/securetrack/api/generic_devices?name={}&context={}".format(generic_device_name, domain_id),
                    expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to GET generic device with name '{}' on domain {}.".format(generic_device_name, domain_id)
            logger.critical(message)
            raise IOError(message)
        try:
            return GenericDevicesList.from_xml_string(response_string)[0]
        except IndexError:
            msg = "Generic device with name '{}' on domain {} is not found".format(generic_device_name, domain_id)
            logger.error(msg)
            raise ValueError(msg)

    def add_offline_device(self, name, vendor, model, domain_id=None, domain_name="Default", topology="true",
                           offline="true"):
        """Add an offline device to SecureTrack.

        :param model: The model for the device that will be created. (see DEVICE_TYPES)
        :type model: str
        :param vendor: The vendor for the device that will be created. (see DEVICE_TYPES)
        :type vendor: str
        :param domain_id: The domain_id for the device that will be created.
        :type domain_id: str
        :param domain_name: The domain_name for the device that will be created.
        :type domain_name: str
        :param name: The name for the device that will be created.
        :type name: str
        :param offline: The offline flag for the device that will be created.
        :type offline: str
        :param topology: The topology flag for the device that will be created.
        :type topology: str
        :return: The ID of the created object .
        :rtype: int
        :raise ValueError: If the device could not be created.
        :raise IOError: If there was a communication problem while trying to create the device.
        """
        logger.info("Creating SecureTrack device.")
        if vendor not in DEVICE_TYPES:
            message = "Unknown vendor '{}'.".format(vendor)
            logger.error(message)
            raise ValueError(message)
        if model not in DEVICE_TYPES[vendor]:
            message = "Unknown model '{}' for vendor '{}'.".format(model, vendor)
            logger.error(message)
            raise ValueError(message)

        device = Device(model, vendor, domain_id, domain_name, None, name, offline, topology)
        try:
            response = self.post_uri("/securetrack/api/devices/", device.to_xml_string(), expected_status_codes=201)
            device_id = response.get_created_item_id()
            return device_id
        except RequestException:
            message = "Failed to create device."
            logger.critical(message)
            raise IOError(message)
        except REST_Bad_Request_Error as http_exception:
            message = "Could not create device, got error: '{}'".format(http_exception)
            logger.critical(message)
            raise ValueError(message)

    def upload_device_offline_config(self, device_id, conf_file_handle):
        """Upload configuration for a device that is marked as an offline device by ID.

        :param device_id: The device ID for which configuration will be uploaded.
        :type device_id: str|int
        :param conf_file_handle: The configuration file that will be uploaded for the specified device ID.
        :type conf_file_handle: An string containing the path to the configuration file.
        :raise ValueError: If there was a problem with the supplied parameters.
        :raise IOError: If there was a communication problem while trying to upload the offline device configuration.
        """
        logger.info("Uploading offline device configuration for device ID '%s'", device_id)
        multi_part_form_dict = {"device_id": str(device_id), "configuration_file": (
            conf_file_handle.name, conf_file_handle, "application/octet-stream")}
        try:
            response = self.post_uri("/securetrack/api/tasks/add_device_config_task",
                                     multi_part_form_params=multi_part_form_dict, expected_status_codes=201)
            logger.info("Upload successful.")
            config_upload_task_id = response.get_created_item_id()
            return config_upload_task_id
        except RequestException:
            message = "Failed to upload offline configuration for device ID {}".format(device_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Bad_Request_Error as http_exception:
            message = "Could not upload offline device configuration, got error: '{}'.".format(http_exception)
            logger.critical(message)
            raise ValueError(message)

    def get_shadowed_rules_for_device_by_id(self, device_id, start_rule_num=None, rule_count=None):
        """Get the shadowed rules for a device by ID.

        :type rule_count: int
        :type start_rule_num: int
        :param rule_count: How many rules to fetch.
        :param start_rule_num: The number of the first rule to fetch.
        :param device_id: The device ID for which the list of shadowed rules will be fetched.
        :type device_id: str|int
        :return: The list of shadowed rules for the device with the specified ID.
        :rtype: Cleanup_Set
        :raise ValueError: If there was a problem with the supplied parameters.
        :raise IOError: If there was a communication problem while trying to get the list of shadowed rules.
        """
        optional_params = [start_rule_num, rule_count]
        params_defined = [param is not None for param in optional_params]
        if any(params_defined) and not all(params_defined):
            raise ValueError("start_rule and rule_count must either be both set or both unset.")
        if start_rule_num is not None:
            logger.info("Getting shadowed rules for device ID '%s', start rule is '%s', rule count is '%s'", device_id,
                        start_rule_num, rule_count)
            params_string = "&start={}&count={}".format(start_rule_num, rule_count)
        else:
            params_string = ""
            logger.info("Getting shadowed rules for device ID '%s'", device_id)
        try:
            response_string = self.get_uri(
                    "/securetrack/api/devices/{}/cleanups?code=C01{}".format(device_id, params_string),
                    expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of shadowed rules for device ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        return Cleanup_Set.from_xml_string(response_string)

    def get_cleanups_for_device_by_id(self, device_id):
        """Get the cleanups for a device.

        :param device_id: The device ID or list of IDs for which to get the cleanups.
        :type device_id: int|list[int]|str
        :return: The list of shadowed rules for the device with the specified ID.
        :rtype: Generic_Cleanup_List
        :raise ValueError: If there was a problem with the supplied parameters.
        :raise IOError: If there was a communication problem while trying to get the list of shadowed rules.
        """
        if isinstance(device_id, list):
            device_id = ",".join(device_id)
        logger.info("Getting shadowed rules for device ID '%s'", device_id)
        try:
            response_string = self.get_uri("/securetrack/api/cleanups?devices={}".format(device_id),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of shadowed rules for device ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        return Generic_Cleanup_List.from_xml_string(response_string)

    def get_shadowing_rules_for_device_id_and_rule_uids(self, device_id, rule_uids):
        """Get the shadowing rules for a device.

        :param device_id: The device ID for which the list of shadowed rules will be fetched.
        :type device_id: int
        :param rule_uids: The UID of the rules for which to get shadowing rules.
        :type rule_uids: str|list[str]
        :return: The list of shadowed rules for the device with the specified ID.
        :rtype: Cleanup_Set
        :raise ValueError: If there was a problem with the supplied parameters.
        :raise IOError: If there was a communication problem while trying to get the list of shadowed rules.
        """
        logger.info("Getting shadowing rules for device ID '%s', UIDs are '%s'", device_id, rule_uids)
        if isinstance(rule_uids, list):
            rule_uids = ",".join(rule_uids)
        try:
            response_string = self.get_uri(
                    "/securetrack/api/devices/{}/shadowing_rules?shadowed_uids={}".format(device_id, rule_uids),
                    expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of shadowed rules for device ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        except REST_Request_URI_Too_Long:
            message = "Maximum URI length exceeded."
            logger.critical(message)
            raise REST_Request_URI_Too_Long(message, expected_status_code=200)
        return Cleanup_Set.from_xml_string(response_string)

    def get_devices_by_rule_search(self, search_text=None, context=None):
        """Get list of device that match to the search text based on the rule documentation

        :param search_text: dictionary of the search params
        :param context: Domain ID
        :return: List collection of effected devices
        """
        logger.info("Getting devices by: Search text: {}, context: {}".format(search_text, context))
        search_str = ""
        if search_text is not None:
            search_params = ",".join(["{}:{}".format(key, value) for key, value in search_text.items()])
            search_str = "search_text={}".format(search_params)
        context_str = "context={}".format(context) if context else ""
        url = "/securetrack/api/rule_search?{}{}".format(search_str, context_str)
        try:
            response_string = self.get_uri(url, expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get device list for search text: {} and context: {}".format(search_text, context)
            logger.critical(message)
            raise IOError(message)
        except REST_Bad_Request_Error:
            message = "Failed to find devices for search string '{}'".format(search_str)
            logger.critical(message)
            raise ValueError(message)
        return RuleSearchDeviceList.from_xml_string(response_string)

    def rule_search_for_device(self, device_id, search_text=None, context=None):
        """Find rules for device based on search input

        :param device_id:
        :param search_text: dictionary of the search params
        :type search_text: dict
        :param context: Domain ID
        :type context: int
        :return: The rules for device based on the search context
        :rtype: Rules_List
        """
        logger.info("Getting rules for device {}. Search text: {}, context: {}".format(device_id, search_text, context))
        search_text_string = ""
        context_string = ""
        if search_text:
            search_params = " ".join(["{}:{}".format(key, value) for key, value in search_text.items()])
            search_text_string = "search_text={}".format(search_params)
        if context:
            context_string = "context={}".format(context)
        url = "/securetrack/api/rule_search/{}?{}{}".format(device_id, search_text_string, context_string)
        try:
            response_string = self.get_uri(url, expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of rules" \
                      " for device ID {} with search text:" \
                      " {}, context: {}.".format(device_id, search_text, context)
            logger.critical(message)
            raise IOError(message)
        except REST_Bad_Request_Error:
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        return Rules_List.from_xml_string(response_string)

    def get_rules_for_device(self, device_id, get_documentation=False, custom_params=None):
        """Get the rules for a device.

        :param device_id: The device ID for which we want to get rules.
        :type device_id: int
        :param get_documentation: Whether or not we want to also get the documentation for the rule.
        :type get_documentation: bool
        :param custom_params: Dictionary from param name to value, eg {'policyId': 1}
        :type custom_params: dict
        :return: The rules for the specified device.
        :rtype: Rules_List
        :raise ValueError: If a device with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the rules.
        """

        logger.info("Getting rules for device with ID '%s'.", device_id)
        uri_suffix = ""
        lead_param = "?"
        if get_documentation:
            uri_suffix = "?add=documentation"
            lead_param = "&"
            logger.info("Getting rules with rule documentation.")

        if custom_params:
            params = '&'.join('{}={}'.format(k, v) for k, v in custom_params.items())
            uri_suffix += lead_param + params

        try:
            response_string = self.get_uri("/securetrack/api/devices/{}/rules{}".format(device_id, uri_suffix),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of rules for device ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        return Rules_List.from_xml_string(response_string)

    def get_rules_for_revision(self, revision_id, get_documentation=False):
        """Get the rules for a device.

        :param revision_id: The revision ID for which we want to get rules.
        :type revision_id: int
        :param get_documentation: Whether or not we want to also get the documentation for the rule.
        :type get_documentation: bool
        :return: The rules for the specified revision.
        :rtype: Rules_List
        :raise ValueError: If a revision with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the rules.
        """

        logger.info("Getting rules for revision with ID '%s'.", revision_id)
        rule_documentation_uri_suffix = ""
        if get_documentation:
            rule_documentation_uri_suffix = "?add=documentation"
            logger.info("Getting rules with rule documentation.")
        try:
            response_string = self.get_uri(
                    "/securetrack/api/revisions/{}/rules{}".format(revision_id, rule_documentation_uri_suffix),
                    expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of rules for revision ID {}.".format(revision_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Revision with ID {} does not exist.".format(revision_id)
            logger.critical(message)
            raise ValueError(message)
        return Rules_List.from_xml_string(response_string)

    def get_policies_for_revision(self, revision_id):
        """Get the policies for a revision.

        :param revision_id: The revision ID for which we want to get policies.
        :type revision_id: int
        :return: The policies for the specified revision.
        :rtype: Policy_List
        :raise ValueError: If a revision with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the rules.
        """

        logger.info("Getting policies for device with ID '%s'.", revision_id)
        try:
            response_string = self.get_uri("/securetrack/api/revisions/{}/policies".format(revision_id),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of policies for revision ID {}.".format(revision_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Revision with ID {} does not exist.".format(revision_id)
            logger.critical(message)
            raise ValueError(message)
        return Policy_List.from_xml_string(response_string)

    def get_policies_for_device(self, device_id):
        """Get the policies for a device.

        :param device_id: The device ID for which we want to get policies.
        :type device_id: int
        :return: The policies for the specified device.
        :rtype: Policy_List
        :raise ValueError: If a device with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the policies.
        """

        logger.info("Getting policies for device with ID '%s'.", device_id)
        device = self.get_device_by_id(device_id)
        if device.model == "module":
            return Policy_List([])
        try:
            response_string = self.get_uri("/securetrack/api/devices/{}/policies".format(device_id),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of policies for device ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        return Policy_List.from_xml_string(response_string)

    def get_bindings_for_device(self, device_id):
        """Get the bindings for a device.

        :param device_id: The device ID for which we want to get bindings.
        :type device_id: int
        :return: The bindings for the specified device.
        :rtype: Bindings_List
        :raise ValueError: If a device with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the bindings.
        """
        logger.info("Getting bindings for device with ID '%s'.", device_id)
        try:
            response_string = self.get_uri("/securetrack/api/devices/{}/bindings".format(device_id),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of bindings for device ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        return Bindings_List.from_xml_string(response_string)

    def get_interfaces_for_device(self, device_id):
        """Get the interfaces for a device.

        :param device_id: The device ID for which we want to get interfaces.
        :type device_id: int
        :return: The interfaces for the specified device.
        :rtype: Interfaces_List
        :raise ValueError: If a device with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the interfaces.
        """
        logger.info("Getting interfaces for device with ID '%s'.", device_id)
        try:
            response_string = self.get_uri("/securetrack/api/devices/{}/interfaces".format(device_id),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of bindings for device ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        return Interfaces_List.from_xml_string(response_string)

    def get_topology_interfaces(self, device_id):
        """Get the topology interfaces for a device

        :param device_id: The device ID for which we want to get interfaces.
        :type device_id: int
        :return: The topology interfaces for the specified device
        :rtype: Interfaces_List
        :raise ValueError: If a device with the specified ID dies not exist
        :raise IOError: If there was a communication problem trying to get the interfaces
        """
        logger.info("Getting topology interfaces for device with ID {}".format(device_id))
        try:
            response_string = self.get_uri("/securetrack/api/devices/topology_interfaces?mgmtId={}".format(device_id),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of the topology interfaces for device with ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exists.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        return Topology_Interfaces_List.from_xml_string(response_string)

    def get_generic_device_interfaces(self, device_id):
        """Get the topology interfaces for a generic device

        :param device_id: The device ID for which we want to get interfaces.
        :type device_id: int
        :return: The topology interfaces for the specified device
        :rtype: Interfaces_List
        :raise ValueError: If a device with the specified ID dies not exist
        :raise IOError: If there was a communication problem trying to get the interfaces
        """
        logger.info("Getting topology interfaces for device with ID {}".format(device_id))
        try:
            request_uri = "/securetrack/api/devices/topology_interfaces" \
                          "?genericDeviceId={}&mgmtId={}&is_generic=true".format(device_id, device_id)
            response_string = self.get_uri(request_uri, expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of the topology interfaces for device with ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exists.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        return Topology_Interfaces_List.from_xml_string(response_string)

    def get_policy_analysis(self, device_ids, sources="Any", destinations="Any", services="Any", exclude="", action=""):
        """Run policy analysis and return the associated devices and rules.

        :param device_ids: The device ID(s) for which we want to run policy analysis.
        :type device_ids: int|list[int]
        :param sources: The sources for the policy analysis.
        :type sources: str|list[str]
        :param destinations: The destinations for the policy analysis.
        :type destinations: str|list[str]
        :param services: The services (protocol and port)
        :type services: str|list[str]
        :param exclude: List of parameters where to exclude "Any" from search (e.g. : "service,source")
        :type exclude: str
        :param action: Filter action (e.g. "Allow", "Deny")
        :type action: str

        :return: The policy analysis result for the specified parameters.
        :rtype: Policy_Analysis_Query_Result
        :raise ValueError: If a device with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the policy analysis result.
        """
        if isinstance(device_ids, list):
            device_ids = ",".join([str(device_id) for device_id in device_ids])
        if isinstance(sources, list):
            sources = ",".join(sources)
        if isinstance(destinations, list):
            destinations = ",".join(destinations)
        if isinstance(services, list):
            services = ",".join(services)
        if exclude:
            exclude_string = "&exclude_any={}".format(exclude)
        else:
            exclude_string = ""
        if action:
            action_string = "&action={}".format(action)
        else:
            action_string = ""
        logger.info("Running policy analysis with the following parameters:"
                    "\nDevice IDs: %s\nSources: %s\nDestinations: %s\nServices: %s\nExclude: %s", device_ids, sources,
                    destinations, services, exclude)
        request_uri = "/securetrack/api/policy_analysis/query/matching_rules" \
                      "?device_ids={}&sources={}&destinations={}&services={}{}{}".format(device_ids, sources,
                                                                                         destinations, services,
                                                                                         exclude_string, action_string)
        try:
            response_string = self.get_uri(request_uri, expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to run policy analysis."
            logger.critical(message)
            raise IOError(message)
        return Policy_Analysis_Query_Result.from_xml_string(response_string)

    def get_network_objects_for_device(self, device_id):
        """Get the network objects for a device.

        :param device_id: The device ID for which we want to get network objects.
        :type device_id: int
        :return: The network objects for the specified device.
        :rtype: Network_Objects_List
        :raise ValueError: If a device with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the network objects.
        """
        logger.info("Getting network objects for device with ID %s.", device_id)
        try:
            response_string = self.get_uri("/securetrack/api/devices/{}/network_objects".format(device_id),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of rules for device ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        return Network_Objects_List.from_xml_string(response_string)

    def get_services_for_device(self, device_id):
        """Get the services for a device.

        :param device_id: The device ID for which we want to get services.
        :type device_id: int
        :return: The services for the specified device.
        :rtype: Services_List
        :raise ValueError: If a device with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the services.
        """
        logger.info("Getting services for device with ID '%s'.", device_id)
        try:
            response_string = self.get_uri("/securetrack/api/devices/{}/services".format(device_id),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of services for device ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        return Services_List.from_xml_string(response_string)

    def get_service_for_device_by_name(self, device_id, service_name):
        """Get the services for the device by device Id and service name

        :param device_id: The device ID for which we want to get services.
        :type device_id: int
        :param service_name: The name of the service to match
        :type service_name: str
        :return: The service with the name match
        :rtype: Single_Service| Group_Service
        :raise ValueError: If a device with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the services.
        """
        logger.info("Getting services for device with ID {} and service name '{}'".format(device_id, service_name))
        try:
            response_string = self.get_uri(
                    "/securetrack/api/devices/{}/services?name={}".format(device_id, service_name),
                    expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of services for device ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        try:
            service = Services_List.from_xml_string(response_string)[0]
        except IndexError:
            msg = "No service with name {} on device with ID {} was found".format(service_name, device_id)
            logger.error(msg)
            raise ValueError(msg)
        return service

    def get_security_policy_exceptions(self, domain_id=DEFAULT_DOMAIN_ID):
        logger.info("Getting security policy exceptions for domain id '{}'".format(domain_id))
        url = "/securetrack/api/security_policies/exceptions?context={}".format(domain_id)
        try:
            response_string = self.get_uri(url, expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of exceptions for domain ID {}.".format(domain_id)
            logger.critical(message)
            raise IOError(message)
        return SecurityPolicyExceptionList.from_xml_string(response_string)

    def get_security_policy_exception(self, exception_id, domain_id=DEFAULT_DOMAIN_ID):
        logger.info("Getting security policy exception id '{}' for domain id '{}'".format(exception_id, domain_id))
        url = "/securetrack/api/security_policies/exceptions/{}?context={}".format(exception_id, domain_id)
        try:
            response_string = self.get_uri(url, expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of exceptions for domain ID {}.".format(domain_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Exception with ID {} does not exist.".format(exception_id)
            logger.critical(message)
            raise ValueError(message)
        return Security_Policy_Exception.from_xml_string(response_string)

    def post_security_policy_exception(self, exception, domain_id=DEFAULT_DOMAIN_ID):
        """Create a new Unified Security Policy exception in SecureTrack.

        :param exception: The USP exception to create.
        :type exception: Security_Policy_Exception
        :return: The ID of the created exception.
        :rtype: int
        """
        logger.info("Posting new security policy exception.")
        uri = "/securetrack/api/security_policies/exceptions/?context={}".format(domain_id)
        try:
            response = self.post_uri(uri, exception.to_xml_string(),
                                     expected_status_codes=201)
            exception_id = response.get_created_item_id()
            logger.info("Created exception with ID '%s'", exception_id)
            return exception_id
        except RequestException:
            message = "Failed to create security policy exception."
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as client_error:
            message = "Failed to create security policy exception, error was '{}'.".format(client_error.message)
            logger.critical(message)
            raise ValueError(message)

    def delete_security_policy_exception(self, exception_id):
        """
        :param exception_id: Exception ID
        :type exception_id: int
        :return: 
        """
        logger.info("Deleting security policy exception id '{}'".format(exception_id))
        url = "/securetrack/api/security_policies/exceptions/{}".format(exception_id)
        try:
            self.delete_uri(url, expected_status_codes=[200, 204])
        except RequestException:
            message = "Failed to delete security policy exception with ID {}.".format(exception_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Security Policy Exception with ID {} doesn't exist.".format(exception_id)
            logger.critical(message)
            raise ValueError(message)
        return True

    def get_security_policies(self, domain_id=DEFAULT_DOMAIN_ID):
        """Get unified security policies from SecureTrack.

        :param domain_id: Get policies only for this domain.
        :type domain_id: int
        :return: List of policies
        :rtype: Security_Policies_List
        :raise IOError: If there was a communication problem trying to get the bindings.
        """
        logger.info("Getting security policies for domain ID %s.", domain_id)
        try:
            response_string = self.get_uri("/securetrack/api/security_policies?context={}".format(domain_id),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of security policies"
            logger.critical(message)
            raise IOError(message)
        return Security_Policies_List.from_xml_string(response_string)

    def get_security_policy_by_id(self, security_policy_id, context=DEFAULT_DOMAIN_ID):
        """Get Security Policy by ID from SecureTrack

        :param security_policy_id: ID of the Secure Policy
        :type security_policy_id: int
        :param context: Domain of the Security Policy
        :type context: int
        :return: Security Policy
        :rtype: Security_Policy
        :raise ValueError: If no policy with given name (and optionally context) is found
        :raise IOError: If there was communication error
        """
        logger.info("Searching for the security policy with ID {}".format(security_policy_id))
        security_policies = self.get_security_policies(context)
        try:
            return \
                [security_policy for security_policy in security_policies if security_policy.id == security_policy_id][
                    0]
        except IndexError:
            raise ValueError("No Security Policy with ID {} found".format(security_policy_id))

    def get_security_policy_by_name(self, security_policy_name, context=DEFAULT_DOMAIN_ID):
        """Get Security Policy by ID from SecureTrack

        :param security_policy_name: Name of the Security Policy
        :type security_policy_name: str
        :param context: Domain of the Security Policy
        :type context: int
        :return: Security Policy
        :rtype: Security_Policy
        :raise ValueError: If no policy with given name (and optionally context) is found
        :raise IOError: If there was communication error
        """
        logger.info("Searching for the security policy '{}'".format(security_policy_name))
        security_policies = self.get_security_policies(context)
        try:
            return [security_policy for security_policy in security_policies if
                    security_policy.name.lower() == security_policy_name.lower()][0]
        except IndexError:
            raise ValueError("No Security Policy '{}' found".format(security_policy_name))

    def get_security_policy_matrix_csv(self, security_policy_id):
        """Get CSV (file object) from SecureTrack for specified security policy

        :param security_policy_id: ID of the policy
        :type security_policy_id: int
        :return: File object containing CSV config of the matrix policy
        """
        logger.info("Getting CSV configuration of the Secure Policy with ID {}".format(security_policy_id))
        try:
            request = self.get_uri("/securetrack/api/security_policies/{}/export".format(security_policy_id),
                                   expected_status_codes=200)
        except RequestException:
            message = "Failed to get config of security policy."
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as client_error:
            message = "Failed to get config of security policy, error was '{}'.".format(client_error.message)
            logger.critical(message)
            raise ValueError(message)
        else:
            return request.response.content

    def post_security_policy_matrix(self, security_policy_name, security_policy):
        """Create a new Unified Security Policy in SecureTrack.

        :param security_policy_name: The name of the security policy to create.
        :type security_policy_name: str
        :param security_policy: The security policy to create.
        :type security_policy: str|dict
        :return: The ID of the created security policy.
        :rtype: int
        """

        def _create_csv_from_dict(security_policy_dict):
            csv_buffer = io.StringIO()
            csv_writer = csv.writer(csv_buffer)
            existing_zones = [zone.name for zone in self.get_zones()]
            valid_access_types = ("restricted", "blocked", "ignored")
            valid_severity_types = ("low", "medium", "high", "critical")
            csv_writer.writerow(("from zone", "to zone", "severity", "access type", "allowed services"))
            for from_zone in security_policy_dict:
                if from_zone not in existing_zones:
                    raise ValueError("Specified from_zone '{}' does not exist.".format(from_zone))
                for to_zone in security_policy_dict[from_zone]:
                    if to_zone not in existing_zones:
                        raise ValueError("Specified to_zone '{}' does not exist.".format(to_zone))
                    severity = security_policy_dict[from_zone][to_zone]["severity"]
                    if severity not in valid_severity_types:
                        raise (ValueError("Severity '{}' is not valid.".format(severity)))
                    access_type = security_policy_dict[from_zone][to_zone]["access_type"]
                    if access_type not in valid_access_types:
                        raise (ValueError("Access type '{}' is not valid.".format(access_type)))
                    allowed_services = security_policy_dict[from_zone][to_zone]["allowed_services"]
                    csv_writer.writerow([from_zone, to_zone, severity, access_type, allowed_services])
            return csv_buffer.getvalue()

        security_policy_buffer = io.StringIO()
        if isinstance(security_policy, dict):
            security_policy_buffer = _create_csv_from_dict(security_policy)
        elif isinstance(security_policy, (bytes, str)):
            try:
                security_policy_buffer.write(security_policy.decode())
            except AttributeError:
                security_policy_buffer.write(security_policy)
        else:
            raise ValueError("Unknown type '{}' for security policy.".format(type(security_policy)))
        multi_part_form_dict = {"security_policy_name": security_policy_name,
                                "file": ("security_policy", security_policy_buffer, "text/csv")}
        logger.info("Posting new security policy rule matrix.")
        try:
            response = self.post_uri("/securetrack/api/security_policies", multi_part_form_params=multi_part_form_dict,
                                     expected_status_codes=[201, 200])
            policy_id = response.get_created_item_id()
            logger.info("Created security policy with ID '%s'.", policy_id)
            return policy_id
        except RequestException as e:
            message = "Failed to create security policy, Error: '{}'".format(e)
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as client_error:
            message = "Failed to create security policy, error was '{}'.".format(client_error.message)
            logger.critical(message)
            raise ValueError(message)

    def delete_security_policy_matrix(self, security_policy_id):
        """Delete a security policy.

        :param security_policy_id: The ID of the security policy to delete.
        :type security_policy_id: int
        """
        logger.info("Deleting security policy rule matrix.")
        try:
            self.delete_uri("/securetrack/api/security_policies/{}".format(security_policy_id),
                            expected_status_codes=[200, 204])
        except RequestException:
            message = "Failed to delete security policy with ID {}.".format(security_policy_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Security Policy Matrix with ID {} doesn't exist.".format(security_policy_id)
            logger.critical(message)
            raise ValueError(message)
        return True

    def delete_zone_by_zone_id(self, zone_id, force_delete=False):
        """Delete a zone from SecureTrack.

        :param zone_id: The ID of the zone to delete.
        :type zone_id: int
        :param force_delete: Delete the zone even if it has entries.
        :type force_delete: bool
        :return:
        """
        if not force_delete and self.get_entries_for_zone_id(zone_id):
            raise AttributeError('Zone with ID {} has entries, not deleting'.format(zone_id))
        logger.info("Deleting Zone with ID {}.".format(zone_id))
        url = "/securetrack/api/zones/{}".format(zone_id)
        try:
            self.delete_uri(url, expected_status_codes=[200, 204])
        except RequestException:
            message = "Failed to delete zone with ID {}.".format(zone_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Zone with ID {} doesn't exist.".format(zone_id)
            logger.critical(message)
            raise ValueError(message)

    def put_rule_documentation_for_device(self, device_id, rule):
        """Update rule documentation for an existing rule.

        :param device_id: The ID of the device that the rule is associated with.
        :param rule: The rule containing the rule documentation.
        """
        logger.info("Updating rule documentation for rule ID '%s' under device ID '%s'.", rule.id, device_id)
        try:
            rule_documentation_xml = rule.documentation.to_xml_string().encode()
            response = self.put_uri("/securetrack/api/devices/{}/rules/{}/documentation".format(device_id, rule.id),
                                    rule_documentation_xml, expected_status_codes=[201, 204])
            documentation_id = response.get_created_item_id()
            return documentation_id
        except RequestException:
            message = "Failed to update rule documentation."
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error as not_found_error:
            message = "Failed to find device or rule, error was '{}'.".format(not_found_error.message)
            logger.critical(message)
            raise ValueError(message)
        except REST_HTTP_Exception as client_error:
            message = "Failed to update rule documentation, error was '{}'.".format(client_error.message)
            logger.critical(message)
            raise ValueError(message)

    def get_rule_documentation_by_device_id_and_rule_id(self, device_id, rule_id):
        """Get rule documentation information for specific device and rule

        :param device_id: The device ID for which we want to get the rule documentation.
        :type device_id: int
        :param rule_id: The ID of the rule for which we want to get the information.
        :type rule_id: int
        :return: A Rule_Documentation containing the information for required device and rule
        :rtype: Rule_Documentation
        :raise ValueError: If a device or rule with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the rule.
        """
        logger.info("Getting Rule Documentation for device ID {} for Rule ID {} .".format(device_id, rule_id))
        try:
            response_string = self.get_uri(
                    "/securetrack/api/devices/{}/rules/{}/documentation".format(device_id, rule_id),
                    expected_status_codes=200).response.content
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist OR Rule ID {} does not exist.".format(device_id, rule_id)
            logger.critical(message)
            raise ValueError(message)
        except RequestException:
            message = "Failed to GET device with ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        return Rule_Documentation.from_xml_string(response_string)

    def get_rule_base(self, get_documentation=False, device_ids=None):
        """Get the rules for each of the devices configured in SecureTrack.

        :type device_ids: collections.Iterable[int]
        :param device_ids: If specified, get the rule base only for the specified devices.
        :param get_documentation: Whether or not to get the rule documentation together with the rule base.
        :type get_documentation: bool
        :return: The rules for all the devices configured in SecureTrack.
        :rtype dict[int, Rules_List]
        """
        process_pool = multiprocessing.pool.ThreadPool(processes=Secure_Track_Helper.NUM_API_THREADS)
        if device_ids is None:
            device_list = self.get_devices_list()
        else:
            device_list = self._create_devices_list(device_ids)
        rule_base = {device.id: process_pool.apply_async(self.get_rules_for_device, args=(device.id, get_documentation))
                     for device in device_list}
        rule_base = {key: value.get() for key, value in rule_base.items()}
        return rule_base

    def get_revisions_base(self, device_ids=None):
        """Get the revisions for each of the devices configured in SecureTrack.

        :return: The revisions for all the devices configured in SecureTrack.
        :rtype: dict[Device, Device_Revisions_List]
        """
        process_pool = multiprocessing.pool.ThreadPool(processes=Secure_Track_Helper.NUM_API_THREADS)
        if device_ids is None:
            device_list = self.get_devices_list()
        else:
            device_list = self._create_devices_list(device_ids)
        revision_base = {device: process_pool.apply_async(self.get_device_revisions_by_id, args=(device.id,)) for device
                         in device_list}
        revision_base = {key: value.get() for key, value in revision_base.items()}
        return revision_base

    def _create_devices_list(self, device_ids):
        process_pool = multiprocessing.pool.ThreadPool(processes=Secure_Track_Helper.NUM_API_THREADS)
        devices = [process_pool.apply_async(self.get_device_by_id, args=(device_id,)) for device_id in device_ids]
        devices = [device.get() for device in devices]
        device_list = Devices_List(devices)
        return device_list

    def get_policies_base(self, devices=None):
        """Get the policies for each of the devices configured in SecureTrack.

        :return: The policies for all the devices configured in SecureTrack.
        :rtype: dict[Device, Policy_List]
        """
        process_pool = multiprocessing.pool.ThreadPool(processes=Secure_Track_Helper.NUM_API_THREADS)
        if devices is None:
            devices = self.get_devices_list()
        policy_base = {device: process_pool.apply_async(self.get_policies_for_device, args=(device.id,)) for device in
                       devices}
        policy_base = {key: value.get() for key, value in policy_base.items()}
        return policy_base

    def get_network_objects(self, device_ids=None):
        """Get the network objects for each of the devices configured in SecureTrack.

        :return: The network objects for all the devices configured in SecureTrack.
        :rtype: dict[int, Network_Objects_List]
        """
        process_pool = multiprocessing.pool.ThreadPool(processes=Secure_Track_Helper.NUM_API_THREADS)
        if device_ids is None:
            device_list = self.get_devices_list()
        else:
            device_list = self._create_devices_list(device_ids)
        network_objects = {device.id: process_pool.apply_async(self.get_network_objects_for_device, args=(device.id,))
                           for device in device_list}
        network_objects = {key: value.get() for key, value in network_objects.items()}
        return network_objects

    def get_zones(self, domain_id=DEFAULT_DOMAIN_ID):
        """Get the zones configured in SecureTrack.

        :param domain_id: return zones in this domain
        :type: int
        :return: The list of zones configured in SecureTrack.
        :rtype: Zone_List
        """
        logger.info("Getting SecureTrack Zones.")
        url = "/securetrack/api/zones?context={}".format(domain_id)
        try:
            response_string = self.get_uri(url, expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of zones."
            logger.critical(message)
            raise IOError(message)
        return Zone_List.from_xml_string(response_string)

    def get_zone_by_name(self, zone_name, case_sensitive=True):
        """Get a SecureTrack zone by name.

        :return: The matching SecureTrack zone.
        :rtype: Zone
        :raise: ValueError: If a zone with the specified name cannot be found.
        """
        zones = self.get_zones()
        for zone in zones:
            if case_sensitive:
                match = zone.name == zone_name
            else:
                match = zone.name.lower() == zone_name.lower()
            if match:
                return zone
        raise ValueError("Could not find a zone with the name '{}'.".format(zone_name))

    def get_zone_descendants(self, zone_ids, domain_id=DEFAULT_DOMAIN_ID):
        """Get the zones descendants.
        :param zone_ids: comma separated list of id, list of ids or single id
        :type: string, list
        :param domain_id: return zones in this domain
        :type: int
        :return: The list of zones configured in SecureTrack.
        :rtype: Zone_List
        """
        logger.info("Getting SecureTrack Zones descendants")
        if isinstance(zone_ids, list):
            zone_ids = ','.join(zone_ids)
        url = "/securetrack/api/zones/{}/descendants?context={}".format(zone_ids, domain_id)
        try:
            response_string = self.get_uri(url, expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of zones descendants"
            logger.critical(message)
            raise IOError(message)
        return ZoneDescendantsList.from_xml_string(response_string)

    def get_entries_for_zone_id(self, zone_id, domain_id=DEFAULT_DOMAIN_ID):
        """Get the zone entries for a zone by its ID.

        :param zone_id: The ID of the zone for
        :type zone_id: int
        :rtype: Zone_Entries_List
        """
        logger.info("Getting entries for zone with ID '%s'.", zone_id)
        try:
            response_string = self.get_uri("/securetrack/api/zones/{}/entries?context={}".format(zone_id, domain_id),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of entries for zone with ID {}.".format(zone_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Zone with ID {} does not exist.".format(zone_id)
            logger.critical(message)
            raise ValueError(message)
        return Zone_Entries_List.from_xml_string(response_string)

    def get_entries_for_zones(self, get_zones_as_object=False):
        """Get zone entries for each zone in SecureTrack.

        :return: All the entries of all zones in ST
        :rtype: dict{int: list[Zone_Entry]}
        """
        process_pool = multiprocessing.pool.ThreadPool(processes=Secure_Track_Helper.NUM_API_THREADS)
        zones_list = self.get_zones()
        if get_zones_as_object:
            zones_entries = {zone: process_pool.apply_async(self.get_entries_for_zone_id, args=(zone.id,)) for zone in
                             zones_list}
        else:
            zones_entries = {zone.id: process_pool.apply_async(self.get_entries_for_zone_id, args=(zone.id,)) for zone
                             in zones_list}
        zones_entries = {key: value.get() for key, value in zones_entries.items()}
        return zones_entries

    def import_zones_file(self, zone_file_data, domain_id=DEFAULT_DOMAIN_ID):
        """
        :param zone_file_data: The zone file to import.
        :type zone_file_data: str|bytes|_io.TextIOWrapper
        :param domain_id: The ID of the domain in which to import the zones.
        :type domain_id: int
        """
        logger.info("Importing zone file for context '%s'", domain_id)

        try:
            zone_file_data.seek(0)
        except AttributeError:
            pass
        else:
            zone_file_data = zone_file_data.read()
        multi_part_form_dict = {"import_file_input": ("zones.csv", zone_file_data, "application/force-download")}

        try:
            response = self.post_uri("/securetrack/api/zones/fileResponseAsString?context={}".format(domain_id),
                                     multi_part_form_params=multi_part_form_dict, expected_status_codes=200).response
            added_zones = response.json()["result"]["added_zones"]["zone"]
            illegal_lines = response.json()["result"]["illegal_lines"]
            status = response.json()["result"]["status"]
            return added_zones, illegal_lines, status
        except RequestException:
            message = "Failed to import zones file."
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as client_error:
            message = "Failed to import zones file, error was '{}'.".format(client_error.message)
            logger.critical(message)
            raise ValueError(message)

    def post_zone(self, zone, domain_id=DEFAULT_DOMAIN_ID):
        """
        :param zone: The zone to create.
        :type zone: Zone
        :param domain_id: The ID of the domain in which to create the zone.
        :type domain_id: int
        :return: The ID of the created zone.
        :rtype: int
        """
        logger.info("Adding new zone for context '%s'", domain_id)
        try:
            response = self.post_uri("/securetrack/api/zones?context={}".format(domain_id), zone.to_xml_string(),
                                     expected_status_codes=201)
            zone_id = response.get_created_item_id()
            logger.info("Created zone with ID '%s'.", zone_id)
            return zone_id
        except RequestException:
            message = "Failed to create zone."
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as client_error:
            message = "Failed to create zone, error was '{}'.".format(client_error.message)
            logger.critical(message)
            raise ValueError(message)

    def post_zone_entry(self, zone_id, zone_entry, domain_id=DEFAULT_DOMAIN_ID):
        """Create a new zone entry under an existing zone.

        :param zone_id: The ID of the zone under which to create the zone entry.
        :param zone_entry: The zone entry to create.
        :param domain_id: The ID of the domain in which to create the zone entry.
        :return: The ID of the created zone entry.
        :rtype: int
        """
        logger.info("Adding zone entry under zone ID '%s'", zone_id)
        try:
            response = self.post_uri("/securetrack/api/zones/{}/entries?context={}".format(zone_id, domain_id),
                                     zone_entry.to_xml_string(), expected_status_codes=201)
            entry_id = response.get_created_item_id()
            logger.info("Created zone entry with ID '%s'.", entry_id)
            return entry_id
        except RequestException:
            message = "Failed to create zone entry."
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error as not_found_error:
            message = "Failed to find zone, error was '{}'.".format(not_found_error.message)
            logger.critical(message)
            raise ValueError(message)
        except REST_Client_Error as client_error:
            # # TODO : work around if zone already exist we get an error instead
            message = "Failed to create zone entry, error was '{}'.".format(client_error.message)
            logger.critical(message)
            raise ValueError(message)

    def put_zone_entry(self, zone_id, zone_entry, domain_id=DEFAULT_DOMAIN_ID):
        """Modify an existing zone entry.

        :param zone_id: The ID of the zone under which to modify the zone entry.
        :type zone_id: int
        :param zone_entry: The zone entry to modify.
        :type zone_entry: Zone_Entry
        :param domain_id: The ID of the domain in which to modify the zone entry.
        :type domain_id: int
        """
        ZONE_ENTRY_EXISTS_MSG = "This zone entry already exists."
        logger.info("Modifying zone entry with ID '%s' under zone ID '%s'.", zone_entry.id, zone_id)
        try:
            self.put_uri("/securetrack/api/zones/{}/entries/{}?context={}".format(zone_id, zone_entry.id, domain_id),
                         zone_entry.to_xml_string(), expected_status_codes=[200, 204]).response.content
        except RequestException:
            message = "Failed to create zone entry."
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error as not_found_error:
            message = "Failed to find zone, error was '{}'.".format(not_found_error.message)
            logger.critical(message)
            raise ValueError(message)
        except REST_Client_Error as client_error:
            if client_error.message == ZONE_ENTRY_EXISTS_MSG:
                raise ItemAlreadyExists(client_error.message, [200, 204])
            message = "Failed to create zone entry, error was '{}'.".format(client_error.message)
            logger.critical(message)
            raise ValueError(message)
        return True

    def delete_zone_entry_by_zone_and_entry_id(self, zone_id, entry_id, domain_id=DEFAULT_DOMAIN_ID):
        """Delete an existing zone entry by its ID and the ID of its parent zone.

        :param zone_id: The ID of the zone under which to delete the zone entry.
        :type zone_id: int
        :param entry_id: The zone entry ID to delete.
        :type entry_id: int
        :param domain_id: The ID of the domain in which to delete the zone entry.
        :type domain_id: int
        """
        logger.info("Getting entries for zone with ID '%s'.", zone_id)
        try:
            self.delete_uri("/securetrack/api/zones/{}/entries/{}?context={}".format(zone_id, entry_id, domain_id),
                            expected_status_codes=[200, 204])
        except RequestException:
            message = "Failed to delete the entry with the ID {} under zone with ID {}.".format(entry_id, zone_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Entry with ID {} under zone with ID {} does not exist.".format(entry_id, zone_id)
            logger.critical(message)
            raise ValueError(message)
        return True

    def network_object_text_search(self, search_string, search_field, exact_match=False):
        """Search for network objects containing the specified string in the specified field.

        :param search_string: The text string to search for.
        :type search_string: str
        :param search_field: The field in which to search for the string.
            Can be one of the following:
             "ip": To search for the string in the network object's IP.
             "name": To search for the string in the network object's name.
             "comment": To search for the string in the network object's comment.
             "any_field": To search for the string in any of the network object's aforementioned fields.
        :type search_field: str
        :param exact_match: If set to True, only exact matches will be returned.
        :type exact_match: bool
        :return: The list of network objects matching the search string.
        :rtype: Network_Objects_List
        """
        valid_search_fields = ("ip", "name", "comment", "any_field")
        base_url = "/securetrack/api/network_objects/search?filter=text"
        if search_field not in valid_search_fields:
            raise ValueError("The specified search field '{}' is not valid. "
                             "Valid search fields are '{}'.".format(search_field, valid_search_fields))
        search_url = base_url + "&{}={}".format(search_field, search_string)
        if exact_match:
            search_url += "&exact_match=true"
        logger.info("Searching for network object with the string '%s' in %s field.", search_string, search_field)
        try:
            response = self.get_uri(search_url, expected_status_codes=200).response.content
        except RequestException as error:
            message = "Failed to search for network object, error was '{}'.".format(error)
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as client_error:
            message = "Failed to search for network object, error was '{}'.".format(client_error.message)
            logger.critical(message)
            raise ValueError(message)
        return Network_Objects_List.from_xml_string(response)

    def network_object_subnet_search(self, search_subnet, search_type):
        """Search for network objects with the specified subnet.

        :param search_subnet: The subnet to search for.
        :type search_subnet: str
        :param search_type: The field in which to search for the string.
            Can be one of the following:
             "contained_in": To search for network object that are contained in the specified subnet.
             "contains": To search for network object that contain the specified subnet.
             "exact_subnet": To search for network object that exactly match the specified subnet.
        :type search_type: str
        :return: The list of network objects matching the search subnet.
        :rtype: Network_Objects_List
        """
        valid_search_types = ("contained_in", "contains", "exact_subnet")
        base_url = "/securetrack/api/network_objects/search?filter=subnet"
        if search_type not in valid_search_types:
            raise ValueError("The specified search type '{}' is not valid. "
                             "Valid search types are '{}'.".format(search_type, valid_search_types))
        search_url = base_url + "&{}={}".format(search_type, search_subnet)
        logger.info("Searching for network object with the string '%s' in %s field.", search_subnet, search_type)
        try:
            response = self.get_uri(search_url, expected_status_codes=200).response.content
            return Network_Objects_List.from_xml_string(response)
        except RequestException as error:
            message = "Failed to search for network object, error was '{}'.".format(error)
            logger.critical(message)
            raise IOError(message)
        except REST_Client_Error as client_error:
            message = "Failed to search for network object, error was '{}'.".format(client_error.message)
            logger.critical(message)
            raise ValueError(message)

    def get_rules_for_network_object_by_id(self, network_object_id):
        """Get rules that refer a network object by it's ID.

        :type network_object_id: int
        :param network_object_id: The ID of the network object to search for.
        :rtype: Rules_List
        """
        logger.info("Getting rules for network object with ID %s.", network_object_id)
        try:
            response_string = self.get_uri("/securetrack/api/network_objects/{}/rules".format(network_object_id),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the rules for network object with ID {}.".format(network_object_id)
            logger.critical(message)
            raise IOError(message)
        return Rules_List.from_xml_string(response_string)

    def get_network_object_by_device_and_object_id(self, device_id, network_object_id):
        """Get the network objects for a device.

        :param device_id: The device ID for which we want to get network objects.
        :type device_id: int
        :param network_object_id: The ID of the network object
        :type network_object_id: int
        :return: The network objects for the specified device.
        :rtype: T <= Secure_App.XML_Objects.Base_Types.Network_Object
        :raise ValueError: If a device with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the network objects.
        """
        logger.info("Getting network object with ID %s for device %s.", network_object_id, device_id)
        try:
            response_string = self.get_uri(
                    "/securetrack/api/devices/{}/network_objects/{}".format(device_id, network_object_id),
                    expected_status_codes=200).response.content
            network_object = Network_Objects_List.from_xml_string(response_string)[0]
        except RequestException:
            message = "Failed to get the list of rules for device ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        except (REST_Not_Found_Error, IndexError):
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        if network_object.device_id is None:
            network_object.device_id = device_id
        return network_object

    def get_member_network_objects_for_group_network_object(self, group_network_object, device_id,
                                                            get_nested_members=True, device_network_objects=None):
        """Get member objects for a group network object.

        :type device_network_objects: dict[int,T <= Secure_Track.XML_Objects.Base_Types.Network_Object]
        :param device_network_objects: The network objects in the device containing the group network object.
        :param get_nested_members: Get members from the device recursively.
        :type device_id: int
        :param device_id: The ID of the device containing the group network object.
        :param group_network_object:
        :type group_network_object: Secure_Track.XML_Objects.REST.Rules.Group_Network_Object
        :return:
        """
        logger.info("Getting member network objects for network object with ID %s.", group_network_object.id)
        network_objects = []
        if device_network_objects is None:
            device_network_objects = {network_object.id: network_object for network_object in
                                      self.get_network_objects_for_device(device_id)}
        for member in group_network_object.members:
            try:
                item = device_network_objects[member.id]
            except KeyError:
                logger.error("Did not find member ID {} - {} in device {}'s network objects".format(member.id,
                                                                                                    member.display_name,
                                                                                                    device_id))
                continue
            try:
                for member_object in item.members:
                    member_object.device_id = group_network_object.device_id
            except AttributeError:
                pass
            else:
                logger.debug("Set device ID for member network objects to '%s'.", group_network_object.device_id)
            if get_nested_members:
                logger.debug("Getting nested member objects for network object with ID '%s'.", item.id)
                try:
                    member_objects = self.get_member_network_objects_for_group_network_object(item, device_id,
                                                                                              get_nested_members,
                                                                                              device_network_objects)
                    network_objects.extend(member_objects)
                except AttributeError:
                    network_objects.append(item)
            else:
                network_objects.append(item)
        return network_objects

    def get_service_by_device_and_object_id(self, device_id, service_id):
        """Get the network objects for a device.

        :param device_id: The device ID for which we want to get network objects.
        :type device_id: int
        :param service_id: The ID of the service
        :type service_id: int
        :return: The service for the specified device with the specified ID.
        :rtype: Single_Service|Group_Service
        :raise ValueError: If a device with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the network objects.
        """
        service_id = int(service_id)
        logger.info("Getting service with ID %s for device %s.", service_id, device_id)
        try:
            response_string = self.get_uri("/securetrack/api/devices/{}/services/{}".format(device_id, service_id),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the service with ID {} for device ID {}.".format(service_id, device_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)

        # FIXME: Actually returns also members of group if they are part of it, meanwhile filter by ID
        # return Services_List.from_xml_string(response_string)[0]
        try:
            return Services_List([service for service in Services_List.from_xml_string(response_string) if
                                  service.id == service_id])[0]
        except IndexError:
            message = "Service with ID {} does not exist on device with ID {}".format(service_id, device_id)
            logger.critical(message)
            raise ValueError(message)

    def get_member_services_for_group_service(self, group_service, device_id, get_nested_members=True,
                                              device_services=None):
        """Get member servers for a group service.

        :type device_services: dict[int,T <= Secure_Track.XML_Objects.Base_Types.Service]
        :param device_services: The services in the device containing the group service.
        :param get_nested_members: Get members from the device recursively.
        :type device_id: int
        :param group_service:
        :type group_service: Group_Service
        :return: List of services
        :rtype: list
        """
        logger.info("Getting member services for service with ID %s.", group_service.id)
        services = []
        if device_services is None:
            device_services = {service.id: service for service in self.get_services_for_device(device_id)}
        for member in group_service.members:
            member = device_services[member.id]
            if hasattr(member, "members"):
                if get_nested_members:
                    logger.debug("Getting nested services for service with ID '%s'.", member.id)
                    services.extend(self.get_member_services_for_group_service(member, device_id, get_nested_members,
                                                                               device_services))
                else:
                    services.append(member)
            else:
                services.append(member)
        return services

    def get_change_authorization_status(self, old_revision_id, new_revision_id, show_traffic_details=False,
                                        ignore_tickets=False):
        """Get the change authorization status between the specified old and new revisions.

        :param old_revision_id: The old revision ID.
        :type old_revision_id: int
        :param new_revision_id: The new revision ID.
        :type new_revision_id: int
        :param show_traffic_details: Return unauthorized traffic change details for all modified rules.
        :type show_traffic_details: bool
        :param ignore_tickets: Ignore SecureChange tickets and consider all traffic changes unauthorized.
        :type ignore_tickets: bool
        :return: The change authorization status for the specified revisions.
        :rtype: Change_Authorization
        """
        logger.info("Getting change authorization status between revision ID %s and %s.", old_revision_id,
                    new_revision_id)
        uri = "/securetrack/api/change_authorization/?old_version={}&new_version={}".format(old_revision_id,
                                                                                            new_revision_id)
        if show_traffic_details:
            uri += "&traffic_details=true"
        if ignore_tickets:
            uri += "&ignore_tickets=true"
        try:
            response_string = self.get_uri(uri, expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get authorization status between revision ID %s and %s.".format(old_revision_id,
                                                                                                 new_revision_id)
            logger.critical(message)
            raise IOError(message)
        else:
            return Change_Authorization.from_xml_string(response_string)

    def get_revision_by_id(self, revision_id):
        """Get a SecureTrack device revision by ID.

        :param revision_id: The ID  of the revision we want to get.
        :type revision_id: int
        :return: The revision with the specified ID.
        :rtype: Device_Revision
        :raise ValueError: If a revision with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the revision.
        """
        logger.info("Getting SecureTrack revision with ID %s.", revision_id)
        try:
            response_string = self.get_uri("/securetrack/api/revisions/{}".format(revision_id),
                                           expected_status_codes=200).response.content
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist.".format(revision_id)
            logger.critical(message)
            raise ValueError(message)
        except RequestException:
            message = "Failed to get revision with ID {}.".format(revision_id)
            logger.critical(message)
            raise IOError(message)
        return Device_Revision.from_xml_string(response_string)

    def get_domains(self):
        """Get the list of domains from SecureTrack.

        :return: Available domains
        :rtype: Domains
        """
        logger.info("Getting domains from SecureTrack")
        try:
            response_string = self.get_uri("/securetrack/api/domains", expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get domains"
            logger.critical(message)
            raise IOError(message)
        return Domains.from_xml_string(response_string)

    def get_domain_by_id(self, domain_id):
        """Get a domain by ID from SecureTrack.

        :param domain_id: the Id of the domain
        :type domain_id: int
        :return: Domain information
        :rtype: Domain
        """
        logger.info("Getting domain with ID {}".format(domain_id))
        try:
            response_string = self.get_uri("/securetrack/api/domains/{}".format(domain_id),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get domain with ID {}".format(domain_id)
            logger.critical(message)
            raise ValueError(message)
        return Domain.from_xml_string(response_string)

    def get_security_policy_device_violations_by_severity(self, device_id, severity, policy_type=None):
        logger.info("Getting rule violation by device id '{}' and severity '{}'".format(device_id, severity))
        parameters = "severity={}".format(severity) if policy_type is None else "type={}&severity={}".format(
                policy_type, severity)
        url = "/securetrack/api/violating_rules/{}/device_violations?{}".format(device_id, parameters)
        try:
            response_string = self.get_uri(url, expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the rules for network object with ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        return SecurityPolicyDeviceViolations.from_xml_string(response_string)

    def get_security_policy_violations_for_all_devices(self, cp_types_to_exclude=None, thread_count=None):
        """Returns a dictionary with all the devices and their violations

        :param cp_types_to_exclude: list/tuple of cp_types to exclude
        :type cp_types_to_exclude: list/tuple
        :return: dictionary of the form {device -> {severity: [violations]}}
        :rtype: dict[Device,dict[str,SecurityPolicyDeviceViolations]
        """
        if thread_count is None:
            thread_count = multiprocessing.cpu_count()
        process_pool = multiprocessing.pool.ThreadPool(processes=thread_count)
        severity_levels_list = tuple(level.value for level in Elements.SeverityLevels)
        devices_list = self.get_devices_list()

        if cp_types_to_exclude:
            devices_list = [device for device in devices_list if device.model not in cp_types_to_exclude]

        violations = {}
        for device in devices_list:
            violations[device] = {}
            for severity in severity_levels_list:
                violations[device][severity] = process_pool.apply_async(
                        self.get_security_policy_device_violations_by_severity, args=(device.id, severity),
                        kwds={'policy_type': 'SECURITY_POLICY'})

        for device, violations_dict in violations.items():
            for severity, violations_results in violations_dict.items():
                try:
                    violations[device][severity] = violations_results.get()
                except REST_Internal_Server_Error:
                    violations[device][severity] = None

        return violations

    def dereference_rule(self, rule, device_id=None):
        """Convert the object references in a Rule to the actual objects.

        :type device_id: int
        :param device_id: The ID of the device that contains the rule. If not specified, taken from the rule itself.
        :type rule: Secure_Track.XML_Objects.REST.Rules.Rule
        :rtype Secure_Track.XML_Objects.REST.Rules.Rule
        """
        if device_id is None:
            device_id = rule.device_id
        logger.info("De-referencing rule for device ID %s.", device_id)
        src_network_object_ids = [src.id for src in rule.src_networks]
        dst_network_object_ids = [dst.id for dst in rule.dst_networks]
        network_objects = self.get_network_objects_by_device_and_object_ids(device_id, set(
                itertools.chain(src_network_object_ids, dst_network_object_ids)))
        network_object_id_to_network_objects = {network_object.id: network_object for network_object in network_objects}

        service_ids = [srv.id for srv in rule.dst_services]
        services = self.get_services_by_device_and_object_ids(device_id, service_ids)
        service_id_to_service = {service.id: service for service in services}
        rule.src_networks = [network_object_id_to_network_objects[src_id] for src_id in src_network_object_ids]
        rule.dst_networks = [network_object_id_to_network_objects[dst_id] for dst_id in dst_network_object_ids]
        rule.dst_services = [service_id_to_service[service_id] for service_id in service_ids]
        return rule

    def dereference_rule_list(self, rule_list, device_id=None):
        """Convert the object references in each Rule in a Rules_List to the actual objects.
        This method assumes that all the rules in the list are from the same device.

        :type device_id: int
        :param device_id: The ID of the device that contains the rules. If not specified, taken from the first rule.
        :type rule_list: Secure_Track.XML_Objects.REST.Rules.Rules_List|XML_List[Rule]
        :rtype: Secure_Track.XML_Objects.REST.Rules.Rules_List
        """
        if device_id is None:
            device_id = rule_list[0].device_id
        logger.info("De-referencing rules for device ID %s.", device_id)
        rule_to_src_ids = {}
        rule_to_dst_ids = {}
        rule_to_srv_ids = {}
        for rule in rule_list:
            rule_to_src_ids[rule] = [src.id for src in rule.src_networks]
            rule_to_dst_ids[rule] = [dst.id for dst in rule.dst_networks]
            rule_to_srv_ids[rule] = [srv.id for srv in rule.dst_services]
        network_objects = self.get_network_objects_by_device_and_object_ids(device_id, set(
                itertools.chain(itertools.chain.from_iterable(rule_to_src_ids.values()),
                                itertools.chain.from_iterable(rule_to_dst_ids.values()))))
        network_object_id_to_network_objects = {network_object.id: network_object for network_object in network_objects}
        services = self.get_services_by_device_and_object_ids(device_id, set(rule_to_srv_ids.values()))
        service_id_to_service = {service.id: service for service in services}
        for index, rule in enumerate(rule_list):
            rule.src_networks = [network_object_id_to_network_objects[src_id] for src_id in rule_to_src_ids[rule]]
            rule.dst_networks = [network_object_id_to_network_objects[dst_id] for dst_id in rule_to_dst_ids[rule]]
            rule.dst_services = [service_id_to_service[service_id] for service_id in rule_to_srv_ids[rule]]
            rule_list[index] = rule
        return rule_list

    def get_services_by_device_and_object_ids(self, device_id, service_ids):
        """Get the network objects for a device.

        :param device_id: The device ID for which we want to get network objects.
        :type device_id: int
        :param service_ids: The ID of the service
        :type service_ids: int|collections.Iterable[int]
        :return: The service for the specified device with the specified ID.
        :rtype: Single_Service|Group_Service
        :raise ValueError: If a device with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the network objects.
        """
        if isinstance(service_ids, collections.Iterable):
            service_ids = ",".join([str(service_id) for service_id in service_ids])
        logger.info("Getting service with ID %s for device %s.", service_ids, device_id)
        try:
            response_string = self.get_uri("/securetrack/api/devices/{}/services/{}".format(device_id, service_ids),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the service with ID {} for device ID {}.".format(service_ids, device_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        else:
            return Services_List.from_xml_string(response_string)

    def get_services_by_revision_and_object_ids(self, revision_id, service_ids=""):
        """Get the services for a revision.

        :param revision_id: The revision ID for which we want to get network objects.
        :type revision_id: int
        :param service_ids: The ID of the service
        :type service_ids: int|collections.Iterable[int]
        :return: The service for the specified revision with the specified ID.
        :rtype: Services_List
        :raise ValueError: If a revision with the specified ID does not exist.
        :raise IOError: If there was a communication problem trying to get the services.
        """
        if isinstance(service_ids, collections.Iterable):
            service_ids = ",".join([str(service_id) for service_id in service_ids])
        logger.info("Getting service with ID %s for revision %s.", service_ids, revision_id)
        try:
            response_string = self.get_uri("/securetrack/api/revisions/{}/services/{}".format(revision_id, service_ids),
                                           expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the service with ID {} for revision ID {}.".format(service_ids, revision_id)
            logger.critical(message)
            raise IOError(message)
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist.".format(revision_id)
            logger.critical(message)
            raise ValueError(message)
        else:
            return Services_List.from_xml_string(response_string)

    def get_network_objects_by_revision_and_object_ids(self, revision_id, network_object_ids=""):
        """Get the network objects for a device.

        :param revision_id: The revision ID for which we want to get network objects.
        :type revision_id: int
        :param network_object_ids: The ID of the network object to get
        :type network_object_ids: int|collections.Iterable[int]
        :return: The network objects for the specified revision.
        :rtype: Network_Objects_List
        :raise ValueError: If a revision with the specified ID does not exist.
        :raise IOError: Ifp there was a communication problem trying to get the network objects.
        """
        logger.info("Getting network object with ID %s for revision %s.", network_object_ids, revision_id)
        if isinstance(network_object_ids, collections.Iterable):
            network_object_ids = ",".join([str(network_object_id) for network_object_id in network_object_ids])
        try:
            response_string = self.get_uri(
                    "/securetrack/api/revisions/{}/network_objects/{}".format(revision_id, network_object_ids),
                    expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of rules for revision ID {}.".format(revision_id)
            logger.critical(message)
            raise IOError(message)
        except (REST_Not_Found_Error, IndexError):
            message = "Revision with ID {} does not exist.".format(revision_id)
            logger.critical(message)
            raise ValueError(message)
        return Network_Objects_List.from_xml_string(response_string)

    def get_network_objects_by_device_and_object_ids(self, device_id, network_object_ids):
        """Get the network objects for a device.

        :param device_id: The device ID for which we want to get network objects.
        :type device_id: int
        :param network_object_ids: The ID of the network object to get
        :type network_object_ids: int|collections.Iterable[int]
        :return: The network objects for the specified device.
        :rtype: Network_Objects_List
        :raise ValueError: If a device with the specified ID does not exist.
        :raise IOError: Ifp there was a communication problem trying to get the network objects.
        """
        logger.info("Getting network object with ID %s for device %s.", network_object_ids, device_id)
        if isinstance(network_object_ids, collections.Iterable):
            network_object_ids = ",".join([str(network_object_id) for network_object_id in network_object_ids])
        try:
            response_string = self.get_uri(
                    "/securetrack/api/devices/{}/network_objects/{}".format(device_id, network_object_ids),
                    expected_status_codes=200).response.content
        except RequestException:
            message = "Failed to get the list of rules for device ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        except (REST_Not_Found_Error, IndexError):
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        return Network_Objects_List.from_xml_string(response_string)

    def __get_device_to_id(self, devices):
        if devices is None:
            device_id_to_device = {device.id: device for device in self.get_devices_list()}
        else:
            device_id_to_device = {device.id: device for device in devices}
        return device_id_to_device

    def get_latest_ready_revision_for_device_id(self, device_id):
        """Get the latest ready for the specified device ID.

        :param device_id: The device ID for which to get the latest specified revision.
        :type device_id: int|str
        :return: The latest ready revision for the device.
        :rtype: Device_Revision
        :raise ValueError: If the device has not ready revisions.
        """
        revisions = self.get_device_revisions_by_id(device_id)
        revisions.sort()
        for revision in revisions:
            if revision.is_ready():
                return revision
        raise ValueError("No ready revisions for device with ID {}.".format(device_id))

    def get_latest_revision_for_device_id(self, device_id):
        """Get the latest revision for device

        :param device_id: The device ID for which we want to get the latest revision
        :type device_id: str|int
        return: The latest revision for the device
        :rtype: Device_Revision
        :raise ValueError: If no revision was found
        :raise IOError: API call failed
        """
        logger.info("Getting SecureTrack latest revision for device with ID %s.", device_id)
        try:
            response_string = self.get_uri("/securetrack/api/devices/{}/latest_revision/".format(device_id),
                                           expected_status_codes=200).response.content
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist or has no revisions.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        except RequestException:
            message = "Failed to GET latest revision for the device with ID {}.".format(device_id)
            logger.critical(message)
            raise IOError(message)
        return Device_Revision.from_xml_string(response_string)

    def get_device_generic_config_by_id(self, device_id):

        """Get the generic device configuration for a device.

        :param device_id: The device ID for which the generic configuration will be created.
        :rtype: config
        """
        vrf_id_to_name = self.get_device_virtual_routers(device_id)
        interfaces = self.get_device_generic_interfaces(device_id, vrf_id_to_name)
        routes = self.get_device_generic_routes(device_id, vrf_id_to_name)
        device_config = config(interfaces, routes)
        return device_config

    def add_contexts_for_device(self, device_id, device_tree, domain_id=DEFAULT_DOMAIN_ID):
        """Import child devices from parent device.

        :type domain_id: int
        :type device_id: int
        :type device_tree: DeviceTree
        """

        def _prepare_device_for_import(device_to_prepare):
            if device_to_prepare is None:
                return
            if not device_to_prepare.is_imported():
                device_to_prepare.allow_import = 1
            for child in device_to_prepare.children:
                _prepare_device_for_import(child)

        logger.info("Adding contexts for device with ID %s.", device_id)
        for device in device_tree.children:
            _prepare_device_for_import(device)
        return self._set_configuration(device_id, full_xml_set=device_tree.to_xml_string(), action="add_contexts",
                                       domain_id=domain_id)

    def get_internet_referral_object_for_device_id(self, device_id):
        """Get the internet referral object for StoneSoft (except master engine) or Check Point SMC/CMA devices.

        :rtype: InternetReferralObject
        :type device_id: int
        """
        logger.info("Getting internet referral object for SecureTrack device with ID %s", device_id)
        uri = "/securetrack/api/internet_referral/{}".format(device_id)
        try:
            response = self.get_uri(uri, 200).response.content
        except RequestException as error:
            message = "Failed to get internet referral object for device. Error: {}".format(error)
            logger.critical(message)
            raise IOError(message)
        return InternetReferralObject.from_xml_string(response)

    def set_internet_referral_object_for_device_id(self, device_id, internet_referral_object):
        """Set the internet referral object for StoneSoft (except master engine) or Check Point SMC/CMA devices.

        :type internet_referral_object: InternetReferralObject
        :type device_id: int
        """
        logger.info("Setting internet referral object for SecureTrack device with ID %s", device_id)
        uri = "/securetrack/api/internet_referral/{}".format(device_id)
        try:
            self.put_uri(uri, internet_referral_object.to_xml_string(), expected_status_codes=200).response.content
        except RequestException as error:
            message = "Failed to set internet referral object for device. Error: {}".format(error)
            logger.critical(message)
            raise IOError(message)

    def get_device_routes(self, device_id, is_generic=None, start=None, count=None):
        """Get the list of device routes from SecureTrack.

        :return: list of available routes
        :rtype: RoutesList
        """
        logger.info("Getting device routes from SecureTrack")
        device_route_uri_suffix = ""
        if is_generic:
            device_route_uri_suffix += "&is_generic={}".format(is_generic)
        if start and count:
            device_route_uri_suffix += "&start={}&count={}".format(start, count)
        try:
            response_string = self.get_uri(
                "/securetrack/api/devices/topology_routes?mgmtId={}{}".format(device_id, device_route_uri_suffix),
                expected_status_codes=200).response.content
        except REST_Not_Found_Error:
            message = "Device with ID {} does not exist.".format(device_id)
            logger.critical(message)
            raise ValueError(message)
        except RequestException:
            message = "Failed to get routes for device id '{}'".format(device_id)
            logger.critical(message)
            raise IOError(message)
        return RoutesList.from_xml_string(response_string)
