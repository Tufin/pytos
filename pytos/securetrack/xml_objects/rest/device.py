
import logging
from datetime import datetime

from pytos.common.base_types import XML_Object_Base, XML_List, Comparable
from pytos.common.definitions import xml_tags
from pytos.common.functions import str_to_bool, XML_LOGGER_NAME
from pytos.common.functions.xml import get_xml_text_value, get_xml_int_value

logger = logging.getLogger(XML_LOGGER_NAME)


class Device(XML_Object_Base, Comparable):
    def __init__(self, model, vendor, domain_id, domain_name, num_id, name, offline, topology=None, ip=None,
                 virtual_type=None):
        self.model = model
        self.vendor = vendor
        self.domain_name = domain_name
        self.domain_id = domain_id
        self.id = num_id
        self.name = name
        self.offline = offline
        self.topology = topology
        self.ip = ip
        self.virtual_type = virtual_type
        self._config = None
        self._children = []
        self._parent = None
        super().__init__(xml_tags.Elements.DEVICE)

    def _key(self):
        return self.id, self.name

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        model = get_xml_text_value(xml_node, xml_tags.Elements.MODEL)
        num_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        domain_id = get_xml_int_value(xml_node, xml_tags.Elements.DOMAIN_ID)
        domain_name = get_xml_text_value(xml_node, xml_tags.Elements.DOMAIN_NAME)
        vendor = get_xml_text_value(xml_node, xml_tags.Elements.VENDOR)
        topology = get_xml_text_value(xml_node, xml_tags.Elements.TOPOLOGY)
        offline = get_xml_text_value(xml_node, xml_tags.Elements.OFFLINE)
        ip = get_xml_text_value(xml_node, xml_tags.Elements.IP)
        return cls(model, vendor, domain_id, domain_name, num_id, name, offline, topology, ip)

    @classmethod
    def from_db_device(cls, db_device, domain_name):
        return cls(db_device.cp_type, db_device.management_type, db_device.customer_id, domain_name,
                   db_device.management_id, db_device.management_name, db_device.is_offline,
                   topology=db_device.has_topology, virtual_type=db_device.virtual_type)

    def set_config(self, config):
        """

        :type config: str
        """
        self._config = config

    def get_config(self):
        return self._config

    def get_parent(self):
        return self._parent

    def get_parents_recursive(self):
        if self._parent is not None:
            parents = [self._parent]
            parents.extend(self._parent.get_parents_recursive())
            return parents
        else:
            return []

    def has_children(self):
        return bool(self._children)

    def get_children(self):
        return self._children

    def set_parent(self, parent):
        """

        :type parent: Device
        """
        self._parent = parent

    def set_children(self, children):
        """

        :type children: list[Device]|Devices_List
        """
        self._children = children

    def add_child(self, child):
        self._children.append(child)

    def __repr__(self):
        return "Device('{}','{}','{}','{}','{}','{}','{}','{}','{}',{})".format(self.model, self.vendor, self.domain_id,
                                                                                self.domain_name, self.id, self.name,
                                                                                self.offline, self.topology, self.ip,
                                                                                self._children)


class Devices_List(XML_List):
    """
    :type devices: list[Device]
    """

    def __init__(self, devices, total=None):
        self.count = len(devices)
        self.total = total
        super().__init__(xml_tags.Elements.DEVICES, devices)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        devices = []
        for device_node in xml_node.iter(tag=xml_tags.Elements.DEVICE):
            devices.append(Device.from_xml_node(device_node))
        total = get_xml_int_value(xml_node, xml_tags.Elements.TOTAL)
        return cls(devices, total)

    def extend(self, iterable):
        super().extend(iterable)
        self.count += iterable.count


class GenericDevice(XML_Object_Base):
    def __init__(self, device_id, device_name, domain_id):
        self.id = device_id
        self.name = device_name
        self.customer_id = domain_id
        super().__init__(xml_tags.Elements.DEVICE)

    @classmethod
    def from_xml_node(cls, xml_node):
        device_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        device_name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        domain_id = get_xml_int_value(xml_node, xml_tags.Elements.CUSTOMER_ID)
        return cls(device_id, device_name, domain_id)


class GenericDevicesList(XML_List):
    def __init__(self, generic_devices):
        """Initialize the object from parameters."""
        super().__init__(xml_tags.Elements.GENERIC_DEVICES, generic_devices)

    @classmethod
    def from_xml_node(cls, xml_node):
        generic_devices = []
        for generic_device_node in xml_node.iter(tag=xml_tags.Elements.DEVICE):
            generic_devices.append(GenericDevice.from_xml_node(generic_device_node))
        return cls(generic_devices)


class Device_Revisions_List(XML_List):
    """
    :type revisions: list[Device_Revision]
    """

    def __init__(self, revisions):
        super().__init__(xml_tags.Elements.REVISIONS, revisions)
        self.sort()

    @classmethod
    def from_xml_node(cls, xml_node=None):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        revisions = []
        for revision_node in xml_node.iter(tag=xml_tags.Elements.REVISION):
            revisions.append(Device_Revision.from_xml_node(revision_node))
        return cls(revisions)

    def sort(self):
        self.set_contents(sorted(self.get_contents(), key=lambda revision: revision.revisionId))

    def get_latest_revision(self):
        if self.get_contents():
            self.sort()
            return self[-1]
        else:
            message = "Revision list is empty."
            logger.error(message)
            raise ValueError(message)


class Device_Revision(XML_Object_Base):
    AUTHORIZED_STATUSES = ("AUTOMATICALLY_AUTHORIZED", "MANUALLY_AUTHORIZED")
    UNAUTHORIZED_STATUSES = ("AUTOMATICALLY_UNAUTHORIZED", "MANUALLY_UNAUTHORIZED")
    OTHER_STATUSES = ("N_A", "CALCULATING", "ERROR", "PENDING")
    REVISION_DATE_FORMAT_STRING = "%Y-%m-%d"
    REVISION_TIME_FORMAT_STRING = "%H:%M:%S.%f"

    def __init__(self, action, num_id, admin, auditLog, authorizationStatus, revision_date, revision_time, gui_client,
                 revision_id, modules_and_policy, policy_package, ready):
        self.action = action
        self.admin = admin
        self.auditLog = auditLog
        self.authorizationStatus = authorizationStatus
        self.date = revision_date
        self.guiClient = gui_client
        self.id = num_id
        self.modules_and_policy = modules_and_policy
        self.policyPackage = policy_package
        self.revisionId = revision_id
        self.time = revision_time
        self.ready = ready
        super().__init__(xml_tags.Elements.REVISION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        action = get_xml_text_value(xml_node, xml_tags.Elements.ACTION)
        admin = get_xml_text_value(xml_node, xml_tags.Elements.ADMIN)
        auditLog = get_xml_text_value(xml_node, xml_tags.Elements.AUDITLOG)
        authorizationStatus = get_xml_text_value(xml_node, xml_tags.Elements.AUTHORIZATIONSTATUS)
        revision_date = get_xml_text_value(xml_node, xml_tags.Elements.DATE)
        gui_client = get_xml_text_value(xml_node, xml_tags.Elements.GUICLIENT)
        num_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        modules_and_policy = get_xml_text_value(xml_node, xml_tags.Elements.MODULES_AND_POLICY)
        policy_package = get_xml_text_value(xml_node, xml_tags.Elements.POLICYPACKAGE)
        revision_id = get_xml_int_value(xml_node, xml_tags.Elements.REVISIONID)
        revision_time = get_xml_text_value(xml_node, xml_tags.Elements.TIME)
        ready = get_xml_text_value(xml_node, xml_tags.Elements.READY)
        return cls(action, num_id, admin, auditLog, authorizationStatus, revision_date, revision_time, gui_client,
                   revision_id, modules_and_policy, policy_package, ready)

    def is_authorized(self):
        return self.authorizationStatus in Device_Revision.AUTHORIZED_STATUSES

    def is_ready(self):
        return str_to_bool(self.ready)

    def get_revision_date(self):
        try:
            revision_date = datetime.strptime(self.date, Device_Revision.REVISION_DATE_FORMAT_STRING)
            return revision_date
        except ValueError as valueerror:
            logger.error("Could not parse date string '%s' using format string '%s'", self.date,
                         Device_Revision.REVISION_DATE_FORMAT_STRING)
            raise valueerror

    def get_revision_datetime(self):
        datetime_str = "{} {}".format(self.date, self.time)
        datetime_frmt = "{} {}".format(Device_Revision.REVISION_DATE_FORMAT_STRING,
                                       Device_Revision.REVISION_TIME_FORMAT_STRING)
        try:
            return datetime.strptime(datetime_str, datetime_frmt)
        except ValueError as error:
            logger.error("Could not parse date time '{}' using format string '{}'".format(datetime_str, datetime_frmt))
            raise error



class RuleSearchDevice(XML_Object_Base):
    """Device object that return from rule_search API based on the rule documentation"""

    def __init__(self, device_id, revision_id, rule_count):
        self.device_id = device_id
        self.revision_id = revision_id
        self.rule_count = rule_count
        super().__init__(xml_tags.Elements.DEVICE)

    @classmethod
    def from_xml_node(cls, xml_node):
        device_id = get_xml_int_value(xml_node, xml_tags.Elements.DEVICE_ID)
        revision_id = get_xml_int_value(xml_node, xml_tags.Elements.REVISION_ID)
        rule_count = get_xml_int_value(xml_node, xml_tags.Elements.RULE_COUNT)
        return cls(device_id, revision_id, rule_count)


class RuleSearchDeviceList(XML_List):
    """List of effected devices based on the rule search API"""

    def __init__(self, devices):
        super().__init__(xml_tags.Elements.DEVICES, devices)

    @classmethod
    def from_xml_node(cls, xml_node):
        """Return only devices that the rule_count is greater than 0"""
        devices = []
        for device_node in xml_node.iter(tag=xml_tags.Elements.DEVICE):
            device_obj = RuleSearchDevice.from_xml_node(device_node)
            if int(device_obj.rule_count):
                devices.append(device_obj)
        return cls(devices)


class InternetReferralObject(XML_Object_Base):
    def __init__(self, device_id, object_name):
        super().__init__(xml_tags.Elements.INTERNET_REFERRAL_OBJECT)
        self.device_id = device_id
        self.object_name = object_name

    @classmethod
    def from_xml_node(cls, xml_node):
        device_id = get_xml_int_value(xml_node, xml_tags.Elements.DEVICE_ID)
        object_name = get_xml_text_value(xml_node, xml_tags.Elements.OBJECT_NAME)
        return cls(device_id, object_name)
