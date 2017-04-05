import logging

from pytos.common.base_types import XML_Object_Base, XML_List
from pytos.common.logging.Defines import XML_LOGGER_NAME
from pytos.common.definitions import XML_Tags
from pytos.common.functions.XML import get_xml_text_value, get_xml_int_value, get_xml_node
from pytos.securetrack.xml_objects.REST.Domain import Domain

logger = logging.getLogger(XML_LOGGER_NAME)


class Security_Policy_Exception(XML_Object_Base):
    def __init__(self, name, expiration_date, ticket_id, created_by, approved_by, requested_by, creation_date,
                 description, exempted_traffic_list, domain=None):
        self.name = name
        self.expiration_date = expiration_date
        self.ticket_id = ticket_id
        self.created_by = created_by
        self.approved_by = approved_by
        self.requested_by = requested_by
        self.creation_date = creation_date
        self.description = description
        self.exempted_traffic_list = exempted_traffic_list
        self.domain = domain
        super().__init__(XML_Tags.Elements.SECURITY_POLICY_EXCEPTION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, XML_Tags.Elements.NAME)
        expiration_date = get_xml_text_value(xml_node, XML_Tags.Elements.EXPIRATION_DATE)
        ticket_id = get_xml_int_value(xml_node, XML_Tags.Elements.TICKET_ID)
        created_by = get_xml_text_value(xml_node, XML_Tags.Elements.CREATED_BY)
        approved_by = get_xml_text_value(xml_node, XML_Tags.Elements.APPROVED_BY)
        requested_by = get_xml_text_value(xml_node, XML_Tags.Elements.REQUESTED_BY)
        creation_date = get_xml_text_value(xml_node, XML_Tags.Elements.CREATION_DATE)
        description = get_xml_text_value(xml_node, XML_Tags.Elements.DESCRIPTION)
        exempted_traffic_list = XML_List.from_xml_node_by_tags(xml_node, XML_Tags.Elements.EXEMPTED_TRAFFIC_LIST,
                                                               XML_Tags.Elements.EXEMPTED_TRAFFIC,
                                                               Exception_Exempted_Traffic)
        domain = Domain.from_xml_node(xml_node)
        return cls(name, expiration_date, ticket_id, created_by, approved_by, requested_by, creation_date, description,
                   exempted_traffic_list, domain)


class Exception_Exempted_Traffic(XML_Object_Base):
    def __init__(self, source_network_collection, dest_network_collection, service_collection, security_requirements,
                 comment):
        self.source_network_collection = source_network_collection
        self.dest_network_collection = dest_network_collection
        self.service_collection = service_collection
        self.security_requirements = security_requirements
        self.comment = comment
        super().__init__(XML_Tags.Elements.EXEMPTED_TRAFFIC)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        source_network_collection_node = get_xml_node(xml_node, XML_Tags.Elements.SOURCE_NETWORK_COLLECTION)
        source_network_collection = Exception_Network_Source_Collection.from_xml_node(source_network_collection_node)
        dest_network_collection_node = get_xml_node(xml_node, XML_Tags.Elements.DEST_NETWORK_COLLECTION)
        dest_network_collection = Exception_Network_Destination_Collection.from_xml_node(dest_network_collection_node)
        service_collection_node = get_xml_node(xml_node, XML_Tags.Elements.SERVICE_COLLECTION)
        service_collection = Exception_Service_Collection.from_xml_node(service_collection_node)
        security_requirements = XML_List.from_xml_node_by_tags(xml_node, XML_Tags.Elements.SECURITY_REQUIREMENTS,
                                                               XML_Tags.Elements.ZONE_TO_ZONE_SECURITY_REQUIREMENT,
                                                               Zone_To_Zone_Security_Requirement)
        comment = get_xml_text_value(xml_node, XML_Tags.Elements.COMMENT)
        return cls(source_network_collection, dest_network_collection, service_collection, security_requirements,
                   comment)


class Exception_Network_Collection(XML_Object_Base):
    def __init__(self, network_items, xml_tag):
        self.network_items = network_items
        super().__init__(xml_tag)


class Exception_Network_Source_Collection(Exception_Network_Collection):
    def __init__(self, network_items):
        super().__init__(network_items, XML_Tags.Elements.SOURCE_NETWORK_COLLECTION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        type_to_class_dict = {XML_Tags.Attributes.SUBNET: Exception_Subnet_Network_Item,
                              XML_Tags.Attributes.ZONE: Exception_Zone_Network_Item,
                              XML_Tags.Attributes.RANGE_NETWORK: Exception_Range_Network_Item,
                              XML_Tags.Attributes.DNS: Exception_DNS_Network_Item,
                              XML_Tags.Attributes.DEVICE_NETWORK: Exception_Device_Network_Item}
        network_items = XML_List.from_xml_node_by_type_dict(xml_node, XML_Tags.Elements.NETWORK_ITEMS,
                                                            XML_Tags.Elements.NETWORK_ITEM, type_to_class_dict)
        return cls(network_items)


class Exception_Network_Destination_Collection(Exception_Network_Collection):
    def __init__(self, network_items):
        super().__init__(network_items, XML_Tags.Elements.DEST_NETWORK_COLLECTION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        type_to_class_dict = {XML_Tags.Attributes.SUBNET: Exception_Subnet_Network_Item,
                              XML_Tags.Attributes.ZONE: Exception_Zone_Network_Item,
                              XML_Tags.Attributes.RANGE_NETWORK: Exception_Range_Network_Item,
                              XML_Tags.Attributes.DNS: Exception_DNS_Network_Item,
                              XML_Tags.Attributes.DEVICE_NETWORK: Exception_Device_Network_Item}
        network_items = XML_List.from_xml_node_by_type_dict(xml_node, XML_Tags.Elements.NETWORK_ITEMS,
                                                            XML_Tags.Elements.NETWORK_ITEM, type_to_class_dict)
        return cls(network_items)


class Exception_Network_Item(XML_Object_Base):
    def __init__(self, item_id):
        self.id = item_id
        super().__init__(XML_Tags.Elements.NETWORK_ITEM)
        self.set_attrib(XML_Tags.NAMESPACE_FIELD_ATTRIB_CONTENT, XML_Tags.XSI_NAMESPACE_URL)


class Exception_Subnet_Network_Item(Exception_Network_Item):
    def __init__(self, item_id, ip, netmask, prefix):
        self.ip = ip
        self.netmask = netmask
        self.prefix = prefix
        super().__init__(item_id)
        self.set_attrib(XML_Tags.Attributes.XSI_TYPE, XML_Tags.Attributes.SUBNET)
        #BUG: Work around a bug in the validation of query network items where the mask can not be null if a prefix is sent.
        if self.prefix and not self.netmask:
            del self.netmask
        elif self.netmask and not self.prefix:
            del self.prefix

    def __str__(self):
        netmask = self.netmask if self.netmask else self.prefix
        return "{}/{}".format(self.ip, netmask)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        item_id = get_xml_int_value(xml_node, XML_Tags.Elements.ID)
        ip = get_xml_text_value(xml_node, XML_Tags.Elements.IP)
        mask = get_xml_text_value(xml_node, XML_Tags.Elements.MASK)
        prefix = get_xml_text_value(xml_node, XML_Tags.Elements.PREFIX)
        return cls(item_id, ip, mask, prefix)


class Exception_Any_Network_Item(Exception_Network_Item):
    def __init__(self, item_id):
        super().__init__(item_id)
        self.set_attrib(XML_Tags.Attributes.XSI_TYPE, XML_Tags.Attributes.VIOLATION_ANY_NETWORK_OBJECT)



class Exception_Range_Network_Item(Exception_Network_Item):
    def __init__(self, item_id, minIp, maxIp):
        self.minIp = minIp
        self.maxIp = maxIp
        super().__init__(item_id)
        self.set_attrib(XML_Tags.Attributes.XSI_TYPE, XML_Tags.Attributes.RANGE_NETWORK)

    def __str__(self):
        return "{}/{}".format(self.minIp, self.maxIp)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        item_id = get_xml_int_value(xml_node, XML_Tags.Elements.ID)
        minIp = get_xml_text_value(xml_node, XML_Tags.Elements.MINIP)
        maxIp = get_xml_text_value(xml_node, XML_Tags.Elements.MAXIP)
        return cls(item_id, minIp, maxIp)


class Exception_Zone_Network_Item(Exception_Network_Item):
    def __init__(self, item_id, zone_id, zone_name):
        self.zone_id = zone_id
        self.zone_name = zone_name
        super().__init__(item_id)
        self.set_attrib(XML_Tags.Attributes.XSI_TYPE, XML_Tags.Attributes.ZONE)

    def __str__(self):
        return self.zone_name

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        item_id = get_xml_int_value(xml_node, XML_Tags.Elements.ID)
        zone_id = get_xml_int_value(xml_node, XML_Tags.Elements.ZONE_ID)
        zone_name = get_xml_text_value(xml_node, XML_Tags.Elements.ZONE_NAME)
        return cls(item_id, zone_id, zone_name)


class Exception_Device_Network_Item(Exception_Network_Item):
    def __init__(self, item_id, mgmt_id, network_uid, network_name, mgmt_name):
        self.mgmt_id = mgmt_id
        self.network_uid = network_uid
        self.network_name = network_name
        self.mgmt_name = mgmt_name
        super().__init__(item_id)
        self.set_attrib(XML_Tags.Attributes.XSI_TYPE, XML_Tags.Attributes.DEVICE_NETWORK)

    def __str__(self):
        return self.network_name

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        item_id = get_xml_int_value(xml_node, XML_Tags.Elements.ID)
        mgmt_id = get_xml_int_value(xml_node, XML_Tags.Elements.MGMT_ID)
        network_uid = get_xml_text_value(xml_node, XML_Tags.Elements.NETWORK_UID)
        network_name = get_xml_text_value(xml_node, XML_Tags.Elements.NETWORK_NAME)
        mgmt_name = get_xml_text_value(xml_node, XML_Tags.Elements.MGMT_NAME)
        return cls(item_id, mgmt_id, network_uid, network_name, mgmt_name)


class Exception_DNS_Network_Item(Exception_Network_Item):
    def __init__(self, item_id, dnsAddress):
        self.dnsAddress = dnsAddress
        super().__init__(item_id)
        self.set_attrib(XML_Tags.Attributes.XSI_TYPE, XML_Tags.Attributes.DNS)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        item_id = get_xml_int_value(xml_node, XML_Tags.Elements.ID)
        dnsAddress = get_xml_text_value(xml_node, XML_Tags.Elements.DNSADDRESS)
        return cls(item_id, dnsAddress)


class Exception_Service_Collection(XML_Object_Base):
    def __init__(self, service_items):
        self.service_items = service_items
        super().__init__(XML_Tags.Elements.SERVICE_COLLECTION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        type_to_class_dict = {XML_Tags.Attributes.CUSTOM: Exception_Custom_Service_Item,
                              XML_Tags.Attributes.DEVICE_SERVICE: Exception_Device_Service_Item,
                              XML_Tags.Attributes.PREDEFINED: Exception_Predefined_Service_Item}
        service_items = XML_List.from_xml_node_by_type_dict(xml_node, XML_Tags.Elements.SERVICE_ITEMS,
                                                            XML_Tags.Elements.SERVICE_ITEM, type_to_class_dict)
        return cls(service_items)


class Exception_Service_Item(XML_Object_Base):
    def __init__(self, item_id):
        self.id = item_id
        super().__init__(XML_Tags.Elements.SERVICE_ITEM)
        self.set_attrib(XML_Tags.NAMESPACE_FIELD_ATTRIB_CONTENT, XML_Tags.XSI_NAMESPACE_URL)


class Exception_Custom_Service_Item(Exception_Service_Item):
    def __init__(self, item_id, protocol, port):
        self.protocol = protocol
        self.port = port
        super().__init__(item_id)
        self.set_attrib(XML_Tags.Attributes.XSI_TYPE, XML_Tags.Attributes.CUSTOM)

    def __str__(self):
        return "{}/{}".format(self.protocol, self.port)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        item_id = get_xml_int_value(xml_node, XML_Tags.Elements.ID)
        protocol = get_xml_text_value(xml_node, XML_Tags.Elements.PROTOCOL)
        port = get_xml_text_value(xml_node, XML_Tags.Elements.PORT)
        return cls(item_id, protocol, port)


class Exception_Device_Service_Item(Exception_Service_Item):
    def __init__(self, item_id, mgmt_id, service_uid, service_name, mgmt_name):
        self.mgmt_id = mgmt_id
        self.service_uid = service_uid
        self.service_name = service_name
        self.mgmt_name = mgmt_name
        super().__init__(item_id)
        self.set_attrib(XML_Tags.Attributes.XSI_TYPE, XML_Tags.Attributes.DEVICE_SERVICE)

    def __str__(self):
        return self.service_name

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        item_id = get_xml_int_value(xml_node, XML_Tags.Elements.ID)
        mgmt_id = get_xml_int_value(xml_node, XML_Tags.Elements.MGMT_ID)
        service_uid = get_xml_text_value(xml_node, XML_Tags.Elements.SERVICE_UID)
        service_name = get_xml_text_value(xml_node, XML_Tags.Elements.SERVICE_NAME)
        mgmt_name = get_xml_text_value(xml_node, XML_Tags.Elements.MGMT_NAME)
        return cls(item_id, mgmt_id, service_uid, service_name, mgmt_name)


class Exception_Predefined_Service_Item(Exception_Service_Item):
    def __init__(self, item_id, predefined_service_id, predefined_service_name, predefined_service_ranges):
        self.id = item_id
        self.predefined_service_id = predefined_service_id
        self.predefined_service_name = predefined_service_name
        self.predefined_service_ranges = predefined_service_ranges
        super().__init__(predefined_service_id)
        self.set_attrib(XML_Tags.Attributes.XSI_TYPE, XML_Tags.Attributes.PREDEFINED)

    def __str__(self):
        return self.predefined_service_name

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        item_id = get_xml_int_value(xml_node, XML_Tags.Elements.ID)
        predefined_service_id = get_xml_int_value(xml_node, XML_Tags.Elements.PREDEFINED_SERVICE_ID)
        predefined_service_name = get_xml_text_value(xml_node, XML_Tags.Elements.PREDEFINED_SERVICE_NAME)
        predefined_service_ranges = XML_List.from_xml_node_by_tags(xml_node,
                                                                   XML_Tags.Elements.PREDEFINED_SERVICE_RANGES,
                                                                   XML_Tags.Elements.PREDEFINED_SERVICE_RANGE,
                                                                   Exception_Predefined_Service_Range)
        return cls(item_id, predefined_service_id, predefined_service_name, predefined_service_ranges)


class Exception_Predefined_Service_Range(XML_Object_Base):
    def __init__(self, port_min, port_max, protocol, negate):
        self.min = port_min
        self.max = port_max
        self.protocol = protocol
        self.negate = negate
        super().__init__(XML_Tags.Elements.PREDEFINED_SERVICE_RANGE)
        self.set_attrib(XML_Tags.Attributes.XSI_TYPE, XML_Tags.Attributes.PREDEFINED)
        self.set_attrib(XML_Tags.NAMESPACE_FIELD_ATTRIB_CONTENT, XML_Tags.XSI_NAMESPACE_URL)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        port_min = get_xml_int_value(xml_node, XML_Tags.Elements.MIN)
        port_max = get_xml_int_value(xml_node, XML_Tags.Elements.MAX)
        protocol = get_xml_int_value(xml_node, XML_Tags.Elements.PROTOCOL)
        negate = get_xml_text_value(xml_node, XML_Tags.Elements.NEGATE)
        return cls(port_min, port_max, protocol, negate)


class Exception_Service_Range(Exception_Service_Item):
    def __init__(self, item_id, port_min, port_max, min_protocol, max_protocol):
        self.id = item_id
        self.minPort = port_min
        self.maxPort = port_max
        self.minProtocol = min_protocol
        self.maxProtocol = max_protocol
        super().__init__(item_id)
        self.set_attrib(XML_Tags.Attributes.XSI_TYPE, XML_Tags.Attributes.RANGE_SERVICE)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        item_id = get_xml_int_value(xml_node, XML_Tags.Elements.ID)
        port_min = get_xml_int_value(xml_node, XML_Tags.Elements.MIN)
        port_max = get_xml_int_value(xml_node, XML_Tags.Elements.MAX)
        min_protocol = get_xml_int_value(xml_node, XML_Tags.Elements.MIN_PROTOCOL)
        max_protocol = get_xml_int_value(xml_node, XML_Tags.Elements.MAX_PROTOCOL)
        return cls(item_id, port_min, port_max, min_protocol, max_protocol)


class Zone_To_Zone_Security_Requirement(XML_Object_Base):
    def __init__(self, from_zone, to_zone, policy_name, from_domain=None, to_domain=None):
        self.from_zone = from_zone
        self.to_zone = to_zone
        self.from_domain = from_domain
        self.to_domain = to_domain
        self.policy_name = policy_name
        self.from_domain = from_domain
        self.to_domain = to_domain
        super().__init__(XML_Tags.Elements.ZONE_TO_ZONE_SECURITY_REQUIREMENT)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        from_zone = get_xml_text_value(xml_node, XML_Tags.Elements.FROM_ZONE)
        to_zone = get_xml_text_value(xml_node, XML_Tags.Elements.TO_ZONE)
        policy_name = get_xml_text_value(xml_node, XML_Tags.Elements.POLICY_NAME)
        from_domain = get_xml_text_value(xml_node, XML_Tags.Elements.FROM_DOMAIN)
        to_domain = get_xml_text_value(xml_node, XML_Tags.Elements.TO_DOMAIN)
        return cls(from_zone, to_zone, policy_name, from_domain, to_domain)
