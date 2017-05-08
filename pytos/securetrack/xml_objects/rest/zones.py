import logging

import netaddr

from pytos.common.base_types import XML_List, XML_Object_Base, Comparable, IPNetworkMixin
from pytos.common.definitions.xml_tags import Elements, Attributes
from pytos.common.functions import get_xml_int_value, get_xml_text_value, get_xml_node
from pytos.common.logging.definitions import XML_LOGGER_NAME

logger = logging.getLogger(XML_LOGGER_NAME)


class Zone_List(XML_List):
    def __init__(self, zones):
        """
        :type zones: list[Zone]
        """
        self.zones = zones
        self.count = len(self.zones)
        self.total = self.count
        super().__init__(Elements.ZONES, zones)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        zones = []
        for zone_node in xml_node.iter(Elements.ZONE):
            zones.append(Zone.from_xml_node(zone_node))
        return cls(zones)


class Zone_Domain(XML_Object_Base):
    def __init__(self, domain_id=1, name="Default"):
        self.id = domain_id
        self.name = name
        super().__init__(Elements.DOMAIN)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        domain_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        return cls(domain_id, name)


class Zone(XML_Object_Base, Comparable):
    def __init__(self, zone_id, name, comment, zone_domain=None):
        """
        :type zone_domain: Zone_Domain|None
        :type comment: str|None
        :type name: str
        :type zone_id: int|None
        """
        self.id = zone_id
        self.name = name
        self.comment = comment
        if zone_domain is None:
            zone_domain = Zone_Domain()
        self.domain = zone_domain
        super().__init__(Elements.ZONE)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        zone_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        domain_node = get_xml_node(xml_node, Elements.DOMAIN)
        domain = Zone_Domain.from_xml_node(domain_node)
        return cls(zone_id, name, domain)

    def _key(self):
        return self.id, self.name

    def __repr__(self):
        return "Zone({id},{name},{comment},{domain})".format(**self.__dict__)


class Zone_Entries_List(XML_List):
    def __init__(self, zone_entries):
        """
        :type zone_entries: list[Zone_Entry]
        """
        self.zone_entries = zone_entries
        super().__init__(Elements.ZONE_ENTRIES, zone_entries)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        zone_entries = []
        for zone_entry_node in xml_node.iter(Elements.ZONE_ENTRY):
            zone_entries.append(Zone_Entry.from_xml_node(zone_entry_node))
        return cls(zone_entries)


class Zone_Entry(XML_Object_Base, Comparable, IPNetworkMixin):
    def __init__(self, item_id, comment, ip, _, netmask, zone_id):
        """

        :type netmask: str|int
        :type comment: str|None
        :type item_id: int|None
        :type zone_id: int|None
        """
        self.id = item_id
        self.comment = comment
        self.ip = ip
        self.netmask = netmask
        self.zoneId = zone_id
        IPNetworkMixin.__init__(self)
        super().__init__(Elements.ZONE_ENTRY)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        item_id = get_xml_int_value(xml_node, Elements.ID)
        comment = get_xml_text_value(xml_node, Elements.COMMENT)
        ip = get_xml_text_value(xml_node, Elements.IP)
        netmask = get_xml_text_value(xml_node, Elements.NETMASK)
        zone_id = get_xml_int_value(xml_node, Elements.ZONEID)
        return cls(item_id, comment, ip, None, netmask, zone_id)

    def _get_ip_network(self):
        if not self.netmask:
            ip_network = netaddr.IPNetwork(self.ip)
        else:
            ip_network = netaddr.IPNetwork(str(self.ip) + "/" + str(self.netmask))
        return ip_network

    def _key(self):
        return self.id, self.zoneId

    def __repr__(self):
        return "Zone_Entry({id},{comment},{ip},{netmask},{zoneId})".format(**self.__dict__)

    def __str__(self):
        return "{}/{}".format(self.ip, self.netmask)


class ZoneDescendantsList(XML_List):
    def __init__(self, zones):
        self.zones = zones
        super().__init__(Elements.ZONES, zones)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        zones = []
        for zone_node in xml_node.iterfind(Elements.ZONE):
            zones.append(ZoneDescendants.from_xml_node(zone_node))
        return cls(zones)


class ZoneDescendants(XML_Object_Base, Comparable):
    def __init__(self, zone_id, name, zones):
        self.id = zone_id
        self.name = name
        self.zones = zones
        super().__init__(Elements.ZONE)

    @classmethod
    def from_xml_node(cls, xml_node):
        zone_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        zones = XML_List.from_xml_node_by_tags(xml_node, Elements.ZONES, Elements.ZONE, ZoneDescendants)
        return cls(zone_id, name, zones)

    def _key(self):
        return self.id, self.name

    def __repr__(self):
        return "Zone({id},{name})".format(**self.__dict__)


