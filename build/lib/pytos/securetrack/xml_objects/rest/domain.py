
import logging

from pytos.common.base_types import XML_Object_Base, XML_List
from pytos.common.logging.definitions import XML_LOGGER_NAME
from pytos.common.definitions import xml_tags
from pytos.common.functions.xml import get_xml_text_value, get_xml_int_value

logger = logging.getLogger(XML_LOGGER_NAME)


class Domain(XML_Object_Base):
    def __init__(self, domain_id, domain_name, description=None, address=None):
        self.id = domain_id
        self.name = domain_name
        if description:
            self.description = description
        if address:
            self.address = address
        super().__init__(xml_tags.Elements.DOMAIN)

    @classmethod
    def from_xml_node(cls, xml_node):
        domain_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        domain_name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        description = get_xml_text_value(xml_node, xml_tags.Elements.DESCRIPTION)
        address = get_xml_text_value(xml_node, xml_tags.Elements.ADDRESS)
        return cls(domain_id, domain_name, description, address)

    def __str__(self):
        return "Domain({},{})".format(self.id, self.name)


class Domains(XML_List):
    """
    :type domains: list[Domain]
    """

    def __init__(self, domains):
        self.domains = domains
        super().__init__(xml_tags.Elements.DOMAINS, domains)

    @classmethod
    def from_xml_node(cls, xml_node):
        domains = []
        for domain_node in xml_node.iter(tag=xml_tags.Elements.DOMAIN):
            domains.append(Domain.from_xml_node(domain_node))
        return cls(domains)
