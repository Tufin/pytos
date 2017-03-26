import logging

from pytos.common.Base_Types import XML_Object_Base, XML_List
from pytos.common.logging.Defines import XML_LOGGER_NAME
from pytos.common.definitions import XML_Tags
from pytos.common.functions.XML import get_xml_text_value, get_xml_int_value

logger = logging.getLogger(XML_LOGGER_NAME)


class Domain(XML_Object_Base):
    def __init__(self, domain_id, domain_name, description=None, address=None):
        self.id = domain_id
        self.name = domain_name
        if description:
            self.description = description
        if address:
            self.address = address
        super().__init__(XML_Tags.Elements.DOMAIN)

    @classmethod
    def from_xml_node(cls, xml_node):
        domain_id = get_xml_int_value(xml_node, XML_Tags.Elements.ID)
        domain_name = get_xml_text_value(xml_node, XML_Tags.Elements.NAME)
        description = get_xml_text_value(xml_node, XML_Tags.Elements.DESCRIPTION)
        address = get_xml_text_value(xml_node, XML_Tags.Elements.ADDRESS)
        return cls(domain_id, domain_name, description, address)

    def __str__(self):
        return "Domain({},{})".format(self.id, self.name)


class Domains(XML_List):
    """
    :type domains: list[Domain]
    """

    def __init__(self, domains):
        self.domains = domains
        super().__init__(XML_Tags.Elements.DOMAINS, domains)

    @classmethod
    def from_xml_node(cls, xml_node):
        domains = []
        for domain_node in xml_node.iter(tag=XML_Tags.Elements.DOMAIN):
            domains.append(Domain.from_xml_node(domain_node))
        return cls(domains)
