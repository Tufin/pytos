# Copyright 2017 Tufin Technologies Security Suite. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
