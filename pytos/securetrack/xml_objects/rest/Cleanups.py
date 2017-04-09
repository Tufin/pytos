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
from pytos.common.logging.Defines import XML_LOGGER_NAME
from pytos.common.definitions import XML_Tags
from pytos.common.functions.XML import get_xml_text_value, get_xml_int_value, get_xml_node
from pytos.securetrack.xml_objects.rest.Rules import Shadowed_Rule

logger = logging.getLogger(XML_LOGGER_NAME)


class Generic_Cleanup_List(XML_List):
    def __init__(self, count, total, score, cleanups):
        self.count = count
        self.total = total
        self.score = score
        super().__init__(XML_Tags.Elements.CLEANUPS, cleanups)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        count = get_xml_int_value(xml_node, XML_Tags.Elements.COUNT)
        total = get_xml_int_value(xml_node, XML_Tags.Elements.TOTAL)
        score = get_xml_int_value(xml_node, XML_Tags.Elements.SCORE)
        cleanups = []
        for user_node in xml_node.iter(tag=XML_Tags.Elements.CLEANUP):
            cleanups.append(Generic_Cleanup.from_xml_node(user_node))
        return cls(count, total, score, cleanups)


class Generic_Cleanup(XML_Object_Base):
    def __init__(self, num_id, code, name, instances_total):
        self.id = num_id
        self.code = code
        self.name = name
        self.instances_total = instances_total
        super().__init__(XML_Tags.Elements.CLEANUP)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, XML_Tags.Elements.ID)
        code = get_xml_text_value(xml_node, XML_Tags.Elements.CODE)
        name = get_xml_text_value(xml_node, XML_Tags.Elements.NAME)
        instances_total = get_xml_int_value(xml_node, XML_Tags.Elements.INSTANCES_TOTAL)
        return cls(num_id, code, name, instances_total)


class Cleanup_Set(XML_Object_Base):
    def __init__(self, shadowed_rules_cleanup=None):
        self.shadowed_rules_cleanup = shadowed_rules_cleanup
        super().__init__(XML_Tags.Elements.CLEANUP_SET)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        shadowed_rules_cleanup = Shadowed_Rules_Cleanup.from_xml_node(
                get_xml_node(xml_node, XML_Tags.Elements.SHADOWED_RULES_CLEANUP))
        return cls(shadowed_rules_cleanup)


class Shadowed_Rules_Cleanup(XML_Object_Base):
    def __init__(self, shadowed_rules=None):
        self.shadowed_rules = XML_List(XML_Tags.Elements.SHADOWED_RULES, shadowed_rules)
        super().__init__(XML_Tags.Elements.SHADOWED_RULES_CLEANUP)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        shadowed_rules = XML_List(XML_Tags.Elements.SHADOWED_RULES)
        for shadowed_rule_node in xml_node.iter(tag=XML_Tags.Elements.SHADOWED_RULE):
            shadowed_rules.append(Shadowed_Rule.from_xml_node(shadowed_rule_node))
        return cls(shadowed_rules)
