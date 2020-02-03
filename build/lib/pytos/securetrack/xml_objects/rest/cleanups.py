
import logging

from pytos.common.base_types import XML_Object_Base, XML_List
from pytos.common.logging.definitions import XML_LOGGER_NAME
from pytos.common.definitions import xml_tags
from pytos.common.functions.xml import get_xml_text_value, get_xml_int_value, get_xml_node
from pytos.securetrack.xml_objects.rest.rules import Shadowed_Rule

logger = logging.getLogger(XML_LOGGER_NAME)


class Generic_Cleanup_List(XML_List):
    def __init__(self, count, total, score, cleanups):
        self.count = count
        self.total = total
        self.score = score
        super().__init__(xml_tags.Elements.CLEANUPS, cleanups)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        count = get_xml_int_value(xml_node, xml_tags.Elements.COUNT)
        total = get_xml_int_value(xml_node, xml_tags.Elements.TOTAL)
        score = get_xml_int_value(xml_node, xml_tags.Elements.SCORE)
        cleanups = []
        for user_node in xml_node.iter(tag=xml_tags.Elements.CLEANUP):
            cleanups.append(Generic_Cleanup.from_xml_node(user_node))
        return cls(count, total, score, cleanups)


class Generic_Cleanup(XML_Object_Base):
    def __init__(self, num_id, code, name, instances_total):
        self.id = num_id
        self.code = code
        self.name = name
        self.instances_total = instances_total
        super().__init__(xml_tags.Elements.CLEANUP)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, xml_tags.Elements.ID)
        code = get_xml_text_value(xml_node, xml_tags.Elements.CODE)
        name = get_xml_text_value(xml_node, xml_tags.Elements.NAME)
        instances_total = get_xml_int_value(xml_node, xml_tags.Elements.INSTANCES_TOTAL)
        return cls(num_id, code, name, instances_total)


class Cleanup_Set(XML_Object_Base):
    def __init__(self, shadowed_rules_cleanup=None):
        self.shadowed_rules_cleanup = shadowed_rules_cleanup
        super().__init__(xml_tags.Elements.CLEANUP_SET)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        shadowed_rules_cleanup = Shadowed_Rules_Cleanup.from_xml_node(
                get_xml_node(xml_node, xml_tags.Elements.SHADOWED_RULES_CLEANUP))
        return cls(shadowed_rules_cleanup)


class Shadowed_Rules_Cleanup(XML_Object_Base):
    def __init__(self, shadowed_rules=None):
        self.shadowed_rules = XML_List(xml_tags.Elements.SHADOWED_RULES, shadowed_rules)
        super().__init__(xml_tags.Elements.SHADOWED_RULES_CLEANUP)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        shadowed_rules = XML_List(xml_tags.Elements.SHADOWED_RULES)
        for shadowed_rule_node in xml_node.iter(tag=xml_tags.Elements.SHADOWED_RULE):
            shadowed_rules.append(Shadowed_Rule.from_xml_node(shadowed_rule_node))
        return cls(shadowed_rules)
