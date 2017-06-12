
import re
import logging
import xml.etree.ElementTree as ET

from pytos.common.logging.definitions import XML_LOGGER_NAME

logger = logging.getLogger(XML_LOGGER_NAME)

NAMESPACE_DELIMETER = ":"


def clean_namespaces_from_attribs(xml_node):
    for element in xml_node.iter():
        try:
            for key, value in element.attrib.items():
                if re.search(':(?!\/\/)', value):
                    value = value.split(NAMESPACE_DELIMETER)[1]
                    element.attrib[key] = value
        except AttributeError:
            pass
    return xml_node


def xml_node_from_string(xml_string, clean_attrib_namespaces=True):
    xml_node = ET.fromstring(xml_string)
    if clean_attrib_namespaces:
        xml_node = clean_namespaces_from_attribs(xml_node)
    return xml_node


def get_xml_text_value(xml_node, xpath, default_value=None):
    """
    Get the text value for an XML element, return a specified default value if that element is not found.
    :param xml_node: The XML element on which we will evaluate the XPATH expression.
    :type xml_node: xml.etree.Element
    :param xpath: The XPATH expression used to get the XML element value.
    :type xpath: str
    :param default_value: (Optional) The value to be returned if the XPATH expression is invalid.
    :return: Text value for the specified XPATH expression, or the specified default value
    if that XPATH expression does not contain a text value.
    :rtype: str
    :raise ValueError: If the XPATH expression could not be resolved to an XML node.
    """
    if xml_node is not None:
        try:
            return xml_node.find(xpath).text
        except AttributeError:
            logger.debug(
                "Could not find text value for XML element using XPath expression '%s' under XML node '%s',"
                " returning default value '%s'",
                xpath, xml_node, default_value)
            return default_value
    else:
        raise ValueError("xml_element cannot be None.")


def get_xml_int_value(xml_node, xpath, default_value=None):
    """
    Get the text value for an XML element, return a specified default value if that element is not found.
    :param xml_node: The XML element on which we will evaluate the XPATH expression.
    :type xml_node: xml.etree.Element
    :param xpath: The XPATH expression used to get the XML element value.
    :type xpath: str
    :param default_value: (Optional) The value to be returned if the XPATH expression is invalid.
    :return: Numeric value for the specified XPATH expression, or the specified default value
    if that XPATH expression does not contain a text value.
    :rtype int
    :raise ValueError: If the XPATH expression could not be resolved to an XML node.
    """
    text_value = get_xml_text_value(xml_node, xpath, default_value)
    if text_value is not None:
        return int(text_value)
    else:
        return text_value


def get_xml_node(xml_node, xpath, optional=False):
    """
    Get a specified XML node using XPATH.
    :param xml_node: The XML element on which we will evaluate the XPATH expression.
    :type xml_node: xml.etree.Element
    :param xpath: The XPATH expression used to get the XML node.
    :type xpath: str
    :raise ValueError: If the XPATH expression could not be resolved to an XML node.
    """
    logger.debug("Getting XML node from XML element: '%s'", xml_node.tag)  # @UndefinedVariable
    found_node = xml_node.find(xpath)
    if found_node is None and not optional:
        message = "Could not find XML element using XPath expression '{}' under XML node '{}'".format(xpath, xml_node)
        logger.error(message)
        raise XMLTagNotFound(message)
    return found_node


def create_tagless_xml_objects_list(xml_node, xml_tag, object_class):
    """
    :rtype: list[object_class]
    :param xml_node: 
    :param xml_tag: 
    :param object_class: 
    :return: 
    """
    objects = []
    for xml_tag_node in xml_node.iter(tag=xml_tag):
        if xml_tag_node:
            objects.append(object_class.from_xml_node(xml_tag_node))
    return objects


class XMLTagNotFound(ValueError):
    pass
