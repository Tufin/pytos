
import codecs
import logging
import socket
import xml.etree.ElementTree as ET
import xml.sax.saxutils
from abc import ABCMeta, abstractmethod
from netaddr import IPSet

from pytos.common.definitions import xml_tags
from pytos.common.functions.xml import get_xml_node

SET_PARENT_NODE = "set_parent_node"
ID = "id"
PARENT_NODE = "_parent_node"

from pytos.common.logging.definitions import XML_LOGGER_NAME
logger = logging.getLogger(XML_LOGGER_NAME)


def _get_tab_string(element_level):
    tab_string = " " * XML_Base.SPACER_SIZE * element_level
    return tab_string


class Comparable:
    @abstractmethod
    def _key(self):
        raise NotImplementedError

    def __hash__(self):
        return hash(self._key())

    def __eq__(self, other):
        equals = True
        if not type(self) == type(other):
            raise TypeError("Uncomparable types '{}' and '{}'.".format(type(self), type(other)))
        elif self is other:
            return True
        else:
            for self_item, other_item in zip(self._key(), other._key()):
                if self_item != other_item:
                    equals = False
                    break
            if equals and super().__eq__(None) != NotImplemented:
                equals = super().__eq__(other)
            return equals

    def __lt__(self, other):
        if isinstance(other, self.__class__):
            for self_item, other_item in zip(self._key(), other._key()):
                if self_item != other_item:
                    return self_item < other_item
            return False
        else:
            raise TypeError("Unorderable types: {} < {}".format(type(self), type(other)))


class XML_Base:
    SPACER_SIZE = 2

    def __init__(self, xml_tag, attribs=None):
        """
        :param xml_tag: The XML tag for the XML object.
        :type xml_tag: str
        :param attribs: The XML attributes of the XML_List.
        :type attribs: dict
        """
        if isinstance(xml_tag, str) or isinstance(xml_tag, int):
            self._xml_tag = xml_tag
        else:
            raise ValueError("xml_tag must be either a string or integer, xml_tag is '{}' of type '{}'".format(xml_tag,
                                                                                                               type(
                                                                                                                       xml_tag)))

        try:
            if self._attribs:
                try:
                    self._attribs.update(attribs)
                except TypeError:
                    self._attribs = {}
        except AttributeError:  # If set_attrib is called before __init__
            if attribs:
                self._attribs = attribs
            else:
                self._attribs = {}

    def get_xml_tag(self):
        """Get the XML tag for the current element."""
        return self._xml_tag

    def get_attribs(self):
        return self._attribs

    def get_attrib(self, attrib_name):
        if attrib_name in self._attribs:
            return self._attribs[attrib_name]

    def set_attrib(self, attrib_name, attrib_value):
        try:
            self._attribs[attrib_name] = attrib_value
        except AttributeError:
            self._attribs = {attrib_name: attrib_value}

    def to_xml_string(self, element_level=None):
        raise NotImplementedError("to_xml_string must be implemented by derived classes.")

    def to_xml_doc(self):
        raise NotImplementedError("to_xml_doc must be implemented by derived classes.")

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        raise NotImplementedError("from_xml_node must be implemented by derived classes.")

    @classmethod
    def from_xml_string(cls, xml_string):
        """
        Initialize the object from a XML string.
        :param xml_string: The string from which all necessary parameters will be parsed.
        :type xml_string: str
        """

        xml_node = ET.fromstring(xml_string)
        return cls.from_xml_node(xml_node)


class XML_List(XML_Base):
    """This class is used for when an XML element with one tag contains multiple other XML nodes with different tags."""

    def __init__(self, xml_tag, list_data=None, _attribs=None):
        """
        :param xml_tag: The XML tag for the XML_List.
        :type xml_tag: str
        :param list_data: The contents of the XML_List.
        :type list_data: list
        :param _attribs: The XML attributes of the XML_List.
        :type _attribs: dict
        """
        self._list_data = []
        if list_data:
            self._list_data.extend(list_data)
        super().__init__(xml_tag, _attribs)

    @classmethod
    def from_xml_node_by_tags(cls, xml_node, list_element_name, child_element_name, child_class_type, optional=False):
        xml_list_base_node = get_xml_node(xml_node, list_element_name, optional)
        list_data = []
        if xml_list_base_node:
            for child_node in xml_list_base_node.iterfind(child_element_name):
                list_data.append(child_class_type.from_xml_node(child_node))
        return cls(list_element_name, list_data)

    @classmethod
    def from_xml_node_by_type_dict(cls, xml_node, list_element_name, child_element_name, type_to_class_dict,
                                   optional=False, default_class=None):
        xml_list_base_node = get_xml_node(xml_node, list_element_name, optional)
        list_data = []
        if xml_list_base_node:
            for child_node in xml_list_base_node.iter(tag=child_element_name):
                try:
                    type_attribute = child_node.attrib[xml_tags.Attributes.XSI_NAMESPACE_TYPE]
                except KeyError:
                    try:
                        type_attribute = child_node.attrib[xml_tags.TYPE_ATTRIB]
                    except KeyError:
                        message = "could not find type attribute in {},existing attributes: {}".format(child_node,
                                                                                                       child_node.attrib)
                        logger.error(message)
                        raise KeyError(message)
                try:
                    list_data.append(type_to_class_dict[type_attribute].from_xml_node(child_node))
                except KeyError as error:
                    if default_class:
                        list_data.append(default_class.from_xml_node(child_node))
                    else:
                        raise error

        return cls(list_element_name, list_data)

    @classmethod
    def from_xml_node_by_tag_dict(cls, xml_node, list_element_name, tag_to_class_dict, default_class=None):
        list_data = []
        for child_node in xml_node:
            try:
                list_data.append(tag_to_class_dict[child_node.tag].from_xml_node(child_node))
            except KeyError as error:
                if default_class:
                    list_data.append(default_class.from_xml_node(child_node))
                else:
                    raise error
        return cls(list_element_name, list_data)

    def to_xml_string(self, element_level=None):
        if self.get_xml_tag():
            if element_level is not None:
                element_level += 1
            else:
                element_level = 0
            logger.debug("Element level is '%s'.", element_level)
            tab_string = _get_tab_string(element_level)
            if self._list_data:
                xml_string = "{tab_string}<{xml_tag}>".format(xml_tag=self.get_xml_tag(), tab_string=tab_string)
                non_xml_items = []
                for item in self._list_data:
                    try:
                        xml_string += "\n{}".format(item.to_xml_string(element_level))
                    except AttributeError:
                        non_xml_items.append(xml.sax.saxutils.escape(str(item)))
                if non_xml_items:
                    xml_string += "\n{}".format(",".join(non_xml_items))
                xml_string += "\n{tab_string}</{xml_tag}>".format(xml_tag=self.get_xml_tag(), tab_string=tab_string)
            else:
                xml_string = "\n{tab_string}<{xml_tag}/>".format(xml_tag=self.get_xml_tag(), tab_string=tab_string)
            return xml_string
        else:
            raise ValueError("{} must have a _xml_tag attribute in order to print in XML form.")

    def to_xml_doc(self):
        """
        Returns a Element Tree representation of the XML Object Base.
        :return: An XML representation of the object in xml.etree.Element form.
        :rtype: xml.etree.ElementTree.Element
        """
        return ET.fromstring(self.to_xml_string())

    def get_attribs(self):
        return self._attribs

    def append(self, item):
        return self._list_data.append(item)

    def remove(self, value):
        return self._list_data.remove(value)

    def index(self, index):
        return self._list_data.index(index)

    def insert(self, index, value):
        return self._list_data.insert(index, value)

    def extend(self, iterable):
        return self._list_data.extend(iterable)

    def pop(self, index=0):
        return self._list_data.pop(index)

    def __next__(self):
        return next(self._list_data)

    def __iter__(self):
        if self._list_data is not None:
            return self._list_data.__iter__()

    def __len__(self):
        return self._list_data.__len__()

    def __getitem__(self, index):
        return self._list_data.__getitem__(index)

    def __delitem__(self, index):
        return self._list_data.__delitem__(index)

    def __setitem__(self, index, value):
        return self._list_data.__setitem__(index, value)

    def __str__(self):
        return self.__repr__()

    def __bool__(self):
        return bool(self._list_data)

    def set_contents(self, contents):
        self._list_data = contents

    def get_contents(self):
        return self._list_data

    def __repr__(self):
        return "XML_List('{}', {})".format(self._xml_tag, [repr(item) for item in self])


class XML_Object_Base(XML_Base):
    """
    This class is used as the basis for all other REST objects, and is used to represent
    a Python class as an XML string.
    Each derived class has a self._xml_tag object that is used as the enclosing XML tag for that object.
    Each member represents another tag: For example, self.name would get printed <name></name>
    In the event that a member name conflicts with a Python reserved keyword, an underscore
    is appended to the member variable name,
    even though when the object is converted to an XML the underscore is not displayed.
    """

    def __init__(self, xml_tag, _attribs=None):
        super().__init__(xml_tag, _attribs)
        self._parent_node = None
        self._set_parent_node_for_child_nodes()

    def get_parent_node(self):
        return self._parent_node

    def set_parent_node(self, node):
        self._parent_node = node

    def sanitize_ids(self):
        """
        Deletes all instance attributes with the name "id" in current instance recursively.
        """
        if hasattr(self, ID):
            setattr(self, ID, None)
        for member in self.__dict__:
            if member != PARENT_NODE and isinstance(self.__dict__[member], XML_Base):
                try:
                    self.__dict__[member].sanitize_ids()
                except AttributeError:
                    pass

    def _set_parent_node_for_child_nodes(self):
        for key in self.__dict__:
            if isinstance(self.__dict__[key], XML_Object_Base):
                self.__dict__[key].set_parent_node(self)
            elif isinstance(self.__dict__[key], XML_List) or isinstance(self.__dict__[key], list):
                for subitem in self.__dict__[key]:
                    if hasattr(subitem, SET_PARENT_NODE):
                        subitem.set_parent_node(self)

    def get_nth_parent_node(self, parent_level):
        if not isinstance(parent_level, int) or parent_level < 1:
            raise ValueError("Parent level must be an integer with a value of at least 1.")
        item_node = self
        for _ in range(parent_level):
            try:
                item_node = item_node.get_parent_node()
            except AttributeError:
                raise ValueError("Object {} does not have a parent node.".format(item_node))
        return item_node

    def to_xml_string(self, element_level=None):
        """
        Returns an XML string representation of the XML Object Base.
        :return: An XML representation of the object in string form.
        :rtype: str
        """
        if self.get_xml_tag():
            if element_level is not None:
                element_level += 1
            else:
                element_level = 0
            logger.debug("Element level is '%s'.", element_level)
            item_tab_string = _get_tab_string(element_level + 1)
            attrib_string = ""
            for key, value in self.get_attribs().items():
                attrib_string += ' {}="{}"'.format(key, value)
            xml_string = "{tab_string}<{xml_tag}{attrib_string}>".format(xml_tag=self._xml_tag,
                                                                         attrib_string=attrib_string,
                                                                         tab_string=_get_tab_string(element_level))
            for key in sorted(self.__dict__):
                # Skip the self._xml_tag member and self._attribs of each class ( and any other member beginning with _.
                if key.startswith("_"):
                    continue
                # If the element contains data, handle normally.
                logger.debug("Handling item '%s'.", key)
                # Handle a case where the member itself does not have an XML tag, but it contains XML elements.
                if isinstance(self.__dict__[key], list):
                    logger.debug("Handling list '%s' in XML form.", self.__dict__[key])
                    non_xml_items = []
                    for item in self.__dict__[key]:
                        if item is not None:
                            logger.debug("Handling list item '%s' in XML form.", item)
                            try:
                                xml_string += "\n{}".format(item.to_xml_string(element_level))
                            except AttributeError:
                                non_xml_items.append(xml.sax.saxutils.escape(str(item)))
                    if non_xml_items:
                        xml_string += "\n<{tag}>{non_xml_items}</{tag}>".format(tag=key,
                                                                                non_xml_items=",".join(non_xml_items))
                else:
                    try:
                        item_xml_string = self.__dict__[key].to_xml_string(element_level)
                        xml_string += "\n{item_xml_string}".format(item_xml_string=item_xml_string)
                        logger.debug("Handling XML_Base '%s'.", key)
                    except AttributeError:
                        # Handle the case where the member name conflicts with a reserved Python keyword,
                        # so an underscore (_) is appended to member name to avoid the conflict.
                        logger.debug("Handling other object type '%s'", key)
                        key_name = key
                        if key_name.endswith("_"):
                            key_name = key_name[:-1]
                        if self.__dict__[key] is not None:
                            item_xml_string = xml.sax.saxutils.escape(str(self.__dict__[key]))
                            xml_string += "\n{tab_string}<{xml_tag}>{item_xml_string}</{xml_tag}>".format(
                                    xml_tag=key_name, item_xml_string=item_xml_string, tab_string=item_tab_string)
                        else:
                            xml_string += "\n{tab_string}<{xml_tag}/>".format(xml_tag=key_name,
                                                                              tab_string=item_tab_string)
            xml_string += "\n{tab_string}</{xml_tag}>".format(xml_tag=self.get_xml_tag(),
                                                              tab_string=_get_tab_string(element_level))
            return xml_string
        else:
            raise ValueError("{} must have a _xml_tag attribute in order to output to XML form.")

    def to_xml_doc(self):
        """
        Returns a Element Tree representation of the XML Object Base.
        :return: An XML representation of the object in xml.etree.Element form.
        :rtype: xml.etree.ElementTree.Element
        """
        return ET.fromstring(self.to_xml_string())

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        raise NotImplementedError("from_xml_node must be implemented by derived classes.")

    @classmethod
    def from_xml_string(cls, xml_string):
        """
        Initialize the object from a XML string.
        :param xml_string: The string from which all necessary parameters will be parsed.
        :type xml_string: str
        """

        xml_node = ET.fromstring(xml_string)
        return cls.from_xml_node(xml_node)

    @classmethod
    def from_file(cls, xml_path):
        """
        Read an XML from a file and create an object from it.
        :param xml_path: The path to the file containing the XML.
        :type xml_path: str
        :return: The created object.
        :raise FileNotFoundError: If the template file was not found.
        """
        try:
            with codecs.open(xml_path, encoding='utf-8') as xml_file:
                xml_string = xml_file.read()
                xml_node = ET.fromstring(xml_string)
        except FileNotFoundError:
            message = "The file {} does not exist.".format(xml_path)
            logger.error(message)
            raise FileNotFoundError(message)
        else:
            return cls.from_xml_node(xml_node)


class Flat_XML_Object_Base(XML_Base):
    """
    This is the class for XML contains only single parameter and does not contain any tags inside
    """

    def __init__(self, xml_tag, _attribs=None, content=None):
        super().__init__(xml_tag, _attribs)
        self.content = content
        self._parent_node = None

    def get_parent_node(self):
        return self._parent_node

    def set_parent_node(self, node):
        self._parent_node = node

    def to_xml_string(self, element_level=None):
        """
        Returns an XML string representation of the Flat XML Object Base.
        :return: An XML representation of the object in string form.
        :rtype: str
        """
        if self.get_xml_tag():
            if element_level is not None:
                element_level += 1
            else:
                element_level = 0
            logger.debug("Element level is '%s'.", element_level)
            item_tab_string = _get_tab_string(element_level + 1)
            attrib_string = ""
            for key, value in self.get_attribs().items():
                attrib_string += ' {}="{}"'.format(key, value)
            xml_string = "{tab_string}<{xml_tag}{attrib_string}".format(tab_string=item_tab_string,
                                                                        xml_tag=self._xml_tag,
                                                                        attrib_string=attrib_string)
            if self.content:
                content = xml.sax.saxutils.escape(str(self.content))
                xml_string += ">{content}</{xml_tag}>".format(content=content, xml_tag=self._xml_tag)
            else:
                xml_string += "/>"
            return xml_string
        else:
            raise ValueError("{} must have a _xml_tag attribute in order to print in XML form.")

    def to_xml_doc(self):
        """
        Returns a Element Tree representation of the XML Object Base.
        :return: An XML representation of the object in xml.etree.Element form.
        :rtype: xml.etree.ElementTree.Element
        """
        return ET.fromstring(self.to_xml_string())


class XSI_Object(XML_Object_Base):
    def __init__(self, xml_tag, xsi_type):
        super().__init__(xml_tag)
        self.set_attrib(xml_tags.NAMESPACE_FIELD_ATTRIB_CONTENT, xml_tags.XSI_NAMESPACE_URL)
        self.set_attrib(xml_tags.Attributes.XSI_TYPE, xsi_type)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        raise NotImplementedError("from_xml_node must be implemented by derived classes.")


class ReferenceURL(XML_Object_Base):
    def __init__(self, url, tag_name):
        super().__init__(tag_name)
        self._url = url
        self.set_attrib(xml_tags.NAMESPACE_FIELD_ATTRIB_CONTENT, xml_tags.XSI_NAMESPACE_URL)
        self.set_attrib(xml_tags.Attributes.HREF, url)

    @classmethod
    def from_xml_node(cls, xml_node):
        url = xml_node.attrib[xml_tags.Attributes.HREF]
        return cls(url, xml_node.tag)

    @staticmethod
    def reference_from_xml_string(xml_string, class_ref):
        return class_ref.from_xml_string(xml_string)


class Service_Type:
    def __contains__(self, item):
        raise NotImplementedError

    def __eq__(self, other):
        raise NotImplementedError

    def __lt__(self, other):
        raise NotImplementedError

    def __str__(self):
        return self.__repr__()

    @staticmethod
    def get_valid_port(port):
        if isinstance(port, str):
            try:
                port = int(socket.getservbyname(port.lower()))
            except OSError:
                raise ValueError("Service for port '{}' not found.".format(port.lower()))
        elif isinstance(port, int):
            if not 0 <= port <= 65535:
                raise ValueError("Port must be between 0 and 65535.")
        else:
            raise ValueError("Invalid port '{}'.".format(port))
        return port

    @staticmethod
    def get_valid_protocol(ip_protocol):
        if isinstance(ip_protocol, str):
            try:
                ip_protocol = socket.getprotobyname(ip_protocol.lower())
            except OSError:
                raise ValueError("Protocol '{}' not found.".format(ip_protocol.lower()))
        elif isinstance(ip_protocol, int):
            if not 0 <= ip_protocol <= 255:
                raise ValueError("Protocol must be between 0 and 255.")
        else:
            raise ValueError("Invalid IP protocol '{}'.".format(ip_protocol))
        return ip_protocol


class Single_Service_Type(Service_Type):
    def __init__(self, ip_protocol, port=0):
        self.ip_protocol = self.get_valid_protocol(ip_protocol)
        self.port = self.get_valid_port(port)

    def __eq__(self, other):
        """
        :param other:
        :return:
        """
        try:
            return self.ip_protocol == other.ip_protocol and self.port == other.port
        except AttributeError:
            return False

    def __contains__(self, item):
        return self == item

    def __hash__(self):
        return hash("{}/{}".format(self.ip_protocol, self.port))

    def __lt__(self, other):

        if type(other) == Any_Service_Type:
            return True
        elif hasattr(other, "_members"):
            return False
        elif hasattr(other, "start_port"):
            return self.ip_protocol < other.ip_protocol or (
                self.ip_protocol == other.ip_protocol and self.port < other.end_port)
        else:
            try:
                return self.ip_protocol < other.ip_protocol or (
                    self.ip_protocol == other.ip_protocol and self.port < other.port)
            except AttributeError:
                raise TypeError("Unorderable types: {} < {}".format(type(self), type(other)))

    def __repr__(self):
        return "Single_Service_Type({},{})".format(self.ip_protocol, self.port)


class Any_Service_Type(Service_Type):
    def __eq__(self, other):
        return type(other) == Any_Service_Type

    def __contains__(self, item):
        return True

    def __hash__(self):
        return hash("ANY")

    def __repr__(self):
        return "Any_Service_Type()"

    def __lt__(self, other):
        return False


class Range_Service_Type(Service_Type):
    def __init__(self, ip_protocol, start_port, end_port):
        self.ip_protocol = self.get_valid_protocol(ip_protocol)
        self.start_port = self.get_valid_port(start_port)
        self.end_port = self.get_valid_port(end_port)

    def __eq__(self, other):
        """
        :param other:
        :return:
        """
        try:
            return self.ip_protocol == other.ip_protocol and self.start_port == other.start_port and self.end_port ==\
                                                                                                     other.end_port
        except AttributeError:
            return False

    def __repr__(self):
        return "Range_Service_Type({},{},{})".format(self.ip_protocol, self.start_port, self.end_port)

    def __contains__(self, item):
        try:
            if hasattr(item, "_members"):
                for member in item.members:
                    if member in self:
                        continue
                    else:
                        return False
                return True
            elif self.ip_protocol == item.ip_protocol:
                if hasattr(item, "start_port"):
                    if self.start_port <= item.start_port and self.end_port >= item.end_port:
                        return True
                elif item.port in range(self.start_port, self.end_port + 1):
                    return True
                else:
                    return False

        except AttributeError:
            return False

    def __lt__(self, other):
        if type(other) == Any_Service_Type:
            return True

        elif hasattr(other, "_members"):
            return False
        elif hasattr(other, "start_port"):
            return self.ip_protocol < other.ip_protocol or (
                self.ip_protocol == other.ip_protocol and self.end_port < other.end_port) or (
                       self.ip_protocol == other.ip_protocol and self.end_port == other.end_port and self.start_port
                       < other.start_port)
        else:
            try:
                return self.ip_protocol < other.ip_protocol or (
                    self.ip_protocol == other.ip_protocol and self.end_port < other.port)
            except AttributeError:
                raise TypeError("Unorderable types: {} < {}".format(type(self), type(other)))

    def __hash__(self):
        return hash("{}/{}-{}".format(self.ip_protocol, self.start_port, self.end_port))


class Group_Service_Type(Service_Type):
    def __init__(self, members=None):
        if members is None:
            self._members = []
        else:
            self._members = members

    def __iter__(self):
        return iter(self._members)

    def __contains__(self, item):
        try:
            if hasattr(item, "_members"):
                for item_member in item:
                    if item_member not in self:
                        return False
                return True
            else:
                for member in self:
                    if item in member or item == member:
                        return True
                return False
        except AttributeError:
            return False

    def append(self, service):
        return self._members.append(service)

    def __lt__(self, other):
        if type(other) == Any_Service_Type:
            return True
        elif hasattr(other, '_members'):
            return False
        else:
            return True

    def __repr__(self):
        return "Group_Service_Type([{}])".format(",".join((repr(member) for member in self)))

    def __len__(self):
        return len(self._members)

    def __eq__(self, other):
        raise NotImplementedError


class Service_Set:
    def __init__(self, services=None):
        self._services = set()
        if services is not None:
            for service in services:
                if hasattr(service, "_members"):
                    self._services.update(service)
                else:
                    self._services.add(service)

    def add(self, item):
        self._services.add(item)

    def issubset(self, other_set):
        for service in self:
            if service not in other_set:
                return False
        return True

    def copy(self):
        return self.__class__(self._services)

    def __repr__(self):
        return "Service_Set([{}])".format(",".join((repr(service) for service in self)))

    def __iter__(self):
        return iter(self._services)

    def __contains__(self, other_service):
        if hasattr(other_service, "_members"):
            for member in other_service:
                if member not in self:
                    return False
            return True
        elif hasattr(other_service, '_services'):
            for service in other_service:
                if service not in self:
                    return False
            return True
        else:
            for service in self:
                if other_service in service or other_service == service:
                    return True
            return False

    def __len__(self):
        return len(self._services)


class Singleton(type):
    """
    Singleton Metaclass.
    """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class SubclassRegistry(type):
    """
    Metaclass that registers subclasses.
    """

    def __init__(cls, name, bases, namespace):
        super().__init__(name, bases, namespace)
        if not hasattr(cls, 'registry'):
            cls.registry = set()
        cls.registry.add(cls)
        cls.registry -= set(bases)  # Remove base classes

    # Metamethods, called on class objects:
    def __iter__(cls):
        return iter(cls.registry)


class SubclassWithIdentifierRegistry(type):
    """
    Metaclass that registers subclasses based on a class identifier.
    """
    CLASS_IDENTIFIER_VAR = "class_identifier"
    REGISTRY = 'registry'

    def __init__(cls, name, bases, namespace):
        super().__init__(name, bases, namespace)
        if not hasattr(cls, cls.REGISTRY):
            cls.registry = {}
        if hasattr(cls, cls.CLASS_IDENTIFIER_VAR):
            cls.registry[cls.class_identifier] = cls

    def __getitem__(cls, item):
        return cls.registry[item]


class IPNetworkMixin(metaclass=ABCMeta):
    def __init__(self):
        self._ip_network_cache = None

    @abstractmethod
    def _get_ip_network(self):
        """

        :rtype: netaddr.IPNetwork
        """
        pass

    def get_ip_network(self):
        """

        :rtype: netaddr.IPNetwork
        """
        if self._ip_network_cache is None:
            self._ip_network_cache = self._get_ip_network()
        return self._ip_network_cache

    def get_ip_set(self):
        """
        This returns an IPset representing the object.
        :rtype: IPSet
        """
        return IPSet(self.get_ip_network())


