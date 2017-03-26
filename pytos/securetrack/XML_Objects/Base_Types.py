import netaddr

from pytos.common.Base_Types import XML_Object_Base, Comparable
from pytos.common.definitions import XML_Tags


class Base_Object(XML_Object_Base):
    def __init__(self, xml_tag, name, display_name, object_id):
        self.name = name
        self.display_name = display_name
        self.id = object_id
        super().__init__(xml_tag)

    def __str__(self):
        if self.display_name:
            return str(self.display_name)
        else:
            return str(self.name)


class Service(Base_Object):
    def __init__(self, xml_tag, service_id, display_name, is_global, name, service_type, attr_type):
        self.global_ = is_global
        self.type = service_type
        self.set_attrib(XML_Tags.Attributes.XSI_TYPE, attr_type)
        super().__init__(xml_tag, name, display_name, service_id)


class Network_Object(XML_Object_Base, Comparable):
    def __init__(self, xml_tag, display_name, is_global, object_id, name, object_type, device_id, comment, implicit,
                 class_name=None):
        self.id = object_id
        self.name = name
        self.type = object_type
        self.display_name = display_name
        self.global_ = is_global
        self.device_id = device_id
        self.comment = comment
        self.implicit = implicit
        self.class_name = class_name
        super().__init__(xml_tag)

    def as_netaddr_obj(self):
        raise NotImplementedError

    def as_netaddr_set(self):
        """This returns a netaddr set representing the Network_Object"""
        return netaddr.IPSet(self.as_netaddr_obj())

    def __key(self):
        return self.id, self.device_id


class URL_Link(XML_Object_Base):
    def __init__(self, url):
        self.set_attrib(XML_Tags.Attributes.HREF, url)
        super().__init__(XML_Tags.Elements.LINK)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        url = xml_node.attrib[XML_Tags.Attributes.HREF]
        return cls(url)


class Base_Link_Target(XML_Object_Base):
    def __init__(self, xml_tag, connection_id, display_name, name, link):
        self.id = connection_id
        self.display_name = display_name
        self.name = name
        self.link = link
        super().__init__(xml_tag)
