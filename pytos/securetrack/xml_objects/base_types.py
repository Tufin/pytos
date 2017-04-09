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
import netaddr

from importlib import import_module
from pytos.common.base_types import XML_Object_Base, Comparable
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

    def as_sa_service(self, *, alt_class_name=None):
        module = import_module('Secure_App.XML_Objects.REST')
        class_name = alt_class_name or type(self).__name__
        return getattr(module, class_name).from_st_service_object(self)


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

    def as_sa_object(self, *, alt_class_name=None):
        module = import_module('Secure_App.XML_Objects.REST')
        class_name = alt_class_name or type(self).__name__
        return getattr(module, class_name).from_st_network_object(self)


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
