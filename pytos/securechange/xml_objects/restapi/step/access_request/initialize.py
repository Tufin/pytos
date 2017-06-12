
import logging
import textwrap
import netaddr
import socket
import itertools
import requests
from xml.sax.saxutils import unescape
import xml.etree.ElementTree as ET

from pytos.common.base_types import XML_Object_Base, XML_List, Flat_XML_Object_Base, ReferenceURL, SubclassWithIdentifierRegistry
from pytos.common.definitions.xml_tags import Elements, Attributes
from pytos.common.functions.xml import get_xml_text_value, get_xml_node, get_xml_int_value
from pytos.common.logging.definitions import XML_LOGGER_NAME
from pytos.common.helpers import Secure_API_Helper
from pytos.common.exceptions import REST_Service_Unavailable_Error
from pytos.common.definitions.xml_tags import TYPE_ANY, TYPE_ATTRIB, TYPE_DNS, TYPE_IP, TYPE_OBJECT, TYPE_NETWORK, \
    TYPE_HOST, TYPE_RANGE, SERVICE_OBJECT_TYPE_PREDEFINED, SERVICE_OBJECT_TYPE_PROTOCOL, \
    SERVICE_OBJECT_TYPE_APPLICATION_IDENTITY, TYPE_INTERNET

from pytos.securechange.xml_objects.restapi.step.access_request.analysisresult import Analysis_Result
from pytos.securechange.xml_objects.base_types import Target_Base, Access_Request_Target, Step_Multi_Field_Base
from pytos.securechange.xml_objects.restapi.step.access_request.risk import Risk_Analysis_Result
