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
import textwrap
import netaddr
import socket
import itertools
import requests
from xml.sax.saxutils import unescape
import xml.etree.ElementTree as ET

from pytos.common.base_types import XML_Object_Base, XML_List, Flat_XML_Object_Base, ReferenceURL, SubclassWithIdentifierRegistry
from pytos.common.definitions.XML_Tags import Elements, Attributes
from pytos.common.functions.XML import get_xml_text_value, get_xml_node, get_xml_int_value
from pytos.common.logging.Defines import XML_LOGGER_NAME
from pytos.common.helpers import Secure_API_Helper
from pytos.common.exceptions import REST_Service_Unavailable_Error
from pytos.common.definitions.XML_Tags import TYPE_ANY, TYPE_ATTRIB, TYPE_DNS, TYPE_IP, TYPE_OBJECT, TYPE_NETWORK, \
    TYPE_HOST, TYPE_RANGE, SERVICE_OBJECT_TYPE_PREDEFINED, SERVICE_OBJECT_TYPE_PROTOCOL, \
    SERVICE_OBJECT_TYPE_APPLICATION_IDENTITY, TYPE_INTERNET

from pytos.securechange.xml_objects.restapi.Step.AccessRequest.AnalysisResult import Analysis_Result
from pytos.securechange.xml_objects.base_types import Target_Base, Access_Request_Target, Step_Multi_Field_Base
from pytos.securechange.xml_objects.restapi.Step.AccessRequest.Risk import Risk_Analysis_Result
