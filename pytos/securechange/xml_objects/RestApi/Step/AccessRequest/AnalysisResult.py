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
from pytos.securechange.xml_objects.RestApi.Step.AccessRequest.initialize import *


class Analysis_Result(XML_Object_Base):
    IMPLEMENTED = "implemented"
    NOT_AVAILABLE = "not available"
    NOT_IMPLEMENTED = "not implemented"
    NOT_RUN = "not run"
    VERIFIED = "verified"

    def __init__(self, xml_tag, status):
        self.status = status
        super().__init__(xml_tag)

    def is_not_run(self):
        if self.status == Analysis_Result.NOT_RUN:
            return True
        else:
            return False

    def is_not_available(self):
        if self.status == Analysis_Result.NOT_AVAILABLE:
            return True
        else:
            return False

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        raise NotImplementedError(
                "from_xml_node must be implemented by derived classes.")