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
from pytos.common.definitions.XML_Tags import Elements
from pytos.common.functions.XML import get_xml_text_value, get_xml_int_value, get_xml_node

logger = logging.getLogger(XML_LOGGER_NAME)


class DCR_Test_Base(XML_Object_Base):
    def __init__(self, xml_tag, num_id, group_id, name):
        self.id = num_id
        self.groupId = group_id
        self.name = name
        super().__init__(xml_tag)


class DCR_Test_Group(DCR_Test_Base):
    def __init__(self, num_id, group_id, name, dcr_tests):
        self.dcr_tests = dcr_tests
        super().__init__(Elements.DCR_TEST_GROUP, num_id, group_id, name)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        group_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        dcr_tests = XML_List.from_xml_node_by_tags(xml_node, Elements.DCR_TESTS, Elements.DCR_TEST_CONCRETE,
                                                   DCR_Test_Concrete)
        return cls(num_id, group_id, name, dcr_tests)


class DCR_Test_Concrete(DCR_Test_Base):
    def __init__(self, num_id, groupId, name, isActive, isDefault, risk, severity, testDef, testUid, testParams):
        self.isActive = isActive
        self.isDefault = isDefault
        self.risk = risk
        self.severity = severity
        self.testDef = testDef
        self.testUid = testUid
        self.testParams = testParams
        super().__init__(Elements.DCR_TEST_CONCRETE, num_id, groupId, name)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        groupid = get_xml_int_value(xml_node, Elements.GROUPID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        isactive = get_xml_text_value(xml_node, Elements.ISACTIVE)
        isdefault = get_xml_text_value(xml_node, Elements.ISDEFAULT)
        risk = get_xml_text_value(xml_node, Elements.RISK)
        severity = get_xml_text_value(xml_node, Elements.SEVERITY)
        testuid = get_xml_text_value(xml_node, Elements.TESTUID)
        test_params = []
        for test_param_node in xml_node.iter(tag=Elements.TESTPARAMS):
            test_params.append(DCR_Test_Param.from_xml_node(test_param_node))
        testdef_node = get_xml_node(xml_node, Elements.TESTDEF)
        testdef = DCR_Test_Definition.from_xml_node(testdef_node)

        return cls(num_id, groupid, name, isactive, isdefault, risk, severity, testdef, testuid, test_params)


class DCR_Test_Definition(XML_Object_Base):
    def __init__(self, num_id, description, expression, test_input, isCustom, mustContain, name, products, remediation,
                 testDefUid, test_type, blockStart, blockEnd):
        self.description = description
        self.expression = expression
        self.input = test_input
        self.isCustom = isCustom
        self.mustContain = mustContain
        self.name = name
        self.id = num_id
        self.products = products
        self.remediation = remediation
        self.testDefUid = testDefUid
        self.type = test_type  # line_match|all_line_match|block_match|multiline_match
        self.blockStart = blockStart
        self.blockEnd = blockEnd
        super().__init__(Elements.TESTDEF)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        description = get_xml_text_value(xml_node, Elements.DESCRIPTION)
        expression = get_xml_text_value(xml_node, Elements.EXPRESSION)
        test_input = get_xml_text_value(xml_node, Elements.INPUT)
        isCustom = get_xml_text_value(xml_node, Elements.ISCUSTOM)
        mustContain = get_xml_text_value(xml_node, Elements.MUSTCONTAIN)
        name = get_xml_text_value(xml_node, Elements.NAME)
        remediation = get_xml_text_value(xml_node, Elements.REMEDIATION)
        testDefUid = get_xml_text_value(xml_node, Elements.TESTDEFUID)
        test_type = get_xml_text_value(xml_node, Elements.TYPE)
        products_node = get_xml_node(xml_node, Elements.PRODUCTS)
        products = DCR_Test_Product.from_xml_node(products_node)
        blockStart = get_xml_text_value(xml_node, Elements.BLOCKSTART)
        blockEnd = get_xml_text_value(xml_node, Elements.BLOCKEND)
        return cls(num_id, description, expression, test_input, isCustom, mustContain, name, products, remediation,
                   testDefUid, test_type, blockStart, blockEnd)


class DCR_Test_Product(XML_Object_Base):
    def __init__(self, device, product_id, vendor):
        self.device = device
        self.id = product_id
        self.vendor = vendor  # As per management_type table
        super().__init__(Elements.DCR_PRODUCT)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        device = get_xml_text_value(xml_node, Elements.DEVICE)
        product_id = get_xml_int_value(xml_node, Elements.ID)
        vendor = get_xml_text_value(xml_node, Elements.VENDOR)
        return cls(device, product_id, vendor)


class DCR_Test_Param(XML_Object_Base):
    def __init__(self, num_id, isMandatory, name, param_type, param_value, displayName):
        self.id = num_id
        self.isMandatory = isMandatory
        self.name = name
        self.type = param_type
        self.value = param_value
        self.displayName = displayName
        super().__init__(Elements.TESTPARAMS)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        param_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        displayName = get_xml_text_value(xml_node, Elements.DISPLAYNAME)
        isMandatory = get_xml_text_value(xml_node, Elements.ISMANDATORY)
        value = get_xml_text_value(xml_node, Elements.VALUE)
        param_type = get_xml_text_value(xml_node, Elements.TYPE)
        return cls(param_id, isMandatory, name, param_type, value, displayName)


class Test_Products(XML_List):
    TAG_TO_CLASS = {Elements.DCR_PRODUCT: DCR_Test_Product}

    def __init__(self, products):
        super().__init__(Elements.TEST_PRODUCTS, products)

    @classmethod
    def from_xml_node(cls, xml_node):
        return XML_List.from_xml_node_by_tag_dict(xml_node, Elements.TEST_PRODUCTS, cls.TAG_TO_CLASS)
