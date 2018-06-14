
from pytos.securechange.xml_objects.restapi.step.initialize import *
from pytos.securechange.xml_objects.restapi.step.access_request.analysisresult import Analysis_Result
from pytos.common.definitions import xml_tags

logger = logging.getLogger(XML_LOGGER_NAME)


class Compliance_Rule(XML_Object_Base):
    def __init__(self, number, name):
        self.number = number
        self.name = name
        super().__init__(Elements.COMPLIANCE_RULE)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        number = get_xml_text_value(xml_node, Elements.NUMBER)
        name = get_xml_text_value(xml_node, Elements.NAME)
        return cls(number, name)


class Compliance_Policy(XML_Object_Base):
    def __init__(self, name, policy_type, compliance_rules):
        self.name = name
        self.type = policy_type
        self.compliance_rules = compliance_rules
        super().__init__(Elements.COMPLIANCE_POLICY)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, Elements.NAME)
        rule_type = get_xml_text_value(xml_node, Elements.TYPE)
        compliance_rules = XML_List.from_xml_node_by_tags(xml_node, Elements.COMPLIANCE_RULES, Elements.COMPLIANCE_RULE,
                                                          Compliance_Rule, True)
        return cls(name, rule_type, compliance_rules)


class Risk_Analysis_Result(Analysis_Result):
    HAS_RISK = "has risk"
    MANUALLY_DISREGARDED = "manually disregarded"

    def __init__(self, status, compliance_policies, security_policy_violations, reason):
        self.compliance_policies = compliance_policies
        self.security_policy_violations = security_policy_violations
        self.reason = reason
        super().__init__(Elements.RISK_ANALYSIS_RESULT, status)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        status = get_xml_text_value(xml_node, Elements.STATUS)
        compliance_policies = XML_List.from_xml_node_by_tags(xml_node, Elements.COMPLIANCE_POLICIES,
                                                             Elements.COMPLIANCE_POLICY, Compliance_Policy, True)
        security_policy_violations = XML_List.from_xml_node_by_tags(xml_node, Elements.SECURITY_POLICY_VIOLATIONS,
                                                                    Elements.SECURITY_POLICY_VIOLATION,
                                                                    Security_Policy_Violation, True)
        reason = get_xml_text_value(xml_node, Elements.REASON)
        return cls(status, compliance_policies, security_policy_violations, reason)

    def is_manually_disregarded(self):
        return self.status == Risk_Analysis_Result.MANUALLY_DISREGARDED

    def has_risk(self):
        return self.status == Risk_Analysis_Result.HAS_RISK


class Security_Zone_Matrix(XML_Object_Base):
    def __init__(self, name):
        self.name = name
        super().__init__(Elements.SECURITY_ZONE_MATRIX)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, Elements.NAME)
        return cls(name)


class Security_Policy_Violation(XML_Object_Base):
    def __init__(self, severity, security_zone_matrix, matrix_cell_violation):
        self.severity = severity
        self.security_zone_matrix = security_zone_matrix
        self.matrix_cell_violation = matrix_cell_violation
        super().__init__(Elements.SECURITY_POLICY_VIOLATION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        severity = get_xml_text_value(xml_node, Elements.SEVERITY)
        security_zone_matrix_node = get_xml_node(xml_node, Elements.SECURITY_ZONE_MATRIX)
        security_zone_matrix = Security_Zone_Matrix.from_xml_node(security_zone_matrix_node)
        matrix_cell_violation_node = get_xml_node(xml_node, Elements.MATRIX_CELL_VIOLATION)
        matrix_cell_violation = MatrixCellViolation.from_xml_node(matrix_cell_violation_node)
        return cls(severity, security_zone_matrix, matrix_cell_violation)


class MatrixCellViolation(XML_Object_Base, metaclass=SubclassWithIdentifierRegistry):
    """Base Binding Class that handles all Binding sub Binding DTO parsing"""

    @classmethod
    def from_xml_node(cls, xml_node):
        if xml_node is None:
            return None
        try:
            matrix_cell_type = xml_node.attrib[Attributes.XSI_NAMESPACE_TYPE]
        except KeyError:
            msg = 'XML node is missing the XSI attribute "{}"'.format(Attributes.XSI_NAMESPACE_TYPE)
            logger.error(msg)
            raise ValueError(msg)
        else:
            try:
                return cls.registry[matrix_cell_type](xml_node)
            except KeyError:
                logger.error('Unknown binding object type "{}"'.format(matrix_cell_type))


class RestrictedCellViolation(MatrixCellViolation):
    class_identifier = Attributes.RESTRICTED_CELL_VIOLATION

    def __init__(self, xml_node):
        super().__init__(Elements.MATRIX_CELL_VIOLATION)

        args = (xml_node, Elements.ALLOWED_SERVICES, Elements.ALLOWED_SERVICE, ViolationNetworkObject)
        self.allowed_services = XML_List.from_xml_node_by_tags(*args, optional=True)
        args = (xml_node, Elements.NOT_ALLOWED_SERVICES, Elements.NOT_ALLOWED_SERVICE, ViolationNetworkObject)
        self.not_allowed_services = XML_List.from_xml_node_by_tags(*args, optional=True)
        self.flow_sources = XML_List.from_xml_node_by_tags(xml_node, Elements.FLOW_SOURCES, Elements.FLOW_SOURCE,
                                                           ViolationNetworkObject, optional=True)
        self.flow_destinations = XML_List.from_xml_node_by_tags(xml_node, Elements.FLOW_DESTINATIONS,
                                                                Elements.FLOW_DESTINATION, ViolationNetworkObject,
                                                                optional=True)
        self.flow = get_xml_text_value(xml_node, Elements.FLOW)
        self.sources = XML_List.from_xml_node_by_tags(xml_node, Elements.SOURCES, Elements.SOURCE,
                                                      ViolationNetworkObject)
        self.destinations = XML_List.from_xml_node_by_tags(xml_node, Elements.DESTINATIONS, Elements.DESTINATION,
                                                           ViolationNetworkObject)
        self.from_zone = get_xml_text_value(xml_node, Elements.FROM_ZONE)
        self.to_zone = get_xml_text_value(xml_node, Elements.TO_ZONE)

        self.set_attrib(Attributes.XSI_TYPE, Attributes.RESTRICTED_CELL_VIOLATION)


class BlockedCellViolation(MatrixCellViolation):
    def __init__(self, xml_node):
        self.from_zone = get_xml_text_value(xml_node, Elements.FROM_ZONE)
        self.to_zone = get_xml_text_value(xml_node, Elements.TO_ZONE)
        self.sources = XML_List.from_xml_node_by_tags(xml_node, Elements.SOURCES, Elements.SOURCE,
                                                      ViolationNetworkObject)
        self.destinations = XML_List.from_xml_node_by_tags(xml_node, Elements.DESTINATIONS, Elements.DESTINATION,
                                                           ViolationNetworkObject)
        self.flow_sources = XML_List.from_xml_node_by_tags(xml_node, Elements.FLOW_SOURCES, Elements.FLOW_SOURCE,
                                                           ViolationNetworkObject, optional=True)
        self.flow_destinations = XML_List.from_xml_node_by_tags(xml_node, Elements.FLOW_DESTINATIONS,
                                                                Elements.FLOW_DESTINATION, ViolationNetworkObject,
                                                                optional=True)
        args = (xml_node, Elements.ALLOWED_SERVICES, Elements.ALLOWED_SERVICE, ViolationNetworkObject)
        self.allowed_services = XML_List.from_xml_node_by_tags(*args, optional=True)
        args = (xml_node, Elements.NOT_ALLOWED_SERVICES, Elements.NOT_ALLOWED_SERVICE, ViolationNetworkObject)
        self.not_allowed_services = XML_List.from_xml_node_by_tags(*args, optional=True)
        super().__init__(Elements.MATRIX_CELL_VIOLATION)


class BlockedAllCellViolation(BlockedCellViolation):
        """The class represents the acl_binding_object which is sub type of Binding_DTO"""
        class_identifier = Attributes.BLOCK_CELL_VIOLATION

        def __init__(self, xml_node):
            super().__init__(xml_node)
            self.set_attrib(Attributes.XSI_TYPE, Attributes.BLOCK_CELL_VIOLATION)


class BlockedOnlyCellViolation(BlockedCellViolation):
        """The class represents the acl_binding_object which is sub type of Binding_DTO"""
        class_identifier = Attributes.BLOCK_ONLY_MATRIX_CELL_VIOLATION

        def __init__(self, xml_node):
            super().__init__(xml_node)
            self.set_attrib(Attributes.XSI_TYPE, Attributes.BLOCK_ONLY_MATRIX_CELL_VIOLATION)


class ViolationNetworkObjectMetaclass(type):
    def __init__(cls, name, bases, dct):
        if not hasattr(cls, 'registry'):
            cls.registry = {Elements.SOURCE: dict(),
                            Elements.DESTINATION: dict(),
                            Elements.FLOW_SOURCE: dict(),
                            Elements.FLOW_DESTINATION: dict(),
                            Elements.ALLOWED_SERVICE: dict(),
                            Elements.NOT_ALLOWED_SERVICE: dict()}
        else:
            try:
                if dct["element"] == Elements.SOURCE:
                    cls.registry[Elements.SOURCE].update({dct["class_id"]: cls})

                elif dct["element"] == Elements.DESTINATION:
                    cls.registry[Elements.DESTINATION].update({dct["class_id"]: cls})

                elif dct["element"] == Elements.FLOW_SOURCE:
                    cls.registry[Elements.FLOW_SOURCE].update({dct["class_id"]: cls})

                elif dct["element"] == Elements.FLOW_DESTINATION:
                    cls.registry[Elements.FLOW_DESTINATION].update({dct["class_id"]: cls})

                elif dct["element"] == Elements.ALLOWED_SERVICE:
                    cls.registry[Elements.ALLOWED_SERVICE].update({dct["class_id"]: cls})

                elif dct["element"] == Elements.NOT_ALLOWED_SERVICE:
                    cls.registry[Elements.NOT_ALLOWED_SERVICE].update({dct["class_id"]: cls})

            except KeyError:
                pass
        super().__init__(name, bases, dct)


class ViolationNetworkObject(XML_Object_Base, metaclass=ViolationNetworkObjectMetaclass):
    @classmethod
    def from_xml_node(cls, xml_node):
        try:
            violation_type = xml_node.attrib[Attributes.XSI_NAMESPACE_TYPE]
        except KeyError:
            try:
                object_type = xml_node.attrib[xml_tags.TYPE_ATTRIB]
            except KeyError:
                # a workaround a bug. Some object types (such as Internet) have no xsi:type or type.
                # Checking these based on their "name" tag
                if xml_node.find('name').text.lower() == Attributes.INTERNET.lower():
                    return cls.registry[xml_node.tag][Attributes.INTERNET].from_xml_node(xml_node)
                else:
                    msg = 'XML node is missing the XSI attribute "{}"'.format(Attributes.XSI_NAMESPACE_TYPE)
                    logger.error(msg)
                    raise ValueError(msg)
        else:
            try:
                return cls.registry[xml_node.tag][violation_type].from_xml_node(xml_node)
            except KeyError:
                logger.error('Unknown violation object type "{}"'.format(violation_type))


class Violation_Any_Service(ViolationNetworkObject):
    def __init__(self, target_type_tag):
        super().__init__(target_type_tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.VIOLATION_ANY_SERVICE)

    @classmethod
    def from_xml_node(cls, xml_node):
        return cls()


class Violation_Allowed_Any_Service(Violation_Any_Service):
    class_id = Attributes.VIOLATION_ANY_SERVICE
    element = Elements.ALLOWED_SERVICE

    def __init__(self):
        super().__init__(Elements.ALLOWED_SERVICE)


class Violation_Not_Allowed_Any_Service(Violation_Any_Service):
    class_id = Attributes.VIOLATION_ANY_SERVICE
    element = Elements.NOT_ALLOWED_SERVICE

    def __init__(self):
        super().__init__(Elements.NOT_ALLOWED_SERVICE)


class Violation_Single_Service(ViolationNetworkObject):
    def __init__(self, name, protocol, port, target_type_tag):
        self.name = name
        self.protocl = protocol
        self.mask = port
        super().__init__(target_type_tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.VIOLATION_SINGLE_SERVICE)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, Elements.NAME)
        protocol = get_xml_text_value(xml_node, Elements.PROTOCOL)
        port = get_xml_text_value(xml_node, Elements.PORT)
        return cls(name, protocol, port)


class Violation_Allowed_Single_Service(Violation_Single_Service):
    class_id = Attributes.VIOLATION_SINGLE_SERVICE
    element = Elements.ALLOWED_SERVICE

    def __init__(self, name, protocol, port):
        super().__init__(name, protocol, port, Elements.ALLOWED_SERVICE)


class Violation_Not_Allowed_Single_Service(Violation_Single_Service):
    class_id = Attributes.VIOLATION_SINGLE_SERVICE
    element = Elements.NOT_ALLOWED_SERVICE

    def __init__(self, name, protocol, port):
        super().__init__(name, protocol, port, Elements.NOT_ALLOWED_SERVICE)


class Violation_Single_Service_Object(ViolationNetworkObject):
    def __init__(self, name, uid, management_id, target_type_tag):
        self.name = name
        self.uid = uid
        self.management_id = management_id
        super().__init__(target_type_tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.VIOLATION_SINGLE_SERVICE_OBJECT)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, Elements.NAME)
        uid = get_xml_text_value(xml_node, Elements.UID)
        management_id = get_xml_text_value(xml_node, Elements.MANAGEMENT_ID)
        return cls(name, uid, management_id)


class Violation_Allowed_Single_Service_Object(Violation_Single_Service_Object):
    class_id = Attributes.VIOLATION_SINGLE_SERVICE_OBJECT
    element = Elements.ALLOWED_SERVICE

    def __init__(self, name, uid, management_id):
        super().__init__(name, uid, management_id, Elements.ALLOWED_SERVICE)


class Violation_Not_Allowed_Single_Service_Object(Violation_Single_Service_Object):
    class_id = Attributes.VIOLATION_SINGLE_SERVICE_OBJECT
    element = Elements.NOT_ALLOWED_SERVICE

    def __init__(self, name, uid, management_id):
        super().__init__(name, uid, management_id, Elements.NOT_ALLOWED_SERVICE)


class Violation_Any_Target(XML_Object_Base):
    def __init__(self, target_type_tag):
        super().__init__(target_type_tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.VIOLATION_ANY_NETWORK_OBJECT)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        raise NotImplementedError(
            "from_xml_node must be implemented by derived classes.")


class Violation_Any_Source(ViolationNetworkObject):
    class_id = Attributes.VIOLATION_ANY_NETWORK_OBJECT
    element = Elements.SOURCE

    def __init__(self):
        super().__init__(Elements.SOURCE)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.VIOLATION_ANY_NETWORK_OBJECT)

    @classmethod
    def from_xml_node(cls, xml_node):
        return cls()


class Violation_Any_Destination(ViolationNetworkObject):
    class_id = Attributes.VIOLATION_ANY_NETWORK_OBJECT
    element = Elements.DESTINATION

    def __init__(self):
        super().__init__(Elements.DESTINATION)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.VIOLATION_ANY_NETWORK_OBJECT)

    @classmethod
    def from_xml_node(cls, xml_node):
        return cls()


class Violation_IP_Target(ViolationNetworkObject):
    def __init__(self, name, ip, mask, target_type_tag):
        self.name = name
        self.ip = ip
        self.mask = mask
        super().__init__(target_type_tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.VIOLATION_IP_NETWORK_OBJECT)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        raise NotImplementedError(
            "from_xml_node must be implemented by derived classes.")


class Violation_IP_Source(Violation_IP_Target):
    class_id = Attributes.VIOLATION_IP_NETWORK_OBJECT
    element = Elements.SOURCE

    def __init__(self, name, ip, mask):
        super().__init__(name, ip, mask, Elements.SOURCE)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, Elements.NAME)
        ip = get_xml_text_value(xml_node, Elements.IP)
        mask = get_xml_text_value(xml_node, Elements.MASK)
        return cls(name, ip, mask)


class Violation_IP_Flow_Source(Violation_IP_Target):
    class_id = Attributes.VIOLATION_IP_NETWORK_OBJECT
    element = Elements.FLOW_SOURCE

    def __init__(self, name, ip, mask):
        super().__init__(name, ip, mask, Elements.FLOW_SOURCE)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, Elements.NAME)
        ip = get_xml_text_value(xml_node, Elements.IP)
        mask = get_xml_text_value(xml_node, Elements.MASK)
        return cls(name, ip, mask)


class Violation_IP_Destination(Violation_IP_Target):
    class_id = Attributes.VIOLATION_IP_NETWORK_OBJECT
    element = Elements.DESTINATION

    def __init__(self, name, ip, mask):
        super().__init__(name, ip, mask, Elements.DESTINATION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, Elements.NAME)
        ip = get_xml_text_value(xml_node, Elements.IP)
        mask = get_xml_text_value(xml_node, Elements.MASK)
        return cls(name, ip, mask)


class Violation_IP_Flow_Destination(Violation_IP_Target):
    class_id = Attributes.VIOLATION_IP_NETWORK_OBJECT
    element = Elements.FLOW_DESTINATION

    def __init__(self, name, ip, mask):
        super().__init__(name, ip, mask, Elements.FLOW_DESTINATION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, Elements.NAME)
        ip = get_xml_text_value(xml_node, Elements.IP)
        mask = get_xml_text_value(xml_node, Elements.MASK)
        return cls(name, ip, mask)


class Violation_Single_Target(ViolationNetworkObject):
    def __init__(self, uid, management_id, name, target_type_tag):
        self.uid = uid
        self.management_id = management_id
        self.name = name
        super().__init__(target_type_tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.VIOLATION_SINGLE_NETWORK_OBJECT)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, Elements.NAME)
        management_id = get_xml_text_value(xml_node, Elements.MANAGEMENT_ID)
        uid = get_xml_text_value(xml_node, Elements.UID)
        return cls(uid, management_id, name)


class Violation_Single_Source(Violation_Single_Target):
    class_id = Attributes.VIOLATION_SINGLE_NETWORK_OBJECT
    element = Elements.SOURCE

    def __init__(self, uid, management_id, name):
        super().__init__(uid, management_id, name, Elements.SOURCE)


class Violation_Single_Destination(Violation_Single_Target):
    class_id = Attributes.VIOLATION_SINGLE_NETWORK_OBJECT
    element = Elements.DESTINATION

    def __init__(self, uid, management_id, name):
        super().__init__(uid, management_id, name, Elements.DESTINATION)


class Violation_Group_Target(ViolationNetworkObject):
    def __init__(self, group_member_path, name, group_member, target_type_tag):
        self.group_member_path = group_member_path
        self.name = name
        self.group_member = group_member
        super().__init__(target_type_tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.VIOLATION_GROUP_NETWORK_OBJECT)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        raise NotImplementedError("from_xml_node must be implemented by derived classes.")


class Violation_Single_Group(Violation_Single_Target):
    def __init__(self, uid, management_id, name):
        super().__init__(uid, management_id, name, Elements.GROUP_MEMBER)


class Violation_Group_Source(Violation_Group_Target):
    class_id = Attributes.VIOLATION_GROUP_NETWORK_OBJECT
    element = Elements.SOURCE

    def __init__(self, group_member_path, name, group_member):
        super().__init__(group_member_path, name, group_member, Elements.SOURCE)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        group_member_path = get_xml_text_value(xml_node, Elements.GROUP_MEMBER_PATH)
        name = get_xml_text_value(xml_node, Elements.NAME)
        group_member_node = get_xml_node(xml_node, Elements.GROUP_MEMBER)
        group_member = Violation_Single_Group.from_xml_node(group_member_node)
        return cls(group_member_path, name, group_member)


class Violation_Group_Destination(Violation_Group_Target):
    class_id = Attributes.VIOLATION_GROUP_NETWORK_OBJECT
    element = Elements.DESTINATION

    def __init__(self, group_member_path, name, group_member):
        super().__init__(group_member_path, name, group_member, Elements.DESTINATION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        group_member_path = get_xml_text_value(xml_node, Elements.GROUP_MEMBER_PATH)
        name = get_xml_text_value(xml_node, Elements.NAME)
        group_member_node = get_xml_node(xml_node, Elements.GROUP_MEMBER)
        group_member = Violation_Single_Group.from_xml_node(group_member_node)
        return cls(group_member_path, name, group_member)


class Violation_IP_Range(ViolationNetworkObject):
    def __init__(self, name, min_ip, max_ip, target_type_tag):
        self.name = name
        self.min_ip = min_ip
        self.max_ip = max_ip
        super().__init__(target_type_tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.VIOLATION_RANGE_NETWORK_OBJECT)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, Elements.NAME)
        min_ip = get_xml_text_value(xml_node, Elements.MIN_IP)
        max_ip = get_xml_text_value(xml_node, Elements.MAX_IP)
        return cls(name, min_ip, max_ip, xml_node.tag)


class Violation_IP_Range_Source(Violation_IP_Range):
    class_id = Attributes.VIOLATION_RANGE_NETWORK_OBJECT
    element = Elements.SOURCE

    def __init__(self, name, min_ip, max_ip):
        super().__init__(name, min_ip, max_ip, Elements.SOURCE)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, Elements.NAME)
        min_ip = get_xml_text_value(xml_node, Elements.MIN_IP)
        max_ip = get_xml_text_value(xml_node, Elements.MAX_IP)
        return cls(name, min_ip, max_ip)


class Violation_IP_Range_Destination(Violation_IP_Range):
    class_id = Attributes.VIOLATION_RANGE_NETWORK_OBJECT
    element = Elements.DESTINATION

    def __init__(self, name, min_ip, max_ip):
        super().__init__(name, min_ip, max_ip, Elements.DESTINATION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, Elements.NAME)
        min_ip = get_xml_text_value(xml_node, Elements.MIN_IP)
        max_ip = get_xml_text_value(xml_node, Elements.MAX_IP)
        return cls(name, min_ip, max_ip)


class Violation_Group_Member(XML_Object_Base):
    def __init__(self, uid, management_id):
        self.uid = uid
        self.management_id = management_id
        super().__init__(Elements.GROUP_MEMBER)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        uid = get_xml_text_value(xml_node, Elements.UID)
        management_id = get_xml_int_value(xml_node, Elements.MANAGEMENT_ID)
        return cls(uid, management_id)


class Violation_Group_Member_service_Object(ViolationNetworkObject):
    def __init__(self, group_member_path, group_member, target_type_tag):
        self.group_member_path = group_member_path
        self.group_member = group_member
        super().__init__(target_type_tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.VIOLATION_GROUP_MEMBER_SERVICE_OBJECT)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        group_member_path = get_xml_text_value(xml_node, Elements.GROUP_MEMBER_PATH)
        group_member = Violation_Group_Member.from_xml_node(get_xml_node(xml_node, Elements.GROUP_MEMBER))
        return cls(group_member_path, group_member)


class Violation_Allowed_Group_Member_service_Object(Violation_Group_Member_service_Object):
    class_id = Attributes.VIOLATION_GROUP_MEMBER_SERVICE_OBJECT
    element = Elements.ALLOWED_SERVICE

    def __init__(self, group_member_path, group_member):
        super().__init__(group_member_path, group_member, Elements.ALLOWED_SERVICE)


class Violation_Not_Allowed_Group_Member_service_Object(Violation_Group_Member_service_Object):
    class_id = Attributes.VIOLATION_GROUP_MEMBER_SERVICE_OBJECT
    element = Elements.NOT_ALLOWED_SERVICE

    def __init__(self, group_member_path, group_member):
        super().__init__(group_member_path, group_member, Elements.NOT_ALLOWED_SERVICE)
