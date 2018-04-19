from pytos.securechange.xml_objects.restapi.step.access_request.accessrequest import Any_Access_Request_Device, \
    Named_Access_Request_Device, IP_Range_Access_Request_Target, IP_Access_Request_Target, Object_Access_Request_Target, \
    Internet_Access_Request_Target, Any_Access_Request_Target, DNS_Access_Request_Target, \
    LDAP_Entity_Access_Request_Target
from pytos.securechange.xml_objects.restapi.step.initialize import *

logger = logging.getLogger(XML_LOGGER_NAME)


class Step_Field_Server_Decommission(Step_Multi_Field_Base):
    FIELD_CONTENT_ATTRIBUTES = "server_decommission_request"

    def __init__(self, num_id, name, server_decommission_requests, read_only=None):
        if server_decommission_requests is None:
            server_decommission_requests = []
        self.server_decommission_requests = server_decommission_requests
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_MULTI_SERVER_DECOMMISSION_REQUEST)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        server_decommission_requests = []
        for server_decommission_request_node in xml_node.findall(Elements.SERVER_DECOMMISSION_REQUEST):
            server_decommission_request = ServerDecommissionRequest.from_xml_node(server_decommission_request_node)
            server_decommission_requests.append(server_decommission_request)

        return cls(num_id, name, server_decommission_requests, read_only)

    def to_pretty_str(self):
        # TODO: Implement this function
        pass


class ServerDecommissionRequest(XML_Object_Base):
    def __init__(self, server_decommission_id, order, targets, servers, comment, domain,
                 designer_result=None, verifier_result=None,
                 impact_analysis_result=None, reado_only=None):
        self.id = server_decommission_id
        self.order = order
        self.targets = XML_List(Elements.TARGETS, targets)
        self.servers = XML_List(Elements.SERVERS, servers)
        self.comment = comment
        self.designer_results = designer_result
        self.verifier_result = verifier_result
        self.impact_analysis_result = impact_analysis_result
        if domain:
            self.domain = domain
        self.read_only = reado_only
        super().__init__(Elements.SERVER_DECOMMISSION_REQUEST)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        order = get_xml_text_value(xml_node, Elements.ORDER)
        server_decommission_id = get_xml_int_value(xml_node, Elements.ID)
        comment = get_xml_text_value(xml_node, Elements.COMMENT)
        reado_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        device_type_to_class_dict = {TYPE_ANY: Any_Access_Request_Device, TYPE_OBJECT: Named_Access_Request_Device}
        targets = XML_List.from_xml_node_by_type_dict(xml_node, Elements.TARGETS, Elements.TARGET,
                                                      device_type_to_class_dict)

        server_type_to_class_dict = {TYPE_RANGE: IP_Range_Access_Request_Target, TYPE_IP: IP_Access_Request_Target,
                                     TYPE_DNS: DNS_Access_Request_Target, TYPE_OBJECT: Object_Access_Request_Target,
                                     TYPE_ANY: Any_Access_Request_Target, TYPE_INTERNET: Internet_Access_Request_Target,
                                     TYPE_LDAP_ENTITY: LDAP_Entity_Access_Request_Target}

        servers = XML_List.from_xml_node_by_type_dict(xml_node, Elements.SERVERS, Elements.SERVER,
                                                      server_type_to_class_dict)

        domain = get_xml_text_value(xml_node, Elements.DOMAIN)

        # TODO: Implement

        designer_result = None
        verifier_result = None
        impact_analysis_result = None

        return cls(server_decommission_id, order, targets, servers, comment, domain,
                   designer_result, verifier_result, impact_analysis_result, reado_only)

    def to_pretty_str(self):
        server_decommission_request_string = "Server Decommission {}:\n".format(self.order)
        server_decommission_request_string += "\tTargets: "
        for target in self.targets:
            server_decommission_request_string += target.to_pretty_str()
            server_decommission_request_string += "\n\tServers: "
        for server in self.servers:
            server_decommission_request_string += server.to_pretty_str()
        if self.comment is not None:
            server_decommission_request_string += "\n" + textwrap.fill(
                "\tComment: {}".format(unescape(self.comment)),
                initial_indent='', subsequent_indent='\t\t ')
        return server_decommission_request_string

    def __str__(self):
        return self.to_pretty_str()

