
import os
from pathlib import Path
from mako.template import Template
from pytos.securechange.xml_objects.restapi.step.access_request.designer import *
from pytos.securechange.xml_objects.restapi.step.access_request.verifier import *
from pytos.securechange.xml_objects.restapi.step.access_request.risk import *

logger = logging.getLogger(XML_LOGGER_NAME)
dir_path = list(Path(os.path.abspath(__file__)).parts[:-5])
dir_path.append('templates/risk_analysis_template.html')
RISK_ANALYSIS_HTML_PATH = os.path.join(*tuple(dir_path))


class Label(Flat_XML_Object_Base):
    def __init__(self, label):
        super().__init__(Elements.LABEL, content=label)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        label = xml_node.text
        return cls(label)


class Application_Target(XML_Object_Base):
    def __init__(self, application):
        self.application = [application]
        super().__init__(Elements.APPLICATION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        application = get_xml_text_value(xml_node, Elements.APPLICATION)
        return cls(application)

    def to_pretty_str(self):
        if self.application[0] is not None:
            return "\n\t\tApplication: {}".format(self.application[0])
        else:
            return ""


class Named_Access_Request_Device(Target_Base):
    def __init__(self, num_id, object_name, object_type, object_details, management_name, management_id):

        self.object_name = object_name
        self.object_type = object_type
        self.object_details = object_details
        self.management_name = management_name
        self.management_id = management_id
        super().__init__(Elements.TARGET, num_id, TYPE_OBJECT)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        object_name = get_xml_text_value(xml_node, Elements.OBJECT_NAME)
        object_type = get_xml_text_value(xml_node, Elements.OBJECT_TYPE)
        object_details = get_xml_text_value(xml_node, Elements.OBJECT_DETAILS)
        management_name = get_xml_text_value(xml_node, Elements.MANAGEMENT_NAME)
        management_id = get_xml_int_value(xml_node, Elements.MANAGEMENT_ID)
        return cls(num_id, object_name, object_type, object_details, management_name, management_id)

    def to_pretty_str(self):
        return "\n\t\tManagement Name: {}\n\t\tObject Name: {}\n\t\tObject Details: {}".format(self.management_name,
                                                                                               self.object_name,
                                                                                               self.object_details)

    def __str__(self):
        if all([self.management_name, self.object_name, self.object_details]):
            return "{}/{}/{}".format(self.management_name, self.object_name, self.object_details)
        else:
            return ""


class Any_Access_Request_Device(Target_Base):
    def __init__(self, num_id=None):
        self.management_name = "Any"
        super().__init__(Elements.TARGET, num_id, TYPE_ANY)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        return cls(num_id)

    @staticmethod
    def to_pretty_str():
        return "\n\t\tManagement Name: Any"

    def __str__(self):
        return "Any"


class User_Target(XML_Object_Base):
    def __init__(self, user):
        self.user = [user]
        super().__init__(Elements.USER)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        user = get_xml_text_value(xml_node, Elements.USER)
        return cls(user)

    def to_pretty_str(self):
        if self.user[0] is not None:
            return "\n\t\tUser: {}".format(self.user[0])
        else:
            return ""

    def __str__(self):
        return ",".join(self.user)


class Network_Target(Access_Request_Target):
    def __init__(self, xml_tag, target_id, target_type, region):
        self.region = region
        super().__init__(xml_tag, target_id, target_type)

    def as_netaddr_obj(self):
        raise NotImplementedError

    def as_netaddr_set(self):
        """This returns a netaddr set representing the Network_Target"""
        return netaddr.IPSet(self.as_netaddr_obj())

    def to_pretty_str(self):
        raise NotImplementedError

    def from_xml_node(self, xml_node):
        raise NotImplementedError


class IP_Range_Access_Request_Target(Network_Target):
    def __init__(self, xml_tag, target_id, range_first_ip, range_last_ip, region):
        self.range_first_ip = range_first_ip
        self.range_last_ip = range_last_ip
        super().__init__(xml_tag, target_id, TYPE_RANGE, region)

    def to_pretty_str(self):
        target_string = "\n\t\tFirst IP Address: {}\n\t\tLast IP Address: {}".format(self.range_first_ip,
                                                                                     self.range_last_ip)
        return target_string

    def __str__(self):
        return "{}-{}".format(self.range_first_ip, self.range_last_ip)

    def as_netaddr_obj(self):
        """This returns a netaddr object representing the Ranged_Network_Target"""
        return netaddr.IPRange(self.range_first_ip, self.range_last_ip)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        range_first_ip = get_xml_text_value(xml_node, Elements.RANGE_FIRST_IP)
        range_last_ip = get_xml_text_value(xml_node, Elements.RANGE_LAST_IP)
        target_id = get_xml_int_value(xml_node, Elements.ID)
        region = get_xml_text_value(xml_node, Elements.REGION)
        return cls(xml_node.tag, target_id, range_first_ip, range_last_ip, region)


class IP_Access_Request_Target(Network_Target):
    def __init__(self, xml_tag, target_id, address, netmask, region):
        self.ip_address = address
        self.region = region
        # BUG: The netmask attribute is not always set since when creating an IPv6 target using the REST API
        # the netmask element must not exist (Can't even be empty)

        if netmask:
            self.netmask = netmask
        super().__init__(xml_tag, target_id, TYPE_IP, region)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        target_id = get_xml_int_value(xml_node, Elements.ID)
        region = get_xml_text_value(xml_node, Elements.REGION)
        target_mask = get_xml_text_value(xml_node, Elements.NETMASK)
        target_address = get_xml_text_value(xml_node, Elements.IP_ADDRESS)
        return cls(xml_node.tag, target_id, target_address, target_mask, region)

    def to_pretty_str(self):
        try:
            return "\n\t\tIP Address: {}\n\t\tSubnet Mask: {}".format(self.ip_address, self.netmask)
        except AttributeError:
            return "\n\t\tIP Address: {}\n\t\tSubnet Mask: 255.255.255.255".format(self.ip_address)

    def __str__(self):
        try:
            return "{}/{}".format(self.ip_address, self.netmask)
        except AttributeError:
            return "{}/32".format(self.ip_address)

    def as_netaddr_obj(self):
        """This returns a netaddr object representing the Network_Target"""
        return netaddr.IPNetwork(self.__str__())


class DNS_Access_Request_Target(Network_Target):
    def __init__(self, xml_tag, target_id, address, host_name, region):
        # TODO: resolve dns if no ip address and only hostname
        self.region = region
        self.host_name = host_name
        self.ip_address = address
        super().__init__(xml_tag, target_id, TYPE_DNS, region)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        target_id = get_xml_int_value(xml_node, Elements.ID)
        region = get_xml_text_value(xml_node, Elements.REGION)
        target_hostname = get_xml_text_value(xml_node, Elements.HOST_NAME)
        target_address = get_xml_text_value(xml_node, Elements.IP_ADDRESS)
        return cls(xml_node.tag, target_id, target_address, target_hostname, region)

    def to_pretty_str(self):
        target_string = ""
        if self.ip_address:
            target_string += "\n\t\tIP Address: {}".format(self.ip_address)
        if self.host_name:
            target_string += "\n\t\tHostname: {}".format(self.host_name)
        return target_string

    def __str__(self):
        return "{}/{}".format(self.host_name, self.ip_address)

    def as_netaddr_obj(self):
        """This returns a netaddr object representing the Network_Target"""
        if not self.ip_address and self.host_name:
            return netaddr.IPNetwork(socket.gethostbyname(self.host_name))
        else:
            return netaddr.IPNetwork(self.ip_address)


class Any_Access_Request_Target(Access_Request_Target):
    def __init__(self, xml_tag, num_id, region):
        super().__init__(xml_tag, num_id, TYPE_ANY, region)

    def __str__(self):
        return "Any"

    def to_pretty_str(self):
        return "\n\t\tIP Address: Any"

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        region = get_xml_text_value(xml_node, Elements.REGION)
        num_id = get_xml_int_value(xml_node, Elements.ID)
        return cls(xml_node.tag, num_id, region)

    @staticmethod
    def as_netaddr_obj():
        """This returns a netaddr object representing the Ranged_Network_Target"""
        return netaddr.IPNetwork("0.0.0.0/0")

    def as_netaddr_set(self):
        """This returns a netaddr set representing the Ranged_Network_Target"""
        return netaddr.IPSet(self.as_netaddr_obj())


class Object_Access_Request_Target(Access_Request_Target):
    def __init__(self, xml_tag, target_id, object_name, object_type, object_details, management_name, management_id,
                 object_UID, region):
        self.object_name = object_name
        self.object_type = object_type
        self.object_details = object_details
        self.object_UID = object_UID
        self.management_name = management_name
        self.management_id = management_id
        super().__init__(xml_tag, target_id, TYPE_OBJECT, region)

    def __str__(self):
        return "{}/{}".format(self.object_name, self.object_details)

    def to_pretty_str(self):
        object_string = ""
        if self.management_name:
            object_string += "\n\t\tManagement Name: {}".format(self.management_name)
        if self.object_name:
            object_string += "\n\t\tObject Name: {}".format(self.object_name)
        if self.object_details:
            object_string += "\n\t\tObject Details: {}".format(self.object_details)
        if self.object_UID:
            object_string += "\n\t\tObject UID: {}".format(self.object_UID)
        if self.object_type:
            object_string += "\n\t\tObject Type: {}".format(self.object_type)
        return object_string

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        target_id = get_xml_int_value(xml_node, Elements.ID)
        region = get_xml_text_value(xml_node, Elements.REGION)
        object_name = get_xml_text_value(xml_node, Elements.OBJECT_NAME)
        object_UID = get_xml_text_value(xml_node, Elements.OBJECT_UID)
        object_type = get_xml_text_value(xml_node, Elements.OBJECT_TYPE)
        object_details = get_xml_text_value(xml_node, Elements.OBJECT_DETAILS)
        management_name = get_xml_text_value(xml_node, Elements.MANAGEMENT_NAME)
        management_id = get_xml_int_value(xml_node, Elements.MANAGEMENT_ID)
        return cls(xml_node.tag, target_id, object_name, object_type, object_details, management_name, management_id,
                   object_UID, region)


class Internet_Access_Request_Target(Access_Request_Target):
    def __init__(self, xml_tag, num_id, region):
        super().__init__(xml_tag, num_id, TYPE_INTERNET, region)

    def __str__(self):
        return "Internet"

    def to_pretty_str(self):
        return "\n\t\tIP Address: Internet"

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        region = get_xml_text_value(xml_node, Elements.REGION)
        num_id = get_xml_int_value(xml_node, Elements.ID)
        return cls(xml_node.tag, num_id, region)


class Service_Target(Access_Request_Target):
    def __init__(self, service_id=None, service_type=None):
        super().__init__(Elements.SERVICE, service_id, service_type)

    def to_pretty_str(self):
        raise NotImplementedError

    def from_xml_node(self, xml_node):
        raise NotImplementedError


class Any_Service_Target(Service_Target):
    def __init__(self, num_id=None):
        super().__init__(num_id, TYPE_ANY)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        return cls(num_id)

    def to_pretty_str(self):
        return "\n\t\tService: Any"

    def __str__(self):
        return "Any"


class Protocol_Service_Target(Service_Target):
    def __init__(self, num_id, port, protocol, service_type):
        self.port = port
        self.protocol = protocol
        self.type = service_type
        super().__init__(num_id, SERVICE_OBJECT_TYPE_PROTOCOL)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        protocol = get_xml_text_value(xml_node, Elements.PROTOCOL)
        port = get_xml_text_value(xml_node, Elements.PORT)
        service_type = get_xml_text_value(xml_node, Elements.TYPE)
        return cls(num_id, port, protocol, service_type)

    def to_pretty_str(self):
        return "\n\t\tProtocol: {}\n\t\tPort: {}".format(self.protocol, self.port)

    def __str__(self):
        return "{} {}".format(self.protocol, self.port)


class ApplicationPredefinedServiceTarget(Service_Target):
    def __init__(self, service_id, application_name, services):
        self.id = service_id
        self.application_name = application_name
        self.services = services
        super().__init__(service_id, SERVICE_OBJECT_TYPE_APPLICATION_IDENTITY)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        service_id = get_xml_int_value(xml_node, Elements.ID)
        application_name = get_xml_text_value(xml_node, Elements.APPLICATION_NAME)
        service_type_class_dict = {SERVICE_OBJECT_TYPE_PREDEFINED: Predefined_Service_Target,
                                   SERVICE_OBJECT_TYPE_PROTOCOL: Protocol_Service_Target,
                                   TYPE_OBJECT: Object_Access_Request_Target, TYPE_ANY: Any_Service_Target}
        services = XML_List.from_xml_node_by_type_dict(xml_node, Elements.SERVICES, Elements.SERVICE,
                                                       service_type_class_dict, True)
        return cls(service_id, application_name, services)

    def to_pretty_str(self):
        return "\n\t\tPredefined Appliciation Name: {}".format(self.application_name)

    def __str__(self):
        return "Predefined Appliciation {}".format(self.application_name)


class Predefined_Service_Target(Service_Target):
    def __init__(self, num_id, protocol, protocol_type, predefined_name, port=None):
        self.protocol = protocol
        self.predefined_name = predefined_name
        self.type = protocol_type
        if port:
            self.port = port
        super().__init__(num_id, SERVICE_OBJECT_TYPE_PREDEFINED)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        protocol = get_xml_text_value(xml_node, Elements.PROTOCOL)
        predefined_name = get_xml_text_value(xml_node, Elements.PREDEFINED_NAME)
        protocol_type = get_xml_text_value(xml_node, Elements.TYPE)
        port = get_xml_text_value(xml_node, Elements.PORT)
        return cls(num_id, protocol, protocol_type, predefined_name, port)

    def __str__(self):
        return self.predefined_name

    def to_pretty_str(self):
        return "\n\t\tPredefined name: {}\n\t\t Protocol: {}".format(self.predefined_name, self.protocol)


class Access_Request(XML_Object_Base):
    def __init__(self, order, targets, users, sources, destinations, services, applications, action, comment, labels,
                 verifier_result, risk_analysis_result, ar_id, source_domain=None, destination_domain=None,
                 use_topology=None):
        self.id = ar_id
        self.order = order
        self.targets = XML_List(Elements.TARGETS, targets)
        self.users = XML_List(Elements.USERS, users)
        self.sources = XML_List(Elements.SOURCES, sources)
        self.destinations = XML_List(Elements.DESTINATIONS, destinations)
        self.services = XML_List(Elements.SERVICES, services)
        self.applications = XML_List(Elements.APPLICATIONS, applications)
        self.action = action
        self.comment = comment
        self.use_topology = use_topology
        self.labels = XML_List(Elements.LABELS, labels)
        self.verifier_result = verifier_result
        self.risk_analysis_result = risk_analysis_result
        if source_domain and destination_domain:
            self.source_domain = source_domain
            self.destination_domain = destination_domain
        super().__init__(Elements.ACCESS_REQUEST)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        order = get_xml_text_value(xml_node, Elements.ORDER)
        ar_id = get_xml_int_value(xml_node, Elements.ID)
        action = get_xml_text_value(xml_node, Elements.ACTION)
        comment = get_xml_text_value(xml_node, Elements.COMMENT)
        use_topology = get_xml_text_value(xml_node, Elements.USE_TOPOLOGY)
        verifier_result_node = get_xml_node(xml_node, Elements.VERIFIER_RESULT, True)
        if verifier_result_node is not None:
            verifier_result = Verifier_Result.from_xml_node(verifier_result_node)
        else:
            verifier_result = None

        risk_analysis_result_node = get_xml_node(xml_node, Elements.RISK_ANALYSIS_RESULT, True)
        if risk_analysis_result_node is not None:
            risk_analysis_result = Risk_Analysis_Result.from_xml_node(risk_analysis_result_node)
        else:
            risk_analysis_result = None

        labels = XML_List.from_xml_node_by_tags(xml_node, Elements.LABELS, Elements.LABEL, Label, True)
        applications = XML_List.from_xml_node_by_tags(xml_node, Elements.APPLICATIONS, Elements.APPLICATION,
                                                      Application_Target, True)
        device_type_to_class_dict = {TYPE_ANY: Any_Access_Request_Device, TYPE_OBJECT: Named_Access_Request_Device}
        targets = XML_List.from_xml_node_by_type_dict(xml_node, Elements.TARGETS, Elements.TARGET,
                                                      device_type_to_class_dict)
        users = XML_List.from_xml_node_by_tags(xml_node, Elements.USERS, Elements.USER, User_Target, True)

        target_type_to_class_dict = {TYPE_RANGE: IP_Range_Access_Request_Target, TYPE_IP: IP_Access_Request_Target,
                                     TYPE_DNS: DNS_Access_Request_Target, TYPE_OBJECT: Object_Access_Request_Target,
                                     TYPE_ANY: Any_Access_Request_Target, TYPE_INTERNET: Internet_Access_Request_Target}

        service_type_class_dict = {SERVICE_OBJECT_TYPE_PREDEFINED: Predefined_Service_Target,
                                   SERVICE_OBJECT_TYPE_PROTOCOL: Protocol_Service_Target,
                                   TYPE_OBJECT: Object_Access_Request_Target, TYPE_ANY: Any_Service_Target,
                                   SERVICE_OBJECT_TYPE_APPLICATION_IDENTITY: ApplicationPredefinedServiceTarget}

        sources = XML_List.from_xml_node_by_type_dict(xml_node, Elements.SOURCES, Elements.SOURCE,
                                                      target_type_to_class_dict, True)
        destinations = XML_List.from_xml_node_by_type_dict(xml_node, Elements.DESTINATIONS, Elements.DESTINATION,
                                                           target_type_to_class_dict, True)
        services = XML_List.from_xml_node_by_type_dict(xml_node, Elements.SERVICES, Elements.SERVICE,
                                                       service_type_class_dict, True)
        source_domain = get_xml_text_value(xml_node, Elements.SOURCE_DOMAIN)
        destination_domain = get_xml_text_value(xml_node, Elements.DESTINATION_DOMAIN)
        return cls(order, targets, users, sources, destinations, services, applications, action, comment, labels,
                   verifier_result, risk_analysis_result, ar_id, source_domain, destination_domain, use_topology)

    def to_pretty_str(self):
        access_request_string = "Access Request {}:\n".format(self.order)

        access_request_string += "\tTargets: "
        for target in self.targets:
            access_request_string += target.to_pretty_str()
        access_request_string += "\n\tSources: "
        for source in self.sources:
            access_request_string += source.to_pretty_str()
        access_request_string += "\n\tDestinations: "
        for destination in self.destinations:
            access_request_string += destination.to_pretty_str()
        access_request_string += "\n\tServices: "
        for service in self.services:
            access_request_string += service.to_pretty_str()
        if self.applications and any((application.to_pretty_str() for application in self.applications)):
            access_request_string += "\n\tApplications: "
            for application in self.applications:
                access_request_string += application.to_pretty_str()
        if self.users and any((user.to_pretty_str() for user in self.users)):
            access_request_string += "\n\tUsers: "
            for user in self.users:
                access_request_string += user.to_pretty_str()
        if self.comment is not None:
            access_request_string += "\n" + textwrap.fill("\tComment: {}".format(unescape(self.comment)),
                                                          initial_indent='', subsequent_indent='\t\t ')
        access_request_string += "\n"
        return access_request_string

    def __str__(self):
        return self.to_pretty_str()

    def to_csv_row(self, *, delimiter=",", inline_delimiter=";", export_targets=False):
        """ This will generate the CSV row in SC format.

        :param delimiter: The delimiter between fields (sources, destinations and etc)
        :type delimiter: str
        :param inline_delimiter: The delimiter in field itself for multiple values
        "type inline_delimiter: str
        :param export_targets: If to include targets (not compatible with SC import format)
        :type export_targets: bool
        :return: str
        """
        sources = inline_delimiter.join(str(src) for src in self.sources if src)
        destinations = inline_delimiter.join(str(dst) for dst in self.destinations if dst)
        services = inline_delimiter.join(str(srv) for srv in self.services if srv)
        action = self.action if self.action else ""
        comment = '"{}"'.format(self.comment.replace("\n", "\\n").replace('"', "'")) if self.comment else ""
        if export_targets:
            targets = inline_delimiter.join(str(target) for target in self.targets if target)
            row_data = (targets, sources, destinations, services, action, comment)
        else:
            row_data = (sources, destinations, services, action, comment)
        return delimiter.join(row_data)

    def get_risk_analysis_result_as_html(self, html_template_path=RISK_ANALYSIS_HTML_PATH, application_name=None,
                                         as_html=True):
        """Returns the risk analysis result as formatted html table or as a tuple

        :param html_template_path:
        :param application_name:
        :param as_html: If True a formatted html string is returned. if False, a tuple is returned
        :type as_html: bool
        :return:
        :rtype: str|tuple
        """
        def get_string_of_resources(resources):
            items = []
            for resource in resources:
                if isinstance(resource, (Violation_Any_Source, Violation_Any_Destination, Violation_Any_Service))\
                        or resource is None:
                    items.append("Any")
                elif isinstance(resource, (Violation_Not_Allowed_Group_Member_service_Object, Violation_Allowed_Group_Member_service_Object)):
                    items.append(resource.group_member_path)
                else:
                    items.append(resource.name)
            return ', '.join(items)

        rows = []
        for security_policy_violation in self.risk_analysis_result.security_policy_violations:
            severity = security_policy_violation.severity
            matrix = security_policy_violation.matrix_cell_violation
            if matrix:
                sources = get_string_of_resources(matrix.sources)
                violations = "Sources in zone {}: {}<BR>".format(matrix.from_zone, sources)
                destinations = get_string_of_resources(matrix.destinations)
                violations += "Destinations in zone {}: {}<BR>".format(matrix.to_zone, destinations)
                violations += "-----------------------------------------------<BR>"
                allowed_services = ""
                if matrix.allowed_services:
                    allowed_services = get_string_of_resources(matrix.allowed_services)
                not_allowed_services = "All services"
                if matrix.not_allowed_services:
                    not_allowed_services = get_string_of_resources(matrix.not_allowed_services)
                violations += "Violating services: {}".format(not_allowed_services)
                security_requirement = 'Policy control "{}" (Global Security Zone Matrix)<BR>'.format(
                    security_policy_violation.security_zone_matrix.name)
                security_requirement += '{} -> {} (Block all)<BR>'.format(matrix.from_zone, matrix.to_zone,
                                                                          matrix.destinations)
                security_requirement += "-----------------------------------------------<BR>"
                security_requirement += 'Services allowed: {}<BR>'.format(allowed_services)
                rows.append((severity, violations, security_requirement))

        compliance_policies = []
        for compliance_policy in self.risk_analysis_result.compliance_policies:
            rules = [(compliance_rule.number, compliance_rule.name) for compliance_rule in
                     compliance_policy.compliance_rules]
            compliance_policies.append((compliance_policy.name, compliance_policy.type, rules))

        if as_html:
            ar_header = "Severity Violations Security-Requirement".split()
            compliance_policy_header = "Name Type Rule".split()
            template = Template(filename=html_template_path)
            return template.render(headers=ar_header, ars=[(self.order, rows, compliance_policies)],
                                   compliance_headers=compliance_policy_header,
                                   app_name=application_name)

        return self.order, rows, compliance_policies


class Step_Field_Multi_Access_Request(Step_Multi_Field_Base):
    FIELD_CONTENT_ATTRIBUTES = "access_requests"

    def __init__(self, num_id, name, access_requests=None, designer_result=None, read_only=None):
        if access_requests is None:
            access_requests = []
        self.access_requests = access_requests
        if designer_result is not None:
            self.designer_result = designer_result
        super().__init__(num_id, name, read_only)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.FIELD_TYPE_MULTI_ACCESS_REQUEST)

    def get_access_request_by_index(self, access_request_index):
        access_request_list = sorted(self.access_requests, key=lambda ar: ar.order)
        return access_request_list[access_request_index]

    def get_next_access_request_order(self):
        return "AR{}".format(len(self.access_requests) + 1)

    def get_all_sources(self):
        return itertools.chain.from_iterable((ar.sources for ar in self.access_requests))

    def get_all_destinations(self):
        return itertools.chain.from_iterable((ar.destinations for ar in self.access_requests))

    def get_all_services(self):
        return itertools.chain.from_iterable((ar.services for ar in self.access_requests))

    def get_all_targets(self):
        return itertools.chain.from_iterable((ar.targets for ar in self.access_requests))

    def get_all_applications(self):
        return itertools.chain.from_iterable((ar.applications for ar in self.access_requests))

    def get_all_users(self):
        return itertools.chain.from_iterable((ar.users for ar in self.access_requests))

    def get_all_verifier_results(self):
        return (ar.verifier_result for ar in self.access_requests)

    def get_all_risk_analysis_results(self):
        return (ar.risk_analysis_result for ar in self.access_requests)

    def get_all_risk_analysis_results_as_html(self, html_template_path=RISK_ANALYSIS_HTML_PATH,
                                              application_name=None, risk=None):
        """Returns all risks as formatted html

        :param html_template_path:
        :param application_name: The relevant SecureApp application name. Usually obtained by ticket.application_details.name
        :param risk: type of risk to export. Can be one of None, Risk_Analysis_Result.HAS_RISK or Risk_Analysis_Result.MANUALLY_DISREGARDED
        :return:
        """

        valid_risk_values = (Risk_Analysis_Result.HAS_RISK, Risk_Analysis_Result.MANUALLY_DISREGARDED, None)
        if risk not in valid_risk_values:
            raise ValueError("'risk' param must be one of {}".format(valid_risk_values))

        if risk is None:
            risk_funcs = (Risk_Analysis_Result.has_risk, Risk_Analysis_Result.is_manually_disregarded)
        elif risk == Risk_Analysis_Result.HAS_RISK:
            risk_funcs = (Risk_Analysis_Result.has_risk,)
        elif risk == Risk_Analysis_Result.MANUALLY_DISREGARDED:
            risk_funcs = (Risk_Analysis_Result.is_manually_disregarded,)

        ar_header = "Severity Violations Security-Requirement".split()
        compliance_policy_header = "Name Type Rule".split()
        ars_with_risk = [ar.get_risk_analysis_result_as_html(as_html=False) for ar in self.access_requests
                         if any(risk_func(ar.risk_analysis_result) for risk_func in risk_funcs)]
        template = Template(filename=html_template_path)
        return template.render(headers=ar_header, ars=ars_with_risk, compliance_headers=compliance_policy_header,
                               app_name=application_name)

    def get_designer_results(self, username, password):
        if not hasattr(self, 'designer_result'):
            return None
        designer_result_url = self.designer_result.get_result_url()
        url_parse = requests.utils.urlparse(designer_result_url)
        try:
            url_helper = Secure_API_Helper(url_parse.netloc, (username, password))
            response_string = url_helper.get_uri(url_parse.path, expected_status_codes=200).response.content
        except (REST_Service_Unavailable_Error, requests.RequestException) as e:
            message = "Failed to GET designer results"
            logger.error(message)
            raise IOError(message)
        return DesignerResults.from_xml_string(response_string)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        field_name = get_xml_text_value(xml_node, Elements.NAME)
        field_id = get_xml_int_value(xml_node, Elements.ID)
        field_read_only = get_xml_text_value(xml_node, Elements.READ_ONLY)
        access_requests = []
        for access_request_node in xml_node.findall(Elements.ACCESS_REQUEST):
            access_request = Access_Request.from_xml_node(access_request_node)
            access_requests.append(access_request)

        designer_result_node = get_xml_node(xml_node, Elements.DESIGNER_RESULT, True)
        if designer_result_node is not None:
            designer_result = DesignerResult.from_xml_node(designer_result_node)
        else:
            designer_result = None

        return cls(field_id, field_name, access_requests, designer_result, field_read_only)

    def to_pretty_str(self):
        output = "Access request field '{}'\n:".format(self.name)
        for ar in self.access_requests:
            output += "\n{}\n".format(ar.to_pretty_str())
        return output

    def to_csv(self, *, delimiter=",", inline_delimiter=";", export_targets=False):
        return "\n".join(
                ar.to_csv_row(delimiter=delimiter, inline_delimiter=inline_delimiter, export_targets=export_targets) for
                ar in self.access_requests)