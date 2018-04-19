from pytos.securechange.xml_objects.restapi.step.initialize import *

logger = logging.getLogger(XML_LOGGER_NAME)


class AbsNetwork(XML_Object_Base, metaclass=SubclassWithIdentifierRegistry):
    """Base class for parsing all network object"""

    @classmethod
    def from_xml_node(cls, xml_node):
        try:
            network_type = xml_node.attrib[Attributes.XSI_NAMESPACE_TYPE]
        except KeyError:
            msg = 'XML node is missing the XSI attribute "{}"'.format(Attributes.XSI_NAMESPACE_TYPE)
            logger.error(msg)
            raise ValueError(msg)
        else:
            try:
                return cls.registry[network_type](xml_node)
            except KeyError:
                logger.error('Unknown violation object type "{}"'.format(network_type))


class NetworkObject(AbsNetwork):
    """Base class for all sub type of the network object"""

    def __init__(self, xml_node, element):
        self.address_book = get_xml_text_value(xml_node, Elements.ADDRESS)
        self.type_on_device = get_xml_text_value(xml_node, Elements.TYPE)
        self.version_id = get_xml_int_value(xml_node, Elements.VERSION_ID)
        self.referenced = get_xml_text_value(xml_node, Elements.REFERENCED)
        interface_name = get_xml_text_value(xml_node, Elements.INTERFACE_NAME)
        self.nat_info = NatInfo(interface_name)
        self.installable_target = get_xml_text_value(xml_node, Elements.INSTALLABLE_TARGET)
        self.group_id = get_xml_text_value(xml_node, Elements.GROUP_ID)
        self.device_type = get_xml_text_value(xml_node, Elements.DEVICE_TYPE)
        self.ip_type = get_xml_text_value(xml_node, Elements.IP_TYPE)
        self.id = get_xml_text_value(xml_node, Elements.ID)
        zone_node = get_xml_node(xml_node, Elements.ZONE, True)
        if zone_node is not None:
            self.zone = PolicyZone(zone_node)
        else:
            self.zone = None
        self.device_id = get_xml_int_value(xml_node, Elements.DEVICE_ID)
        admin_domain_node = get_xml_node(xml_node, Elements.ADMIN_DOMAIN, True)
        if admin_domain_node is not None:
            self.admin_domain = AdminDomain.from_xml_node(admin_domain_node)
        else:
            self.admin_domain = None
        self.inDomainElementId = get_xml_text_value(xml_node, Elements.INDOMAINELEMENTID)
        self.global_el = Flat_XML_Object_Base(Elements.GLOBAL, None, get_xml_text_value(xml_node, Elements.GLOBAL))
        self.origin = get_xml_text_value(xml_node, Elements.ORIGIN)
        self.comment = get_xml_text_value(xml_node, Elements.COMMENT)
        self.shared = get_xml_text_value(xml_node, Elements.SHARED)
        self.name = get_xml_text_value(xml_node, Elements.NAME)
        self.implicit = get_xml_text_value(xml_node, Elements.IMPLICIT)
        self.class_name = get_xml_text_value(xml_node, Elements.CLASS_NAME)
        self.display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        self.uid = get_xml_text_value(xml_node, Elements.UID)
        self.any_zone = get_xml_text_value(xml_node, Elements.ANY_ZONE)
        self.management_domain = get_xml_text_value(xml_node, Elements.MANAGEMENT_DOMAIN)
        self.domain_id = get_xml_int_value(xml_node, Elements.DOMAIN_ID)
        self.application_name = get_xml_text_value(xml_node, Elements.APPLICATION_NAME)
        super().__init__(element)

    def __str__(self):
        return self.display_name


class AnyNetworkObject(NetworkObject):
    """The class represents the any_network_object"""
    class_identifier = Attributes.VIOLATION_ANY_NETWORK_OBJECT

    def __init__(self, xml_node):
        super().__init__(xml_node, xml_node.find('.').tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.VIOLATION_ANY_NETWORK_OBJECT)

    def __str__(self):
        return "Any"


class HostNetworkObject(NetworkObject):
    """The class represents the host_network_object"""
    class_identifier = Attributes.HOST_NETWORK_OBJECT

    def __init__(self, xml_node):
        super().__init__(xml_node, xml_node.find('.').tag)
        self.ip = get_xml_text_value(xml_node, Elements.IP)
        self.subnet_mask = get_xml_text_value(xml_node, Elements.SUBNET_MASK)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.HOST_NETWORK_OBJECT)

    def __str__(self):
        return self.ip


class SubnetNetworkObject(NetworkObject):
    """The class represents the subnet_network_object"""
    class_identifier = Attributes.SUBNET_NETWORK_OBJECT

    def __init__(self, xml_node):
        super().__init__(xml_node, xml_node.find('.').tag)
        self.ip = get_xml_text_value(xml_node, Elements.IP)
        self.subnet_mask = get_xml_text_value(xml_node, Elements.SUBNET_MASK)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.SUBNET_NETWORK_OBJECT)

    def __str__(self):
        return "{}/{}".format(self.ip, self.subnet_mask)


class RangeNetworkObject(NetworkObject):
    class_identifier = Attributes.RANGE_NETWORK_OBJECT

    def __init__(self, xml_node):
        super().__init__(xml_node, xml_node.find('.').tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.RANGE_NETWORK_OBJECT)
        self.min_ip = get_xml_text_value(xml_node, Elements.MIN_IP)
        self.max_ip = get_xml_text_value(xml_node, Elements.MAX_IP)

    def __str__(self):
        return self.min_ip + '-' + self.max_ip


class NetworkObjectGroup(NetworkObject):
    """The class represents the subnet_network_object"""
    class_identifier = Attributes.NETWORK_OBJECT_GROUP

    def __init__(self, xml_node):
        self.members = []
        for member_node in xml_node.iter(tag=Elements.MEMBER):
            self.members.append(NetworkObject.from_xml_node(member_node))

        self.exclusions = []
        for member_node in xml_node.iter(tag=Elements.EXCLUSION):
            self.exclusions.append(NetworkObject.from_xml_node(member_node))

        super().__init__(xml_node, xml_node.find('.').tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.NETWORK_OBJECT_GROUP)


class DomainNetworkObject(NetworkObject):
    class_identifier = Attributes.DOMAIN_NETWORK_OBJECT

    def __init__(self, xml_node):
        super().__init__(xml_node, xml_node.find('.').tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.DOMAIN_NETWORK_OBJECT)


class InstallOnNetworkObject(NetworkObject):
    class_identifier = Attributes.INSTALL_ON_NETWORK_OBJECT

    def __init__(self, xml_node):
        super().__init__(xml_node, xml_node.find('.').tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.INSTALL_ON_NETWORK_OBJECT)


class HostNetworkObjectWithInterfaces(NetworkObject):
    class_identifier = Attributes.HOST_NETWORK_OBJECT_WITH_INTERFACES

    def __init__(self, xml_node):
        super().__init__(xml_node, xml_node.find('.').tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.HOST_NETWORK_OBJECT_WITH_INTERFACES)
        self.ip = get_xml_text_value(xml_node, Elements.IP)
        self.subnet_mask = get_xml_text_value(xml_node, Elements.SUBNET_MASK)
        self.interfaces = []
        for member_node in xml_node.iter(tag=Elements.INTERFACE_FOR_NETWORK_OBJECT):
            self.interfaces.append(NetworkObject.from_xml_node(member_node))


class CloudSecurityGroup(NetworkObject):
    class_identifier = Attributes.CLOUD_SECURITY_GROUP_NETWORK_OBJECT

    def __init__(self, xml_node):
        self.members = []
        for member_node in xml_node.iter(tag=Elements.MEMBER):
            self.members.append(NetworkObject.from_xml_node(member_node))

        self.exclusions = []
        for member_node in xml_node.iter(tag=Elements.EXCLUSION):
            self.exclusions.append(NetworkObject.from_xml_node(member_node))

        super().__init__(xml_node, xml_node.find('.').tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.CLOUD_SECURITY_GROUP_NETWORK_OBJECT)


class InternetNetworkObject(NetworkObject):
    class_identifier = Attributes.INTERNET_NETWORK_OBJECT

    def __init__(self, xml_node):
        super().__init__(xml_node, xml_node.find('.').tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.INTERNET_NETWORK_OBJECT)


class AbsService(XML_Object_Base, metaclass=SubclassWithIdentifierRegistry):
    """Base class for parsing all services objects"""

    @classmethod
    def from_xml_node(cls, xml_node):
        if xml_node is None:
            return None
        try:
            service_type = xml_node.attrib[Attributes.XSI_NAMESPACE_TYPE]
        except KeyError:
            msg = 'XML node is missing the XSI attribute "{}"'.format(Attributes.XSI_NAMESPACE_TYPE)
            logger.error(msg)
            raise ValueError(msg)
        else:
            try:
                return cls.registry[service_type](xml_node)
            except KeyError:
                logger.error('Unknown violation object type "{}"'.format(service_type))


class Service(AbsService):
    """Base class for all sub type of the services objects"""

    def __init__(self, xml_node, element):
        self.version_id = get_xml_text_value(xml_node, Elements.VERSION_ID)
        self.referenced = get_xml_text_value(xml_node, Elements.REFERENCED)
        self.match_rule = get_xml_text_value(xml_node, Elements.MATCH_RULE)
        self.id = get_xml_text_value(xml_node, Elements.ID)
        self.device_id = get_xml_int_value(xml_node, Elements.DEVICE_ID)
        self.admin_domain = AdminDomain.from_xml_node(xml_node)
        self.in_domain_element_id = get_xml_text_value(xml_node, Elements.INDOMAINELEMENTID)
        self.global_el = Flat_XML_Object_Base(Elements.GLOBAL, None, get_xml_text_value(xml_node, Elements.GLOBAL))
        self.origin = get_xml_text_value(xml_node, Elements.ORIGIN)
        self.comment = get_xml_text_value(xml_node, Elements.COMMENT)
        self.shared = get_xml_text_value(xml_node, Elements.SHARED)
        self.name = get_xml_text_value(xml_node, Elements.NAME)
        self.implicit = get_xml_text_value(xml_node, Elements.IMPLICIT)
        self.class_name = get_xml_text_value(xml_node, Elements.CLASS_NAME)
        self.display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        self.uid = get_xml_text_value(xml_node, Elements.UID)
        super().__init__(element)

    def __str__(self):
        return self.display_name


class AnyService(Service):
    """The class represents the any_service_object"""
    class_identifier = Attributes.VIOLATION_ANY_SERVICE

    def __init__(self, xml_node):
        self.negate = get_xml_text_value(xml_node, Elements.NEGATE)
        self.match_for_any = get_xml_text_value(xml_node, Elements.MATCH_FOR_ANY)
        self.timeout = get_xml_text_value(xml_node, Elements.TIMEOUT)
        self.min_protocol = get_xml_int_value(xml_node, Elements.MIN_PROTOCOL)
        self.max_protocol = get_xml_int_value(xml_node, Elements.MAX_PROTOCOL)
        super().__init__(xml_node, xml_node.find('.').tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.VIOLATION_ANY_SERVICE)


class TransportService(Service):
    """The class represents the transport_service_object"""
    class_identifier = Attributes.TRANSPORT_SERVICE

    def __init__(self, xml_node):
        self.cp_inspect_streaming_name = get_xml_text_value(xml_node, Elements.CP_INSPECT_STREAMING_NAME)
        self.min_protocol = get_xml_int_value(xml_node, Elements.MIN_PROTOCOL)
        self.max_protocol = get_xml_int_value(xml_node, Elements.MAX_PROTOCOL)
        self.min_port = get_xml_int_value(xml_node, Elements.MIN_PORT)
        self.max_port = get_xml_int_value(xml_node, Elements.MAX_PORT)
        self.protocol = get_xml_int_value(xml_node, Elements.PROTOCOL)
        self.min_value_source = get_xml_int_value(xml_node, Elements.MIN_VALUE_SOURCE)
        self.max_value_source = get_xml_int_value(xml_node, Elements.MAX_VALUE_SOURCE)
        self.cp_prototype_name = get_xml_text_value(xml_node, Elements.CP_PROTOTYPE_NAME)
        self.match_for_any = get_xml_text_value(xml_node, Elements.MATCH_FOR_ANY)
        self.negate = get_xml_text_value(xml_node, Elements.NEGATE)
        self.timeout = get_xml_text_value(xml_node, Elements.TIMEOUT)
        self.display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        super().__init__(xml_node, xml_node.find('.').tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.TRANSPORT_SERVICE)


class IcmpService(Service):
    """The class represents the icmp_service_object"""
    class_identifier = Attributes.ICMP_SERVICE

    def __init__(self, xml_node):
        super().__init__(xml_node, xml_node.find('.').tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.ICMP_SERVICE)
        self.type_on_device = get_xml_text_value(xml_node, Elements.TYPE_ON_DEVICE)
        self.negate = get_xml_text_value(xml_node, Elements.NEGATE)
        self.match_for_any = get_xml_text_value(xml_node, Elements.MATCH_FOR_ANY)
        self.timeout = get_xml_int_value(xml_node, Elements.TIMEOUT)
        self.min_icmp_type = get_xml_int_value(xml_node, Elements.MIN_ICMP_TYPE)
        self.max_icmp_type = get_xml_int_value(xml_node, Elements.MAX_ICMP_TYPE)


class IPService(Service):
    """The class represents the ip_service_object"""
    class_identifier = Attributes.IP_SERVICE

    def __init__(self, xml_node):
        self.negate = get_xml_text_value(xml_node, Elements.NEGATE)
        self.match_for_any = get_xml_text_value(xml_node, Elements.MATCH_FOR_ANY)
        self.timeout = get_xml_text_value(xml_node, Elements.TIMEOUT)
        self.min_protocol = get_xml_int_value(xml_node, Elements.MIN_PROTOCOL)
        self.max_protocol = get_xml_int_value(xml_node, Elements.MAX_PROTOCOL)
        super().__init__(xml_node, xml_node.find('.').tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.IP_SERVICE)


class ServiceGroup(Service):
    """The class represents the ip_service_object"""
    class_identifier = Attributes.SERVICE_GROUP

    def __init__(self, xml_node):
        super().__init__(xml_node, xml_node.find('.').tag)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.SERVICE_GROUP)
        self.members = [Service.from_xml_node(node) for node in xml_node.findall('member')]


class Binding(XML_Object_Base, metaclass=SubclassWithIdentifierRegistry):
    """Base Binding Class that handles all Binding sub Binding DTO parsing"""

    @classmethod
    def from_xml_node(cls, xml_node):
        if xml_node is None:
            return None
        try:
            binding_type = xml_node.attrib[Attributes.XSI_NAMESPACE_TYPE]
        except KeyError:
            msg = 'XML node is missing the XSI attribute "{}"'.format(Attributes.XSI_NAMESPACE_TYPE)
            logger.error(msg)
            raise ValueError(msg)
        else:
            try:
                return cls.registry[binding_type](xml_node)
            except KeyError:
                logger.error('Unknown binding object type "{}"'.format(binding_type))


class AclBinding(Binding):
    """The class represents the acl_binding_object which is sub type of Binding_DTO"""
    class_identifier = Attributes.ACL__BINDING

    def __init__(self, xml_node):
        self.acl_name = get_xml_text_value(xml_node, Elements.ACL_NAME)

        self.incoming_interface_names = [node.text for node in xml_node.iter(Elements.INCOMING_INTERFACE_NAME)]
        self.outgoing_interface_names = [node.text for node in xml_node.iter(Elements.OUTGOING_INTERFACE_NAME)]

        super().__init__(Elements.BINDING)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.ACL__BINDING)


class ZoneBinding(Binding):
    """The class represents the zone_binding object which is sub type of Binding_DTO"""
    class_identifier = Attributes.ZONE__BINDING

    def __init__(self, xml_node):
        self.from_zone = get_xml_text_value(xml_node, Elements.FROM_ZONE)
        self.to_zone = get_xml_text_value(xml_node, Elements.TO_ZONE)
        super().__init__(Elements.BINDING)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.ZONE__BINDING)


class PolicyBinding(Binding):
    class_identifier = Attributes.POLICY__BINDING

    def __init__(self, xml_node):
        self.policy_name = get_xml_text_value(xml_node, Elements.POLICY_NAME)
        self.installed_on_module = get_xml_text_value(xml_node, Elements.INSTALLED_ON_MODULE)
        super().__init__(Elements.BINDING)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.POLICY__BINDING)


class AbsSlimRule(XML_Object_Base, metaclass=SubclassWithIdentifierRegistry):
    """AbsSlimRule Class that handles all SlimRule sub DTO parsing"""
    @classmethod
    def from_xml_node(cls, xml_node):
        if xml_node is None:
            return None
        try:
            rule_type = xml_node.attrib[Attributes.XSI_NAMESPACE_TYPE]
        except KeyError:
            msg = 'XML node is missing the XSI attribute "{}"'.format(Attributes.XSI_NAMESPACE_TYPE)
            logger.error(msg)
            raise ValueError(msg)
        else:
            try:
                return cls.registry[rule_type].from_xml_node(xml_node)
            except KeyError:
                logger.error('Unknown binding object type "{}"'.format(rule_type))


class SlimRule(AbsSlimRule):
    """The class represents the SlimRule which is sub type of SlimRule"""
    def __init__(self, uid, destination_networks=None, source_networks=None,
                 destination_services=None, rule_number=None, additional_parameters=None, communities=None,
                 rule_location=None, applications=None, install_ons=None, users=None, track=None, source_services=None,
                 from_zone=None, to_zone=None, action=None, comment=None, name=None, is_disabled=None):
        self.additional_parameters = additional_parameters
        self.communities = communities
        self.sourceNetworks = source_networks
        self.destinationNetworks = destination_networks
        self.destination_services = destination_services
        self.install_ons = install_ons
        self.track = track
        self.rule_location = rule_location
        self.source_services = source_services
        self.uid = uid
        self.rule_number = rule_number
        if applications is not None:
            self.applications = applications
        self.from_zone = from_zone
        self.to_zone = to_zone
        self.action = action
        self.comment = comment
        self.name = name
        self.is_disabled = is_disabled
        self.users = users
        super().__init__(Elements.RULE)
        self.set_attrib(Attributes.XSI_TYPE, Attributes.SLIM_RULE_WITH_META_DATA)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        rule_uid = get_xml_text_value(xml_node, Elements.UID)
        rule_location = get_xml_text_value(xml_node, Elements.RULE_LOCATION)
        rule_number = get_xml_int_value(xml_node, Elements.RULENUMBER)
        from_zone = get_xml_text_value(xml_node, Elements.FROM_ZONE)
        to_zone = get_xml_text_value(xml_node, Elements.TO_ZONE)
        action = get_xml_text_value(xml_node, Elements.ACTION)
        comment = get_xml_text_value(xml_node, Elements.COMMENT)
        name = get_xml_text_value(xml_node, Elements.NAME)
        is_disabled = get_xml_text_value(xml_node, Elements.ISDISABLED)

        destination_networks = []
        for destination_network_node in xml_node.iter(tag=Elements.DESTNETWORKS):
            network_object = NetworkObject.from_xml_node(destination_network_node)
            destination_networks.append(network_object)

        source_networks = []
        for source_network_node in xml_node.iter(tag=Elements.SOURCENETWORKS):
            network_object = NetworkObject.from_xml_node(source_network_node)
            source_networks.append(network_object)

        destination_services = []
        for destination_service_node in xml_node.iter(Elements.DESTINATIONSERVICES):
            service = Service.from_xml_node(destination_service_node)
            destination_services.append(service)

        additional_parameters = []
        parameters_node = get_xml_node(xml_node, Elements.ADDITIONAL_PARAMETERS, True)
        if parameters_node is not None:
            for parameter_node in parameters_node.iter(Elements.ADDITIONAL_PARAMETER):
                additional_parameter = AdditionalParameter.from_xml_node(parameter_node)
                additional_parameters.append(additional_parameter)

        communities = []
        communities_node = get_xml_node(xml_node, Elements.COMMUNITIES, True)
        if communities_node is not None:
            for community_node in communities_node.iter(Elements.COMMUNITY):
                community = VpnCommunity.from_xml_node(community_node)
                communities.append(community)

        applications = []
        applications_node = get_xml_node(xml_node, Elements.APPLICATIONS, True)
        if applications_node is not None:
            for application_node in applications_node.iter(Elements.APPLICATION):
                application = Application.from_xml_node(application_node)
                applications.append(application)

        install_ons = []
        install_ons_node = get_xml_node(xml_node, Elements.INSTALL_ONS, True)
        if install_ons_node is not None:
            for install_on_node in install_ons_node.iter(tag=Elements.INSTALL_ON):
                network_object = NetworkObject.from_xml_node(install_on_node)
                install_ons.append(network_object)

        users = []
        users_node = get_xml_node(xml_node, Elements.USERS, True)
        if users_node is not None:
            for user_node in users_node.iter(tag=Elements.USER):
                user = DeviceUser.from_xml_node(user_node)
                users.append(user)

        track_node = get_xml_node(xml_node, Elements.TRACK, True)
        if track_node is not None:
            track = RuleTrack.from_xml_node(track_node)
        else:
            track = None

        source_services = []
        for source_service_node in xml_node.iter(Elements.SOURCESERVICES):
            service = Service.from_xml_node(source_service_node)
            source_services.append(service)

        return cls(rule_uid, destination_networks, source_networks, destination_services,
                   rule_number, additional_parameters, communities, rule_location, applications, install_ons,
                   users, track, source_services, from_zone, to_zone, action, comment, name, is_disabled)

    def to_pretty_str(self):
        rule_string = "Rule name: {}\n".format(self.name)
        rule_string += "From zone: {}\n".format(self.from_zone)
        rule_string += "To zone: {}\n".format(self.to_zone)
        rule_string += "Sources: {}\n".format(", ".join(str(src) for src in self.sourceNetworks))
        rule_string += "Destinations: {}\n".format(", ".join(str(src) for src in self.destinationNetworks))
        rule_string += "Services: {}\n".format(", ".join(str(srv) for srv in self.destination_services))
        if self.comment is not None:
            rule_string += "Comment: {}\n".format(unescape(self.comment))
        return rule_string


class SlimRuleWithMetadata(SlimRule):
    """This class represents the SlimRuleWithMetadata"""

    def __init__(self, uid, destination_networks=None, source_networks=None,
                 destination_services=None, rule_number=None, additional_parameters=None, communities=None,
                 rule_location=None, applications=None, install_ons=None, users=None, track=None, source_services=None,
                 from_zone=None, to_zone=None, action=None, comment=None, name=None, is_disabled=None, rule_meta_data=None):
        super().__init__(uid, destination_networks, source_networks,
                 destination_services, rule_number, additional_parameters, communities,
                 rule_location, applications, install_ons, users, track, source_services,
                 from_zone, to_zone, action, comment, name, is_disabled)
        self.rule_meta_data = rule_meta_data
        self.set_attrib(Attributes.XSI_TYPE, Attributes.SLIM_RULE_WITH_META_DATA)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        slim_rule = super().from_xml_node(xml_node)
        rule_meta_data_node = get_xml_node(xml_node, Elements.RULE_METADATA, True)
        if rule_meta_data_node is not None:
            slim_rule.rule_meta_data = RuleMetaData.from_xml_node(rule_meta_data_node)
        else:
            slim_rule.rule_meta_data = None
        return slim_rule

    def to_pretty_str(self):
        rule_string = super().to_pretty_str()
        rule_string += self.rule_meta_data.to_pretty_str()
        return rule_string


class RuleMetaData(XML_Object_Base):
    """This class represents the RuleMetaData used in rule decommission field"""

    def __init__(self, violations, permissiveness_level, legacy_rule, ticket_ids, tech_owner, last_hit,
                 rule_description, business_owners, last_modified, shadowed_status, applications):
        self.violations = violations
        self.permissiveness_level = permissiveness_level
        self.legacy_rule = legacy_rule
        self.ticket_ids = ticket_ids
        self.tech_owner = tech_owner
        self.last_hit = last_hit
        self.rule_description = rule_description
        self.business_owners = business_owners
        self.last_modified = last_modified
        self.shadowed_status = shadowed_status
        self.applications = applications
        super().__init__(Elements.RULE_METADATA)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        violations = get_xml_text_value(xml_node, Elements.VIOLATIONS)
        permissiveness_level = get_xml_text_value(xml_node, Elements.PERMISSIVENESS_LEVEL)
        legacy_rule = get_xml_text_value(xml_node, Elements.LEGACY_RULE)
        ticket_ids = get_xml_text_value(xml_node, Elements.TICKET_IDS)
        last_hit = get_xml_text_value(xml_node, Elements.LAST_HIT)
        rule_description = get_xml_text_value(xml_node, Elements.RULE_DESCRIPTION)
        business_owners = get_xml_text_value(xml_node, Elements.BUSINESS_OWNERS)
        last_modified = get_xml_text_value(xml_node, Elements.LAST_MODIFIED)
        shadowed_status = get_xml_text_value(xml_node, Elements.SHADOWED_STATUS)
        tech_owner = get_xml_text_value(xml_node, Elements.TECH_OWNER)
        applications = []
        applications_node = get_xml_node(xml_node, Elements.APPLICATIONS, True)
        if applications_node is not None:
            for application_node in applications_node.iter(Elements.APPLICATION):
                application = SaApplication.from_xml_node(application_node)
                applications.append(application)

        return cls(violations, permissiveness_level, legacy_rule, ticket_ids, tech_owner, last_hit, rule_description,
                   business_owners, last_modified, shadowed_status, applications)

    def to_pretty_str(self):
        meta_data_string = ''
        if self.violations is not None:
            meta_data_string += "Violations: {}\n".format(self.violations)
        if self.permissiveness_level is not None:
            meta_data_string += "Permissiveness level: {}\n".format(self.permissiveness_level)
        if self.legacy_rule is not None:
            meta_data_string += "Legacy rule: {}\n".format(self.legacy_rule)
        if self.ticket_ids is not None:
            meta_data_string += "Ticket IDs: {}\n".format(self.ticket_ids)
        if self.tech_owner is not None:
            meta_data_string += "Tech Owner: {}\n".format(self.tech_owner)
        if self.last_hit is not None:
            meta_data_string += "Last hit: {}\n".format(self.last_hit)
        if self.rule_description is not None:
            meta_data_string += "Rule description: {}\n".format(self.rule_description)
        if self.business_owners is not None:
            meta_data_string += "Business owners: {}\n".format(self.business_owners)
        if self.last_modified is not None:
            meta_data_string += "Last modified: {}\n".format(self.last_modified)
        if self.shadowed_status is not None:
            meta_data_string += "Shadowed status: {}\n".format(self.shadowed_status)
        if self.applications:
            meta_data_string += "Applications: {}\n".format(", ".join(str(app) for app in self.applications))
        return meta_data_string


class AdditionalParameter(XML_Object_Base):
    """This class represents the Additional Parameter used in rule decommission field"""

    def __init__(self, num_id, display_name, class_name, name, uid):
        self.id = num_id
        self.display_name = display_name
        self.class_name = class_name
        self.name = name
        self.uid = uid
        super().__init__(Elements.ADDITIONAL_PARAMETER)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        class_name = get_xml_text_value(xml_node, Elements.CLASS_NAME)
        name = get_xml_text_value(xml_node, Elements.NAME)
        uid = get_xml_text_value(xml_node, Elements.UID)
        return cls(num_id, display_name, class_name, name, uid)


class VpnCommunity(XML_Object_Base):
    """This class represents the VpnCommunity used in rule decommission field"""

    def __init__(self, class_name, name, uid):
        self.class_name = class_name
        self.name = name
        self.uid = uid
        super().__init__(Elements.COMMUNITIES)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        class_name = get_xml_text_value(xml_node, Elements.CLASS_NAME)
        name = get_xml_text_value(xml_node, Elements.NAME)
        uid = get_xml_text_value(xml_node, Elements.UID)
        return cls(class_name, name, uid)


class Application(XML_Object_Base):
    """This class represents the Application used in rule decommission field"""

    def __init__(self, application_name, in_domain_element_id, domain_id, device_id, admin_domain, a_global, origin,
                 comment, shared, name, implicit, class_name, display_name, uid):
        self.application_name = application_name
        self.inDomainElementId = in_domain_element_id
        self.domain_id = domain_id
        self.device_id = device_id
        self.admin_domain = admin_domain
        self.a_global = a_global
        self.origin = origin
        self.comment = comment
        self.shared = shared
        self.name = name
        self.implicit = implicit
        self.class_name = class_name
        self.display_name = display_name
        self.uid = uid
        super().__init__(Elements.APPLICATION)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        application_name = get_xml_text_value(xml_node, Elements.APPLICATION_NAME)
        in_domain_element_id = get_xml_text_value(xml_node, Elements.INDOMAINELEMENTID)
        domain_id = get_xml_int_value(xml_node, Elements.DOMAIN_ID)
        device_id = get_xml_int_value(xml_node, Elements.DEVICE_ID)
        admin_domain_node = get_xml_node(xml_node, Elements.ADMIN_DOMAIN, True)
        if admin_domain_node is not None:
            admin_domain = AdminDomain.from_xml_node(admin_domain_node)
        else:
            admin_domain = None
        a_global = get_xml_text_value(xml_node, Elements.GLOBAL)
        origin = get_xml_text_value(xml_node, Elements.ORIGIN)
        comment = get_xml_text_value(xml_node, Elements.COMMENT)
        shared = get_xml_text_value(xml_node, Elements.SHARED)
        name = get_xml_text_value(xml_node, Elements.NAME)
        implicit = get_xml_text_value(xml_node, Elements.IMPLICIT)
        class_name = get_xml_text_value(xml_node, Elements.CLASS_NAME)
        display_name = get_xml_text_value(xml_node, Elements.DISPLAY_NAME)
        uid = get_xml_text_value(xml_node, Elements.UID)

        return cls(application_name, in_domain_element_id, domain_id, device_id, admin_domain, a_global, origin,
                   comment, shared, name, implicit, class_name, display_name, uid)


class AdminDomain(XML_Object_Base):
    """This class represents the AdminDomain used in rule decommission field"""

    def __init__(self, name, uid):
        self.name = name
        self.uid = uid
        super().__init__(Elements.ADMIN_DOMAIN)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        name = get_xml_text_value(xml_node, Elements.NAME)
        uid = get_xml_text_value(xml_node, Elements.UID)
        return cls(name, uid)


class NatInfo(XML_Object_Base):
    def __init__(self, interface_name):
        self.interface_name = interface_name
        super().__init__(Elements.NAT_INFO)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        interface_name = get_xml_text_value(xml_node, Elements.INTERFACE_NAME)
        return cls(interface_name)


class PolicyZone(XML_Object_Base):
    """The class represents the PolicyZoneDTO"""
    def __init__(self, xml_node):
        self.zone_name_in_parent = get_xml_text_value(xml_node, Elements.ZONE_NAME_IN_PARENT)
        self.address_book = get_xml_text_value(xml_node, Elements.ADDRESS_BOOK)
        self.version_id = get_xml_int_value(xml_node, Elements.VERSION_ID)
        self.admin_domain = AdminDomain.from_xml_node(xml_node)
        self.global_el = Flat_XML_Object_Base(Elements.GLOBAL, None, get_xml_text_value(xml_node, Elements.GLOBAL))
        self.name = get_xml_text_value(xml_node, Elements.NAME)
        super().__init__(Elements.ZONE)


class DeviceUser(XML_Object_Base):
    """This class represents the DeviceUser used in rule decommission field"""

    def __init__(self, class_name, name, uid):
        self.class_name = class_name
        self.name = name
        self.uid = uid
        super().__init__(Elements.USERS)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        class_name = get_xml_text_value(xml_node, Elements.CLASS_NAME)
        name = get_xml_text_value(xml_node, Elements.NAME)
        uid = get_xml_text_value(xml_node, Elements.UID)
        return cls(class_name, name, uid)


class RuleTrack(XML_Object_Base):
    """This class represents the RuleTrack used in rule decommission field"""

    def __init__(self, track_interval, track_level):
        self.track_interval = track_interval
        self.track_level = track_level
        super().__init__(Elements.TRACK)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        track_interval = get_xml_text_value(xml_node, Elements.TRACK_INTERVAL)
        track_level = get_xml_text_value(xml_node, Elements.TRACK_LEVEL)
        return cls(track_interval, track_level)


class SaApplication(XML_Object_Base):
    """This class represents the aApplication used in rule decommission field"""

    def __init__(self, num_id, domain_id, name, owner):
        self.id = num_id
        self.domain_id = domain_id
        self.name = name
        self.owner = owner
        super().__init__(Elements.APPLICATIONS)

    @classmethod
    def from_xml_node(cls, xml_node):
        """
        Initialize the object from a XML node.
        :param xml_node: The XML node from which all necessary parameters will be parsed.
        :type xml_node: xml.etree.Element
        """
        num_id = get_xml_int_value(xml_node, Elements.ID)
        name = get_xml_text_value(xml_node, Elements.NAME)
        domain_id = get_xml_int_value(xml_node, Elements.DOMAIN_ID)
        owner = get_xml_text_value(xml_node, Elements.OWNER)
        return cls(num_id, name, domain_id, owner)

    def __str__(self):
        return self.name
