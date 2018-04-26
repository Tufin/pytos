import logging

from pytos.common.base_types import XML_Object_Base
from pytos.common.definitions.xml_tags import Elements
from pytos.common.functions import XML_LOGGER_NAME
from pytos.common.functions.xml import get_xml_text_value, get_xml_int_value


logger = logging.getLogger(XML_LOGGER_NAME)


class IPSec(XML_Object_Base):

    def __init__(self, name, seq_num, ipsec_type, peer, acl, source_ip,
                 outgoing_interface, participating_gws, satellite_gws):
        self.name = name
        self.seqNumber = seq_num
        self.type = ipsec_type
        self.peer = peer
        self.acl = acl
        self.sourceIp = source_ip
        self.outgoingInterface = outgoing_interface
        self.participatingGateways = participating_gws
        self.satelliteGateways = satellite_gws
        super().__init__(Elements.IPSECLIST)

    @classmethod
    def from_xml_node(cls, xml_node):
        name = get_xml_text_value(xml_node, Elements.NAME)
        seq_num = get_xml_int_value(xml_node, Elements.SEQNUMBER)
        ipsec_type = get_xml_text_value(xml_node, Elements.TYPE)
        peer = get_xml_text_value(xml_node, Elements.PEER)
        acl = get_xml_text_value(xml_node, Elements.ACL)
        source_ip = get_xml_text_value(xml_node, Elements.SOURCEIP)
        out_iface = get_xml_text_value(xml_node, Elements.OUTGOINGINTERFACE)
        participating_gws = get_xml_text_value(xml_node, Elements.PARTICIPATINGGATEWAYS)
        satellite_gws = get_xml_text_value(xml_node, Elements.SATELLITEGATEWAYS)

        return cls(name, seq_num, ipsec_type, peer, acl, source_ip,
                   out_iface, participating_gws, satellite_gws)


class Nat(XML_Object_Base):

    def __init__(self, object_names, nat_type, policy_rule_num, original_ips,
                 translated_ips, original_services, translated_services):
        self.objectNames = object_names
        self.type = nat_type
        self.originalIps = original_ips
        self.translatedIps = translated_ips
        self.policyRuleNumber = policy_rule_num
        self.originalServices = original_services
        self.translatedServices = translated_services
        super().__init__(Elements.NATLIST)

    @classmethod
    def from_xml_node(cls, xml_node):
        nat_type = get_xml_text_value(xml_node, Elements.TYPE)
        object_names = get_xml_text_value(xml_node, Elements.OBJECTNAMES)
        policy_rule_num = get_xml_int_value(xml_node, Elements.POLICYRULENUMBER)
        original_ips = get_xml_text_value(xml_node, Elements.ORIGINALIPS)
        translated_ips = get_xml_text_value(xml_node, Elements.TRANSLATEDIPS)
        original_srvs = get_xml_text_value(xml_node, Elements.ORIGINALSERVICES)
        translated_srvs = get_xml_text_value(xml_node, Elements.TRANSLATEDSERVICES)
        return cls(object_names, nat_type, policy_rule_num, original_ips,
                   translated_ips, original_srvs, translated_srvs)


class Route(XML_Object_Base):

    def __init__(self, route_dest, next_hop_ip, outgoing_interface_name,
                 outgoin_vrf, mpls_input_label, mpls_output_label):
        self.routeDestination = route_dest
        self.nextHopIp = next_hop_ip
        self.outgoingInterfaceName = outgoing_interface_name
        self.outgoingVrf = outgoin_vrf
        self.mplsInputLabel = mpls_input_label
        self.mplsOutputLabel = mpls_output_label
        super().__init__(Elements.ROUTES)

    @classmethod
    def from_xml_node(cls, xml_node):
        route_dest = get_xml_text_value(xml_node, Elements.ROUTEDESTINATION)
        next_hop_ip = get_xml_text_value(xml_node, Elements.NEXTHOPIP)
        outgoing_interface_name = get_xml_text_value(xml_node, Elements.OUTGOINGINTERFACENAME)
        outgoin_vrf = get_xml_text_value(xml_node, Elements.OUTGOINGVRF)
        mpls_input_label = get_xml_text_value(xml_node, Elements.MPLSINPUTLABEL)
        mpls_output_label = get_xml_text_value(xml_node, Elements.MPLSOUTPUTLABEL)
        return cls(route_dest, next_hop_ip, outgoing_interface_name,
                   outgoin_vrf, mpls_input_label, mpls_output_label)


class NextDevice(XML_Object_Base):

    def __init__(self, name, routes):
        self.name = name
        self.routes = routes
        super().__init__(Elements.NEXTDEVICES)

    @classmethod
    def from_xml_node(cls, xml_node):
        name = get_xml_text_value(xml_node, Elements.NAME)
        routes = []
        for node in xml_node.iter(tag=Elements.ROUTES):
            routes.append(Route.from_xml_node(node))

        return cls(name, routes)


class Interface(XML_Object_Base):

    def __init__(self, name, ip, subnet, incoming_vrf, vpn_connection):
        self.name = name
        self.ip = ip
        self.subnet = subnet
        self.incomingVrf = incoming_vrf
        self.vpnConnection = vpn_connection
        super().__init__(Elements.INCOMINGINTERFACES)

    @classmethod
    def from_xml_node(cls, xml_node):
        name = get_xml_text_value(xml_node, Elements.NAME)
        ip = get_xml_text_value(xml_node, Elements.IP)
        subnet = get_xml_text_value(xml_node, Elements.SUBNET)
        incoming_vrf = get_xml_text_value(xml_node, Elements.INCOMINGVRF)
        vpn_connection = get_xml_text_value(xml_node, Elements.VPNCONNECTION)
        return cls(name, ip, subnet, incoming_vrf, vpn_connection)


class Rule(XML_Object_Base):

    def __init__(self, rule_id, sources, destinations, services, users,
                 applications, action, src_negated, dest_negated, srv_negated):
        self.ruleIdentifier = rule_id
        self.action = action
        self.sources = sources
        self.destinations = destinations
        self.services = services
        self.applications = applications
        self.users = users
        self.sourceNegated = src_negated
        self.destNegated = dest_negated
        self.serviceNegated = srv_negated
        super().__init__(Elements.RULES)

    @classmethod
    def from_xml_node(cls, xml_node):
        rule_id = get_xml_text_value(xml_node, Elements.RULEIDENTIFIER)
        action = get_xml_text_value(xml_node, Elements.ACTION)
        sources = get_xml_text_value(xml_node, Elements.SOURCES)
        destinations = get_xml_text_value(xml_node, Elements.DESTINATIONS)
        services = get_xml_text_value(xml_node, Elements.SERVICES)
        applications = get_xml_text_value(xml_node, Elements.APPLICATIONS)
        users = get_xml_text_value(xml_node, Elements.USERS)
        src_negated = get_xml_text_value(xml_node, Elements.SOURCENEGATED)
        dest_negated = get_xml_text_value(xml_node, Elements.DESTNEGATED)
        srv_negated = get_xml_text_value(xml_node, Elements.SERVICENEGATED)

        return cls(rule_id, sources, destinations, services, users,
                   applications, action, src_negated, dest_negated, srv_negated)


class Binding(XML_Object_Base):

    def __init__(self, name, rules, enforced):
        self.name = name
        self.rules = rules
        self.enforcedOn = enforced
        super().__init__(Elements.BINDINGS)

    @classmethod
    def from_xml_node(cls, xml_node):
        name = get_xml_text_value(xml_node, Elements.NAME)
        enforced = get_xml_text_value(xml_node, Elements.ENFORCEDON)
        rules = []
        for node in xml_node.iter(tag=Elements.RULES):
            rules.append(Rule.from_xml_node(node))

        return cls(name, rules, enforced)


class DeviceInfo(XML_Object_Base):

    def __init__(self, name, vendor, incoming_interfaces, next_devices, bindings, nat_list, ipsec_list):
        self.name = name
        self.vendor = vendor
        self.incomingInterfaces = incoming_interfaces
        self.nextDevices = next_devices
        self.bindings = bindings
        self.natList = nat_list
        self.ipsecList = ipsec_list
        super().__init__(Elements.DEVICE_INFO)

    @classmethod
    def from_xml_node(cls, xml_node):
        name = get_xml_text_value(xml_node, Elements.NAME)
        vendor = get_xml_text_value(xml_node, Elements.VENDOR)

        incoming_interfaces = []
        for node in xml_node.iter(tag=Elements.INCOMINGINTERFACES):
            incoming_interfaces.append(Interface.from_xml_node(node))

        next_devices = []
        for node in xml_node.iter(tag=Elements.NEXTDEVICES):
            next_devices.append(NextDevice.from_xml_node(node))

        bindings = []
        for node in xml_node.iter(tag=Elements.BINDINGS):
            bindings.append(Binding.from_xml_node(node))

        nat_list = []
        for node in xml_node.iter(tag=Elements.NATLIST):
            nat_list.append(Nat.from_xml_node(node))

        ipsec_list = []
        for node in xml_node.iter(tag=Elements.IPSECLIST):
            ipsec_list.append(IPSec.from_xml_node(node))

        return cls(name, vendor, incoming_interfaces, next_devices, bindings, nat_list, ipsec_list)


class PathCalculationResults(XML_Object_Base):

    def __init__(self, traffic_allowed, devices_info):
        self.traffic_allowed = traffic_allowed
        self.devices_info = devices_info

        super().__init__(Elements.PATH_CALC_RESULTS)

    @classmethod
    def from_xml_node(cls, xml_node):
        traffic_allowed = get_xml_text_value(xml_node, Elements.TRAFFIC_ALLOWED)
        devices_info = []
        for device_info_node in xml_node.iter(tag=Elements.DEVICE_INFO):
            devices_info.append(DeviceInfo.from_xml_node(device_info_node))

        return cls(traffic_allowed, devices_info)
