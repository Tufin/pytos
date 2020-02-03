
import logging
import netifaces
import platform
import re
import socket
import struct
from functools import lru_cache
import dns
from dns import reversename, resolver, name
import netaddr

from pytos.common.logging.definitions import COMMON_LOGGER_NAME

logger = logging.getLogger(COMMON_LOGGER_NAME)

IPV4_ADDRESS_REGEX_STR = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|/\d{1,2})?"

IPV4_ADDRESS_REGEX = re.compile(IPV4_ADDRESS_REGEX_STR)

IPV6_ADDRESS_REGEX = re.compile(
        r"(?:::|(?:(?:[a-fA-F0-9]{1,4}):){7}(?:(?:[a-fA-F0-9]{1,4}))|(?::(?::(?:[a-fA-F0-9]{1,4})){1,6})|(?:(?:(?:["
        r"a-fA-F0-9]{1,4}):){1,6}:)|(?:(?:(?:[a-fA-F0-9]{1,4}):)(?::(?:[a-fA-F0-9]{1,4})){1,6})|(?:(?:(?:[a-fA-F0-9]{"
        r"1,4}):){2}(?::(?:[a-fA-F0-9]{1,4})){1,5})|(?:(?:(?:[a-fA-F0-9]{1,4}):){3}(?::(?:[a-fA-F0-9]{1,4})){1,"
        r"4})|(?:(?:(?:[a-fA-F0-9]{1,4}):){4}(?::(?:[a-fA-F0-9]{1,4})){1,3})|(?:(?:(?:[a-fA-F0-9]{1,4}):){5}(?::(?:["
        r"a-fA-F0-9]{1,4})){1,2}))(?:/[0-9]+)?")


def is_ipv4_string(ip):
    """Check if the specified string is a valid IPv4 address.

    :type ip: str
    :param ip: The IP address to check.
    :rtype: bool
    """
    if re.match(IPV4_ADDRESS_REGEX, ip):
        return True
    else:
        return False


def is_ipv6_string(ip):
    """Check if the specified string is a valid IPv6 address.

    :type ip: str
    :param ip: The IP address to check.
    :rtype: bool
    """
    if re.match(IPV6_ADDRESS_REGEX, ip):
        return True
    else:
        return False


def dns_lookup(target, query_type="A", rdclass=1, tcp=False):
    if is_ipv4_string(target) or is_ipv6_string(target):
        if query_type == "PTR":
            try:
                target = dns.reversename.from_address(target)
            except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.exception.Timeout, dns.resolver.NoNameservers):
                return []
        else:
            raise ValueError("Only PTR is supported for IP addresses.")
    try:
        answers = dns.resolver.query(target, query_type, rdclass, tcp)
    except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.exception.Timeout, dns.resolver.NoNameservers):
        return []
    answers_list = [str(answer).rstrip(".") for answer in answers]
    return answers_list


@lru_cache()
def get_iana_services():
    """Parse the local file of IANA services and return a dictionary of service name to service protocol and port.

    :rtype:dict[str,(str,str)]
    """
    os_dist = platform.system()
    if os_dist == "Linux":
        services_file_path = "/etc/services"
    elif os_dist == "Windows":
        services_file_path = "C:\\windows\\system32\\etc\\services"
    else:
        raise TypeError("Unsupported OS '{}'".format(os_dist))
    services_dict = {}
    with open(services_file_path) as services_file:
        for line in services_file.readlines():
            if not line.startswith("#") and not line.isspace():
                split_line = line.split()
                service_name = split_line[0]
                service_port, service_protocol = split_line[1].split("/")
                try:
                    services_dict[service_name].append((service_protocol, service_port))
                except KeyError:
                    services_dict[service_name] = [(service_protocol, service_port)]
                for alias_name in split_line[2:]:
                    if alias_name.startswith("#"):
                        break
                    try:
                        services_dict[alias_name].append((service_protocol, service_port))
                    except KeyError:
                        services_dict[alias_name] = [(service_protocol, service_port)]

    return services_dict


@lru_cache()
def get_iana_protocols():
    """Parse the local file of IANA IP protocols and return a dictionary of protocol number to name.

    :rtype:dict[int,str]
    """
    os_dist = platform.system()
    if os_dist == "Linux":
        protocols_file_path = "/etc/protocols"
    elif os_dist == "Windows":
        protocols_file_path = "C:\\windows\\system32\\etc\\protocols"
    else:
        raise TypeError("Unsupported OS '{}'".format(os_dist))
    protocols = {}
    with open(protocols_file_path) as services_file:
        for line in services_file.readlines():
            if not line.startswith("#") and not line.isspace():
                _, protocol_number, protocol_name, *_ = line.split()
                protocols[int(protocol_number)] = protocol_name
    return protocols


def get_ip_subnets(ip):
    """Get a list of subnets contained in the specified subnet.

    :type ip: str
    :param ip: The IP that subnets will be returned for.
    :list[netaddr.IPNetwork] 
    """
    ip = ip.strip().replace(" ", "")
    if "/" in ip:
        return [netaddr.IPNetwork(ip)]
    elif "-" in ip:
        start_ip, end_ip = ip.split("-")
        ip_set_object = netaddr.IPSet(netaddr.IPRange(start_ip, end_ip, flags=netaddr.ZEROFILL))
        return [address for address in ip_set_object.iter_cidrs()]
    else:
        if is_ipv4_string(ip):
            return [netaddr.IPNetwork(ip)]
        else:
            raise ValueError("Invalid IP string '{}'.".format(ip))


def calculate_quad_dotted_netmask(mask):
    """
    This function converts a CIDR notation network mask to a Quad Dotted network mask.
    :param mask: A IPv4 network mask in CIDR notation.
    :type mask: int
    :return: The specified mask in quad dotted notation.
    :rtype: str
    """
    try:
        bits = 0xffffffff ^ (1 << 32 - mask) - 1
        return socket.inet_ntoa(struct.pack('>I', bits))
    except (struct.error, ValueError):
        logger.error("Could not calculate quad dotted netmask notation for mask %s", mask)


def get_local_ip_addresses():
    """Get a list of non loopback IP addresses configured on the local host.

    :rtype: list[str]
    """
    addresses = []
    for interface in netifaces.interfaces():
        for address in netifaces.ifaddresses(interface).get(2, []):
            if address["addr"] != "127.0.0.1":
                addresses.append(address["addr"])
    return addresses


def netmask_to_cidr(mask):
    """Convert a network mask from quad dotted notation to CIDR notation.

    :type mask: str
    :param mask: The network mask to convert.
    :rtype: int
    """
    return sum((bin(int(x)).count('1') for x in mask.split('.')))
