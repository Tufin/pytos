
import shlex
import subprocess
import re
import xml.etree.ElementTree as ET

from .xml import get_xml_node, get_xml_text_value

TSS_EXECUTABLE_PATH = "/usr/sbin/tss"
ST_CONF_XML_PATH = "/etc/sysconfig/stconf.xml"
TOS_VERSION_REGEX = re.compile(
    r"Tufin (?:Security|Orchestration) Suite version: (?P<tos_version_major>\d+)\.(?P<tos_version_minor>\d+)")


def get_st_conf():
    with open(ST_CONF_XML_PATH) as xml_file:
        xml_data = xml_file.read()
    xml_node = ET.fromstring(xml_data)
    return xml_node


def is_ha_server_status_active():
    active_status = ("active", "active_after_failover")
    standby_status = ("standby", "standby_after_failover")
    st_conf_xml_node = get_st_conf()
    ha_conf_node = get_xml_node(st_conf_xml_node, "ha_configuration")
    ha_type = get_xml_text_value(ha_conf_node, "ha_type")
    if ha_type in active_status:
        return True
    elif ha_type == standby_status:
        return False
    else:
        raise ValueError("Unknown HA status '{}'.".format(ha_type))

def get_server_type():
    st_conf_xml_node = get_st_conf()
    server_type = get_xml_text_value(st_conf_xml_node, "Server_Type")
    return server_type


def get_tos_version():
    """
    Get the version reported by "tss version" (e.g. (14,3))
    :return: The major and minor version number for TOS/TSS.
    :rtype: tuple[int,int]
    """
    tss_process = subprocess.Popen([TSS_EXECUTABLE_PATH, 'ver'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    tss_ver_output, _ = tss_process.communicate()
    tos_version_match = re.match(TOS_VERSION_REGEX, tss_ver_output)
    tos_version_major = int(tos_version_match.group("tos_version_major"))
    tos_version_minor = int(tos_version_match.group("tos_version_minor"))
    return tos_version_major, tos_version_minor


def create_backup():
    """
    Create a backup of the local TOS installation.
    :return: The name of the created backup file.
    :rtype: str
    """
    backup_file_name_regex = r"^Compressing and saving Tufin Orchestration Suite backup file to: '?(.*(tgz|zip))"
    print("Creating backup file.")

    export_path_command = 'export PATH="${PATH}:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin"'
    backup_command = "{} {}".format(TSS_EXECUTABLE_PATH, "backup")
    command_string = ';'.join((export_path_command, backup_command))

    try:
        output = subprocess.check_output(command_string, shell=True).decode()
    except subprocess.CalledProcessError:
        raise IOError("Could not create backup file.")
    backup_file_name = re.search(backup_file_name_regex, output, re.MULTILINE).group(1)
    return backup_file_name
