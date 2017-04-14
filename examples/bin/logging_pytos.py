import logging
from pytos.common.logging.definitions import COMMON_LOGGER_NAME
from pytos.common.logging.logger import setup_loggers
from pytos.common.functions.config import Secure_Config_Parser
from pytos.securetrack.helpers import Secure_Track_Helper
from pytos.securetrack.xml_objects.rest.rules import Zone_Entry

conf = Secure_Config_Parser(config_file_path="/usr/local/etc/pytos.conf")
logger = logging.getLogger(COMMON_LOGGER_NAME)
st_helper = Secure_Track_Helper('127.0.0.1', ("tzachi", "tzachi"))


def add_zone_entry(zone_name, ip_address, netmask, comment):
    setup_loggers(conf.dict("log_levels"), log_to_stdout=True)
    zone_obj = st_helper.get_zone_by_name(zone_name, case_sensitive=True)
    new_zone_entry = Zone_Entry(None, comment, ip_address, None, netmask, zone_obj.id)
    try:
        st_helper.post_zone_entry(zone_obj.id, new_zone_entry)
    except (ValueError, IOError) as error:
        msg = "Failed to add ip {} (of one of the domains) to zone with ID {}, Error: {}"
        logger.error(msg.format(ip_address, zone_obj.id, error))


def main():
    zone_name = "new"
    ip_address = "192.168.1.1"
    netmask = "255.255.255.255"
    comment = "Automatically added by script"
    add_zone_entry(zone_name, ip_address, netmask, comment)


if __name__ == "__main__":
    main()