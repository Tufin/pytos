Adding new zone entry to an existing zone
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following example shows how to add new entry to an existing zone in SecureTrack:
::
	import logging
	from pytos.common.logging.definitions import COMMON_LOGGER_NAME
	from pytos.common.logging.logger import setup_loggers
	from pytos.common.functions.config import Secure_Config_Parser
	from pytos.securetrack.helpers import Secure_Track_Helper
	from pytos.securetrack.xml_objects.rest.zones import Zone_Entry

	logger = logging.getLogger(COMMON_LOGGER_NAME)

	def add_zone_entry(zone_name, ip_address, netmask, comment):
		st_helper = Secure_Track_Helper('127.0.0.1', ("username", "password"))
		zone_obj = st_helper.get_zone_by_name(zone_name, case_sensitive=True)
		new_zone_entry = Zone_Entry(None, comment, ip_address, None, netmask, zone_obj.id)
		try:
			st_helper.post_zone_entry(zone_obj.id, new_zone_entry)
		except (ValueError, IOError) as error:
			msg = "Failed to add ip {} (of one of the domains) to zone with ID {}, Error: {}"
			logger.error(msg.format(ip_address, zone_obj.id, error))


	def main():
		conf = Secure_Config_Parser(config_file_path="/usr/local/etc/pytos.conf")
		setup_loggers(conf.dict("log_levels"), log_to_stdout=True)
		zone_name = "QA"
		ip_address = "192.168.1.1"
		netmask = "255.255.255.255"
		comment = "Automatically added by script"
		try:
			add_zone_entry(zone_name, ip_address, netmask, comment)
		except ValueError as e:
			logger.error(e)


	if __name__ == "__main__":
		main()