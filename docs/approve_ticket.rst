Approve SecureChange ticket
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following example shows how to approve ticket in SecureChange by using the Approve/Reject field:
::
	import argparse
	import shlex
	import sys
	import logging

	from pytos.common.logging.logger import setup_loggers
	from pytos.common.functions.config import Secure_Config_Parser
	from pytos.common.definitions.xml_tags import Attributes
	from pytos.securechange.helpers import Secure_Change_Helper, Secure_Change_API_Handler
	from pytos.common.logging.definitions import COMMON_LOGGER_NAME

	logger = logging.getLogger(COMMON_LOGGER_NAME)


	def get_cli_args():
		parser = argparse.ArgumentParser("Approve/reject ticket in SecureChange")
		parser.add_argument("--debug", action="store_true",
							help="Print out logging information to STDOUT.")
		parser.add_argument("--ticket_id", type=int,
							help="SecureChange ticket id")
		args = parser.parse_args(shlex.split(" ".join(sys.argv[1:])))
		return args


	def approve_step(ticket):
		sc_helper = Secure_Change_Helper("127.0.0.1", ("username", "password"))
		ticket = sc_helper.get_ticket_by_id(ticket.id)
		approve_step_obj = ticket.get_current_step()
		logger.debug("Current step name to approve is: '{}'".format(approve_step_obj.name))
		task = approve_step_obj.get_last_task()
		approve_reject_field = task.get_field_list_by_type(Attributes.FIELD_TYPE_APPROVE_REJECT)[0]
		approve_reject_field.approved = "true"
		approve_reject_field.reason = "Approved"
		task.mark_as_done()
		sc_helper.put_task(task)


	def main():
		cli_args = get_cli_args()
		conf = Secure_Config_Parser(config_file_path="/usr/local/etc/pytos.conf")
		setup_loggers(conf.dict("log_levels"), log_to_stdout=cli_args.debug)
		logger.info("Script called")

		ticket = sc_helper.get_ticket_by_id(cli_args.ticket_id)
		approve_step(ticket)


	if __name__ == '__main__':
		main()
