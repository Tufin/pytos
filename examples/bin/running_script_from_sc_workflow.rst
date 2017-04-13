Copy field between steps in SecureChange ticket
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following example shows how to run a script from the SecureChange workflow by specify the relevant step name,
read the ticket info and copy a field from previous step:
::
	import argparse
	import shlex
	import sys
	import logging


	from pytos.common.logging.Logger import setup_loggers
	from pytos.common.functions.Config import Secure_Config_Parser
	from pytos.securechange.helpers import Secure_Change_Helper, Secure_Change_API_Handler
	from pytos.common.logging.Defines import COMMON_LOGGER_NAME


	conf = Secure_Config_Parser(config_file_path="/usr/local/etc/pytos.conf")
	logger = logging.getLogger(COMMON_LOGGER_NAME)
	sc_helper = Secure_Change_Helper("127.0.0.1", ("username", "password"))
	src_step_name = "Source step name"
	dst_step_name = "Destination step name"
	src_field_name = "Source Field name"
	dst_field_name = "Destination Field name"


	def get_cli_args():
		parser = argparse.ArgumentParser("Approve/reject ticket in SecureChange")
		parser.add_argument("--debug", action="store_true",
							help="Print out logging information to STDOUT.")
		args = parser.parse_args(shlex.split(" ".join(sys.argv[1:])))
		return args


	def copy_field(ticket):
		logger.debug("Copy field between steps")
		current_step_task = ticket.get_current_task()
		previous_step_task = ticket.get_previous_step().get_last_task()
		dst_field = current_step_task.get_field_list_by_name(dst_field_name)[0]
		src_field = previous_step_task.get_field_list_by_name(src_field_name)[0]
		dst_field.set_field_value(src_field.get_field_value())
		sc_helper.put_field(dst_field)


	def main():
		cli_args = get_cli_args()
		setup_loggers(conf.dict("log_levels"), log_to_stdout=cli_args.debug)
		logger.info("Script called.")

		# Get the ticket information from the STDIN
		try:
			ticket_info = sc_helper.read_ticket_info()
		except (ValueError, AttributeError) as e:
			logger.info(e)
			sys.exit(0)

		# Registered steps
		ticket = sc_helper.get_ticket_by_id(ticket_info.id)
		ticket_handler = Secure_Change_API_Handler(ticket)
		ticket_handler.register_step(dst_step_name, copy_field, ticket)
		ticket_handler.run()


	if __name__ == '__main__':
		main()