import logging
from pytos.common.logging.Defines import COMMON_LOGGER_NAME
from pytos.common.logging.Logger import setup_loggers
from pytos.common.functions.Config import Secure_Config_Parser

conf = Secure_Config_Parser(config_file_path="/usr/local/etc/pytos.conf")
logger = logging.getLogger(COMMON_LOGGER_NAME)
setup_loggers(conf.dict("log_levels"), log_to_stdout=True)
logger.info("Hello world")