
import configparser
import grp
import logging
import logging.handlers
import os
import pwd
import sys

from pytos.common.functions import Secure_Config_Parser
from .definitions import LOG_FORMAT, LOG_LEVEL_SECTION_NAME, logger_name_to_log_domain, \
    COMMON_LOGGER_NAME, REGISTERED_LOGGER_NAMES, LOGGER_NAME_PREFIX, MAX_LOG_FILES_BACKUPS, MAX_LOG_BYTES, \
    DEFAULT_LOG_LEVEL_NAME, DEFAULT_LOG_LEVEL, LOG_FILE_OWNER, LOG_FILE_GROUP

FORMATTER = logging.Formatter(LOG_FORMAT)

logger = logging.getLogger(COMMON_LOGGER_NAME)


def iter_loggers():
    for logger_name in REGISTERED_LOGGER_NAMES:
        yield logging.getLogger(logger_name)


def remove_logger_handlers():
    for logger_ in iter_loggers():
        logger_.handlers = []


def setup_loggers(log_levels_data=None, log_dir_path="/var/log/pytos/", log_file="pytos_logger.log",
                  update_config_file=True, additional_log_files=None, **kwargs):
    """
    Set up the loggers used by the Tufin PS scripts.
    :param log_levels_data: The log level settings
    :type log_levels_data: dict[str,str]|Secure_Config_Parser
    :param log_dir_path: The path for the directory the logger will write to.
    :type log_dir_path: str
    :param log_file: The name of the log file the logger will write to.
    :type log_file: str
    :param update_config_file: Update the configuration file with the default log levels for unconfigured loggers if
    log_domains is Secure_Config_Parser.
    :type update_config_file: bool
    :param additional_log_files: Names of additional log files to write to
    :type additional_log_files: list
    :keyword log_to_stdout: If set to true, log output will be sent to STDOUT.
    """

    def rotate_with_permission(source, dest):
        if os.path.exists(source):
            os.rename(source, dest)
        try:
            os.mknod(source)
            uid = pwd.getpwnam(LOG_FILE_OWNER).pw_uid
            gid = grp.getgrnam(LOG_FILE_GROUP).gr_gid
            os.chown(source, uid, gid)
            os.chmod(source, 0o666)
        except (PermissionError, IOError, AttributeError, KeyError, NotImplementedError):
            pass

    remove_logger_handlers()
    configured_loggers = []
    log_to_stdout = kwargs.get("log_to_stdout")

    if not log_dir_path.endswith("/"):
        log_dir_path += "/"

    if not os.path.exists(log_dir_path):
        print("Creating directory '{}'.".format(log_dir_path))
        os.makedirs(log_dir_path)

    if additional_log_files is None:
        additional_log_files = []

    elif isinstance(additional_log_files, str):
        additional_log_files = [additional_log_files]

    log_files = [log_file] + additional_log_files

    log_data_is_updateable = False
    if hasattr(log_levels_data, "update_config_file"):  # Handle Secure_Config_Parser
        try:
            log_domains = log_levels_data.dict(LOG_LEVEL_SECTION_NAME)
        except configparser.NoSectionError:
            log_domains = {}
        if update_config_file:
            log_data_is_updateable = True
    else:
        log_domains = log_levels_data

    for log_file in log_files:
        handler = logging.handlers.RotatingFileHandler(log_dir_path + log_file, maxBytes=MAX_LOG_BYTES,
                                                       backupCount=MAX_LOG_FILES_BACKUPS)
        handler.rotator = rotate_with_permission
        handler.setFormatter(FORMATTER)

        if log_levels_data is None:
            log_levels_data = {}

        for log_domain, log_level in log_domains.items():
            logger_name = LOGGER_NAME_PREFIX + log_domain.upper()
            if logger_name not in REGISTERED_LOGGER_NAMES:
                print("Unknown log domain '{}', skipping initialization.".format(logger_name))
                continue
            else:
                logger_ = logging.getLogger(logger_name)
                logger_.addHandler(handler)
                log_level_num = logging._nameToLevel.get(log_level.upper())
                if log_level_num is None:
                    print("Invalid log level ({}) specified for log domain '{}'.".format(log_level, log_domain))
                else:
                    logger_.setLevel(log_level.upper())
                    configured_loggers.append(logger_)
            logger_.setLevel(log_level_num)
        configured_loggers = handle_unconfigured_loggers(handler, configured_loggers, log_data_is_updateable,
                                                         log_levels_data)
    if log_to_stdout:
        print("Logging to STDOUT is enabled.")
        handle_log_to_stdout(configured_loggers)

    return logging.getLogger(COMMON_LOGGER_NAME)


def handle_unconfigured_loggers(handler, configured_loggers, log_data_is_updateable, log_levels_data):
    log_levels_changed = False
    configured_logger_names = [logger_.name for logger_ in configured_loggers]
    unconfigured_loggers = [logger_name for logger_name in REGISTERED_LOGGER_NAMES if
                            logger_name not in configured_logger_names]
    for logger_name in unconfigured_loggers:
        print("Logger '{}' was not configured, setting log level to default ({}).".format(logger_name,
                                                                                          DEFAULT_LOG_LEVEL_NAME))
        logger_ = logging.getLogger(logger_name)
        logger_.addHandler(handler)
        logger_.setLevel(DEFAULT_LOG_LEVEL)
        log_levels_changed = True

        if log_data_is_updateable:
            if not log_levels_data.has_section(LOG_LEVEL_SECTION_NAME):
                log_levels_data.add_section(LOG_LEVEL_SECTION_NAME)
            log_levels_data.set(LOG_LEVEL_SECTION_NAME, logger_name_to_log_domain[logger_name], DEFAULT_LOG_LEVEL_NAME)
        configured_loggers.append(logger_)
    if log_data_is_updateable and log_levels_changed:
        print("Setting updated log levels in configuration file.")
        log_levels_data.update_config_file()
    return configured_loggers


def handle_log_to_stdout(configured_loggers):
    for logger_ in configured_loggers:
        log_stream_handler = logging.StreamHandler(stream=sys.stdout)
        log_stream_handler.setFormatter(FORMATTER)
        logger_.addHandler(log_stream_handler)
