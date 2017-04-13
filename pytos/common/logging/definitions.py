# Copyright 2017 Tufin Technologies Security Suite. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging

LOGGER_NAME_PREFIX = "TUFIN_PS_"
COMMON_LOGGER_NAME = LOGGER_NAME_PREFIX + "COMMON"
MAIL_LOGGER_NAME = LOGGER_NAME_PREFIX + "MAIL"
HELPERS_LOGGER_NAME = LOGGER_NAME_PREFIX + "HELPERS"
REPORTS_LOGGER_NAME = LOGGER_NAME_PREFIX + "REPORTS"
REQUESTS_LOGGER_NAME = LOGGER_NAME_PREFIX + "REQUESTS"
SQL_LOGGER_NAME = LOGGER_NAME_PREFIX + "SQL"
THIRD_PARTY_LOGGER_NAME = LOGGER_NAME_PREFIX + "THIRD_PARTY"
XML_LOGGER_NAME = LOGGER_NAME_PREFIX + "XML"
WEB_LOGGER_NAME = LOGGER_NAME_PREFIX + "WEB"

LOG_CONFIG_FILE_PATH = "/opt/tufin/securitysuite/pytos/conf/tufin_api.conf"
LOG_LEVEL_SECTION_NAME = "log_levels"

logger_name_to_log_domain = {COMMON_LOGGER_NAME: "COMMON", MAIL_LOGGER_NAME: "MAIL", HELPERS_LOGGER_NAME: "HELPERS",
                             REPORTS_LOGGER_NAME: "REPORTS", REQUESTS_LOGGER_NAME: "REQUESTS", SQL_LOGGER_NAME: "SQL",
                             THIRD_PARTY_LOGGER_NAME: "THIRD_PARTY", XML_LOGGER_NAME: "XML", WEB_LOGGER_NAME: "WEB"}

REGISTERED_LOGGER_NAMES = (COMMON_LOGGER_NAME, HELPERS_LOGGER_NAME, MAIL_LOGGER_NAME, REPORTS_LOGGER_NAME,
                           REQUESTS_LOGGER_NAME, XML_LOGGER_NAME, THIRD_PARTY_LOGGER_NAME, SQL_LOGGER_NAME,
                           WEB_LOGGER_NAME)
LOG_FORMAT = '%(asctime)s - PID:%(process)d - TID:%(thread)d - %(levelname)s - %(module)s - %(name)s - Line %(' \
             'lineno)d - %(message)s'

LOG_FILE_OWNER = "tomcat"
LOG_FILE_GROUP = "apache"
MAX_LOG_BYTES = 512 * 1000 * 1000  # 512MB
MAX_LOG_FILES_BACKUPS = 4
DEFAULT_LOG_LEVEL = logging.WARNING
DEFAULT_LOG_LEVEL_NAME = logging._levelToName[DEFAULT_LOG_LEVEL]
