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
import enum


@enum.unique
class ConnectionStatus(enum.Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    CALCULATING = "CALCULATING"
    CONNECTED = "CONNECTED"
    DISCONNECTED = "DISCONNECTED"
    DOMAIN_DELETED = "DOMAIN_DELETED"
    NOT_COMPLETE = "NOT_COMPLETE"
    USER_IN_SOURCE = "USER_IN_SOURCE"
    L7_APPLICATION = "L7_APPLICATION"
    ANY_OR_A_CLASS = "ANY_OR_A_CLASS"
    INTERNET = "INTERNET"
    NON_CONTINUOUS_MASK = "NON_CONTINUOUS_MASK"
