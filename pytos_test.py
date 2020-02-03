#!/opt/tufin/securitysuite/ps/python/bin/python3

from pytos.secureapp.helpers import Secure_App_Helper
from pytos.secureapp.xml_objects.rest import Subnet_Network_Object
from pytos.securetrack.helpers import Secure_Track_Helper


# sa_helper = Secure_App_Helper('127.0.0.1', ('adi', 'adi'))
# sa_helper.create_network_objects_for_app_id(221, [Subnet_Network_Object('only_prefix', False, None, 'only_Prefix', 'subnet', '9.9.9.10', prefix='32')])
# sa_helper.create_network_objects_for_app_id(221, [Subnet_Network_Object('only_subnet', False, None, 'only_subnet', 'subnet', '9.9.9.11', netmask='255.255.255.255')])

st_helper = Secure_Track_Helper('127.0.0.1', ('admin', 'zubur1'))
print(st_helper.get_topology_clouds())

