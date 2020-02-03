from pytos.secureapp.helpers import Secure_App_Helper

sa_helper = Secure_App_Helper("127.0.0.1", ("a", "a"))

group = sa_helper.get_network_object_by_name_for_app_id('new group', 221)
sa_helper.update_network_objects_for_app_id(221, [group])


