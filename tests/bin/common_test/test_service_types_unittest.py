import sys
import unittest

from pytos.common.Base_Types import Service_Type, Single_Service_Type, \
    Any_Service_Type, Range_Service_Type, Group_Service_Type, Service_Set

__author__ = 'saar.katz'

service_port = {'http': 80, 'https': 443, 'ftp': 21, 'gopher': 70, 'smtp': 25,
                'imap': 143, 'imaps': 993, 'pop3': 110, 'pop3s': 995}
ip_protocol = {'icmp': 1, 'udp': 17, 'tcp': 6}


class Test_Service_Types(unittest.TestCase):
    def test_service_type(self):
        # Assertions for get_valid_port.
        # By name.
        assert Service_Type.get_valid_port('http') == service_port['http']
        assert Service_Type.get_valid_port('https') == service_port['https']
        with self.assertRaises(ValueError) as ex:
            Service_Type.get_valid_port('not_exists')
        assert "Service for port 'not_exists' not found." in str(ex.exception)

        # By number.
        assert Service_Type.get_valid_port(5) == 5
        assert Service_Type.get_valid_port(65535) == 65535
        with self.assertRaises(ValueError) as ex:
            Service_Type.get_valid_port(65536)
        assert "Port must be between 0 and 65535." in str(ex.exception)

        # Neither name nor number.
        with self.assertRaises(ValueError) as ex:
            Service_Type.get_valid_port([80, 443, 25])
        assert "Invalid port '[80, 443, 25]'." in str(ex.exception)

        # Assertions for get_valid_protocol.
        # By name.
        assert Service_Type.get_valid_protocol('udp') == ip_protocol['udp']
        assert Service_Type.get_valid_protocol('tcp') == ip_protocol['tcp']
        with self.assertRaises(ValueError) as ex:
            Service_Type.get_valid_protocol('not_exists')
        assert "Protocol 'not_exists' not found." in str(ex.exception)

        # By number.
        with self.assertRaises(ValueError) as ex:
            Service_Type.get_valid_protocol(-1)
        assert "Protocol must be between 0 and 255." in str(ex.exception)

        # Neither name nor number.
        with self.assertRaises(ValueError) as ex:
            Service_Type.get_valid_protocol({'icmp': 1})
        assert "Invalid IP protocol '{'icmp': 1}'." in str(ex.exception)

    def test_single_service_type(self):
        single_service_type1 = Single_Service_Type(17, 'https')
        single_service_type2 = Single_Service_Type('udp', 443)
        single_service_type3 = Single_Service_Type('tcp', 'http')
        single_service_type4 = Single_Service_Type('icmp', 'imaps')

        # Assertions for __eq__ and __contains__
        assert single_service_type1 == single_service_type2
        assert single_service_type1 in single_service_type2
        assert single_service_type1 != single_service_type3
        assert single_service_type3 not in single_service_type4
        assert not single_service_type1 == 443

        # Assertions for __hash__
        assert hash(single_service_type1) == hash(single_service_type2)
        assert hash(single_service_type3) != hash(single_service_type4)

        # Assertions for __lt__
        assert single_service_type1 > single_service_type3
        with self.assertRaises(AssertionError):
            assert not single_service_type1 > single_service_type4
            assert not single_service_type1 < single_service_type4

        # Assertion for __repr__
        assert single_service_type1 == eval(repr(single_service_type1))

    def test_range_service_type(self):
        range_service_type1 = Range_Service_Type('tcp', 'http', 443)
        range_service_type2 = Range_Service_Type(6, 80, 'https')
        range_service_type3 = Range_Service_Type('udp', 81, 150)
        range_service_type4 = Range_Service_Type('tcp', 250, 443)
        range_service_type5 = Range_Service_Type('icmp', 21, 151)

        # Assertion for __eq__
        assert range_service_type1 == range_service_type2
        assert range_service_type3 != 17
        assert range_service_type5 != range_service_type4

        # Assertions for __contains__
        assert range_service_type1 in range_service_type2
        assert range_service_type4 in range_service_type2
        assert range_service_type1 not in range_service_type4
        assert range_service_type3 not in range_service_type2

        # Assertions for __hash__
        assert hash(range_service_type1) == hash(range_service_type2)
        assert hash(range_service_type3) != hash(range_service_type4)

        # Assertions for __lt__
        assert range_service_type5 < range_service_type2
        assert range_service_type5 < range_service_type4
        assert not range_service_type1 < range_service_type2
        assert not range_service_type3 < range_service_type4

        # Assertion for __repr__
        assert range_service_type1 == eval(repr(range_service_type1))

    def test_group_service_type(self):
        single_service_type1 = Single_Service_Type('tcp', 80)
        single_service_type2 = Single_Service_Type('tcp', 70)
        single_service_type3 = Single_Service_Type('udp', 443)

        range_service_type1 = Range_Service_Type('tcp', 80, 100)
        range_service_type2 = Range_Service_Type('tcp', 85, 95)
        range_service_type3 = Range_Service_Type('tcp', 70, 90)

        group_service_type1 = Group_Service_Type([single_service_type3])

        assert single_service_type3 in group_service_type1
        assert single_service_type1 not in group_service_type1

        group_service_type1.append(range_service_type1)

        assert single_service_type1 in group_service_type1
        assert single_service_type2 not in group_service_type1
        assert range_service_type2 in group_service_type1
        assert range_service_type3 not in group_service_type1

        group_service_type1.append(single_service_type2)

        assert range_service_type3 not in group_service_type1

        group_service_type2 = Group_Service_Type([single_service_type2])

        assert group_service_type2 in group_service_type1

        group_service_type2 = Group_Service_Type([single_service_type1,
                                                  single_service_type2,
                                                  range_service_type2])

        assert group_service_type2 in group_service_type1

        group_service_type2.append(range_service_type3)

        assert group_service_type2 not in group_service_type1

        assert len(group_service_type1) == 3

        # Assertion for __repr__
        assert group_service_type1 in eval(repr(group_service_type1))

    def test_service_set(self):
        single_service_type1 = Single_Service_Type('tcp', 80)
        single_service_type2 = Single_Service_Type('udp', 443)

        range_service_type1 = Range_Service_Type('tcp', 80, 100)
        range_service_type2 = Range_Service_Type('tcp', 85, 95)
        range_service_type3 = Range_Service_Type('tcp', 70, 90)

        group_service_type1 = Group_Service_Type([single_service_type2])

        service_set1 = Service_Set(group_service_type1)

        assert single_service_type1 not in service_set1
        assert range_service_type2 not in service_set1
        assert single_service_type2 in service_set1
        assert group_service_type1 in service_set1

        service_set1.add(range_service_type1)

        assert single_service_type1 in service_set1
        assert range_service_type2 in service_set1

        service_set2 = Service_Set([single_service_type1])
        service_set2.add(range_service_type2)

        assert service_set2.issubset(service_set1)

        service_set2.add(range_service_type3)

        assert not service_set2.issubset(service_set1)

        assert len(service_set1) == 2

        service_set1.add(single_service_type2)

        assert len(service_set1) == 2

        service_set1.add(Any_Service_Type())

        assert len(service_set1) == 3

        service_set1.add(Any_Service_Type())

        assert len(service_set1) == 3

        # Assertion for copy
        assert service_set1 in service_set1.copy()

        # Assertion for __repr__
        assert service_set2 in eval(repr(service_set2))

    def test_lt_in_between_service_types(self):
        single_service_type1 = Single_Service_Type('tcp', 80)
        range_service_type1 = Range_Service_Type('tcp', 80, 100)
        group_service_type1 = Group_Service_Type([range_service_type1])
        any_service_type = Any_Service_Type()

        assert single_service_type1 < any_service_type

        assert single_service_type1 < range_service_type1
        assert not single_service_type1 > range_service_type1

        assert not single_service_type1 < group_service_type1

        assert not single_service_type1 > any_service_type
        assert single_service_type1 > group_service_type1

        assert range_service_type1 < any_service_type
        assert not range_service_type1 < group_service_type1

        assert not range_service_type1 > any_service_type
        assert range_service_type1 > group_service_type1

        assert group_service_type1 < any_service_type

        assert not group_service_type1 > any_service_type


if __name__ == '__main__':
    unittest.main()