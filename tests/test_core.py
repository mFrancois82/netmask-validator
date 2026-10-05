import unittest

from netmask_validator import NetmaskValidator, ValidationResult


class TestNetmaskValidator(unittest.TestCase):
    def setUp(self):
        self.v = NetmaskValidator()

    def test_legal_network_has_zero_host_bits(self):
        r = self.v.validate("192.168.1.0", 24)
        self.assertTrue(r.is_legal_network)
        self.assertEqual(r.host_bits, 0)

    def test_host_bits_set_makes_network_illegal(self):
        r = self.v.validate("192.168.1.5", 24)
        self.assertFalse(r.is_legal_network)
        self.assertEqual(r.host_bits, 5)

    def test_prefix_32_is_host_route_and_always_legal(self):
        # No host bits exist at /32, so any address is a legal host route.
        r = self.v.validate("10.20.30.40", 32)
        self.assertTrue(r.is_legal_network)
        self.assertEqual(r.host_bits, 0)

    def test_prefix_0_whole_address_is_host_bits(self):
        # /0 means the whole address is host space; legal only for 0.0.0.0.
        r_nonzero = self.v.validate("1.2.3.4", 0)
        self.assertFalse(r_nonzero.is_legal_network)
        self.assertEqual(r_nonzero.host_bits, 0x01020304)

        r_zero = self.v.validate("0.0.0.0", 0)
        self.assertTrue(r_zero.is_legal_network)
        self.assertEqual(r_zero.host_bits, 0)

    def test_host_bits_cross_octet_boundary(self):
        # /20 on 10.0.16.0: the network is 10.0.16.0, last 12 bits are host.
        r_legal = self.v.validate("10.0.16.0", 20)
        self.assertTrue(r_legal.is_legal_network)
        self.assertEqual(r_legal.host_bits, 0)

        # 10.0.16.1 -> host bits = 1
        r_one = self.v.validate("10.0.16.1", 20)
        self.assertFalse(r_one.is_legal_network)
        self.assertEqual(r_one.host_bits, 1)

        # 10.0.31.255 -> last 12 bits all set = 0xFFF = 4095
        r_full = self.v.validate("10.0.31.255", 20)
        self.assertFalse(r_full.is_legal_network)
        self.assertEqual(r_full.host_bits, 0xFFF)

    def test_prefix_8_boundary(self):
        r = self.v.validate("10.0.0.5", 8)
        self.assertFalse(r.is_legal_network)
        self.assertEqual(r.host_bits, 0x000005)

    def test_result_fields_echo_inputs(self):
        r = self.v.validate("172.16.0.0", 12)
        self.assertEqual(r.address, "172.16.0.0")
        self.assertEqual(r.prefix_length, 12)

    def test_result_is_immutable_dataclass(self):
        r = self.v.validate("192.168.1.0", 24)
        self.assertIsInstance(r, ValidationResult)
        with self.assertRaises(Exception):
            r.address = "10.0.0.0"  # type: ignore[misc]

    def test_prefix_length_too_large_raises(self):
        with self.assertRaises(ValueError):
            self.v.validate("10.0.0.0", 33)

    def test_prefix_length_negative_raises(self):
        with self.assertRaises(ValueError):
            self.v.validate("10.0.0.0", -1)

    def test_invalid_address_raises(self):
        with self.assertRaises(ValueError):
            self.v.validate("not.an.address", 24)

    def test_non_ipv4_address_raises(self):
        # IPv6 is explicitly out of scope.
        with self.assertRaises(ValueError):
            self.v.validate("::1", 24)

    def test_wrong_argument_types_raise(self):
        with self.assertRaises(TypeError):
            self.v.validate(12345, 24)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            self.v.validate("10.0.0.0", True)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            self.v.validate("10.0.0.0", "24")  # type: ignore[arg-type]

    def test_all_ones_address_with_prefix_24(self):
        # 255.255.255.255 /24 -> last octet is host bits = 255.
        r = self.v.validate("255.255.255.255", 24)
        self.assertFalse(r.is_legal_network)
        self.assertEqual(r.host_bits, 255)

    def test_all_zeros_address_is_legal_for_any_prefix(self):
        # 0.0.0.0 has no host bits set regardless of prefix.
        for p in (1, 8, 16, 24, 31):
            with self.subTest(prefix=p):
                r = self.v.validate("0.0.0.0", p)
                self.assertTrue(r.is_legal_network)
                self.assertEqual(r.host_bits, 0)


if __name__ == "__main__":
    unittest.main()
