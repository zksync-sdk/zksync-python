from unittest import TestCase

from zksync_sdk.serializers import \
    num_to_bits, bits_into_bytes_in_be_order, reverse_bits, \
    closest_greater_or_eq_packable_amount, closest_greater_or_eq_packable_fee, closest_packable_transaction_fee


class TestNumberToBinaryArray(TestCase):

    def test_simple_conversion(self):
        bin_representation = num_to_bits(8, 4)
        self.assertListEqual(bin_representation, [0, 0, 0, 1])

        bin_representation = num_to_bits(32 + 5, 6)
        self.assertListEqual(bin_representation, [1, 0, 1, 0, 0, 1])

    def test_binary_list_to_bytes(self):
        # INFO: 32
        byte_array = bits_into_bytes_in_be_order([0, 0, 0, 1, 0, 0, 0, 0])
        self.assertEqual(byte_array[0], 0x10)

        values = [0, 0, 0, 0, 1, 0, 0, 0,
                  0, 0, 0, 1, 0, 0, 0, 0,
                  0, 0, 1, 0, 0, 0, 0, 0,
                  0, 1, 0, 0, 0, 0, 0, 0,
                  1, 0, 0, 0, 0, 0, 0, 0
                  ]
        byte_array = bits_into_bytes_in_be_order(values)
        self.assertEqual(len(byte_array), 5)
        self.assertEqual(byte_array[0], 8)
        self.assertEqual(byte_array[1], 16)
        self.assertEqual(byte_array[2], 32)
        self.assertEqual(byte_array[3], 64)
        self.assertEqual(byte_array[4], 128)

    def test_revers_bits(self):
        reverted = reverse_bits([1, 0, 0, 0, 1, 1, 0, 0])
        self.assertListEqual(reverted, [0, 0, 1, 1, 0, 0, 0, 1])

    def test_closest_greater_or_packable_all(self):
        nums = [0, 1, 2, 2047000, 1000000000000000000000000000000000]
        for num in nums:
            ret = closest_greater_or_eq_packable_amount(num)
            self.assertEqual(ret, num)
            ret = closest_greater_or_eq_packable_fee(num)
            self.assertEqual(ret, num)

    def test_closest_greater_or_packable_fee(self):
        ret = closest_greater_or_eq_packable_fee(2048)
        self.assertEqual(ret, 2050)
        ret = closest_packable_transaction_fee(2048)
        self.assertEqual(ret, 2047)
