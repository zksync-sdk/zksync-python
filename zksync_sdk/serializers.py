from typing import List
from math import ceil

AMOUNT_EXPONENT_BIT_WIDTH = 5
AMOUNT_MANTISSA_BIT_WIDTH = 35
FEE_EXPONENT_BIT_WIDTH = 5
FEE_MANTISSA_BIT_WIDTH = 11
MAX_NUMBER_OF_ACCOUNTS = 2 ** 24
MAX_NUMBER_OF_TOKENS = 2 ** 32 - 1


class SerializationError(Exception):
    pass


class WrongIntegerError(SerializationError):
    pass


class WrongBitsError(SerializationError):
    pass


class ValueNotPackedError(SerializationError):
    pass


class WrongValueError(SerializationError):
    pass


def int_to_bytes(val: int, length=4):
    return val.to_bytes(length, byteorder='big')


def num_to_bits(integer: int, bits: int):
    """
    INFO: Can't be used without correct input data of value & corresponded amount of bits, take care
    """
    results = []
    for i in range(bits):
        results.append(integer & 1)
        integer //= 2
    return results


def integer_to_float(integer: int, exp_bits: int, mantissa_bits: int, exp_base: int) -> List[int]:
    max_exponent_power = 2 ** exp_bits - 1
    max_exponent = exp_base ** max_exponent_power
    max_mantissa = 2 ** mantissa_bits - 1
    if integer > max_mantissa * max_exponent:
        raise WrongIntegerError

    exponent = 0
    exponent_temp = 1
    while integer > max_mantissa * exponent_temp:
        exponent_temp = exponent_temp * exp_base
        exponent += 1
    mantissa = integer // exponent_temp
    if exponent != 0:
        variant1 = exponent_temp * mantissa
        variant2 = exponent_temp // exp_base * max_mantissa
        diff1 = integer - variant1
        diff2 = integer - variant2
        if diff2 < diff1:
            mantissa = max_mantissa
            exponent -= 1

    data = num_to_bits(exponent, exp_bits) + num_to_bits(mantissa, mantissa_bits)
    data = list(reversed(data))
    result = list(reversed(bits_into_bytes_in_be_order(data)))

    return result


def integer_to_float_up(integer: int, exp_bits: int, mantissa_bits: int, exp_base) -> List[int]:
    max_exponent_power = 2 ** exp_bits - 1
    max_exponent = exp_base ** max_exponent_power
    max_mantissa = 2 ** mantissa_bits - 1

    if integer > max_mantissa * max_exponent:
        raise WrongIntegerError("Integer is too big")

    exponent = 0
    exponent_temp = 1
    while integer > max_mantissa * exponent_temp:
        exponent_temp = exponent_temp * exp_base
        exponent += 1

    mantissa = int(ceil(integer / exponent_temp))
    encoding = num_to_bits(exponent, exp_bits) + num_to_bits(mantissa, mantissa_bits)
    data = list(reversed(encoding))
    result = list(reversed(bits_into_bytes_in_be_order(data)))

    return result


def bits_into_bytes_in_be_order(bits: List[int]):
    if len(bits) % 8 != 0:
        raise WrongBitsError("wrong number of bits")
    size = len(bits) // 8
    result = [0] * size
    for i in range(size):
        value = 0
        for j in range(8):
            value |= bits[i * 8 + j] * 2 ** (7 - j)
        result[i] = value

    return result


def reverse_bit(b):
    b = ((b & 0xf0) >> 4) | ((b & 0x0f) << 4)
    b = ((b & 0xcc) >> 2) | ((b & 0x33) << 2)
    b = ((b & 0xaa) >> 1) | ((b & 0x55) << 1)
    return b


def reverse_bits(buffer: List[int]):
    return list(reversed(buffer))


def buffer_to_bits_be(buff):
    res = [0] * len(buff) * 8
    for i, b in enumerate(buff):
        for j in range(8):
            res[i * 8 + j] = (b >> (7 - j)) & 1
    return res


def pack_fee(amount: int):
    return bytes(reverse_bits(
        integer_to_float(amount, FEE_EXPONENT_BIT_WIDTH, FEE_MANTISSA_BIT_WIDTH, 10)
    ))


def pack_amount(amount: int) -> bytes:
    return bytes(reverse_bits(
        integer_to_float(amount, AMOUNT_EXPONENT_BIT_WIDTH, AMOUNT_MANTISSA_BIT_WIDTH, 10)
    ))


def float_to_integer(float_bytes: bytes, exp_bits, mantissa_bits, exp_base_number):
    bits = list(reversed(buffer_to_bits_be(list(float_bytes))))
    exponent = 0
    exp_pow2 = 1
    for i in range(exp_bits):
        if bits[i] == 1:
            exponent += exp_pow2
        exp_pow2 *= 2
    exponent = exp_base_number ** exponent
    mantissa = 0
    mantissa_pow2 = 1
    for i in range(exp_bits, exp_bits + mantissa_bits):
        if bits[i] == 1:
            mantissa += mantissa_pow2
        mantissa_pow2 *= 2

    return exponent * mantissa


def pack_amount_up(amount: int):
    return bytes(reverse_bits(
        integer_to_float_up(amount, AMOUNT_EXPONENT_BIT_WIDTH, AMOUNT_MANTISSA_BIT_WIDTH, 10)
    ))


def pack_fee_up(fee: int):
    return bytes(reverse_bits(
        integer_to_float_up(fee, FEE_EXPONENT_BIT_WIDTH, FEE_MANTISSA_BIT_WIDTH, 10)
    ))


def closest_packable_amount(amount: int) -> int:
    packed_amount = pack_amount(amount)
    return float_to_integer(
        packed_amount,
        AMOUNT_EXPONENT_BIT_WIDTH,
        AMOUNT_MANTISSA_BIT_WIDTH,
        10
    )


def closest_greater_or_eq_packable_amount(amount: int) -> int:
    packed_amount = pack_amount_up(amount)
    return float_to_integer(packed_amount, AMOUNT_EXPONENT_BIT_WIDTH, AMOUNT_MANTISSA_BIT_WIDTH, 10)


def closest_packable_transaction_fee(fee: int) -> int:
    packed_fee = pack_fee(fee)
    return float_to_integer(
        packed_fee,
        FEE_EXPONENT_BIT_WIDTH,
        FEE_MANTISSA_BIT_WIDTH,
        10
    )


def closest_greater_or_eq_packable_fee(fee: int) -> int:
    packed_fee = pack_fee_up(fee)
    return float_to_integer(packed_fee, FEE_EXPONENT_BIT_WIDTH, FEE_MANTISSA_BIT_WIDTH, 10)


def packed_fee_checked(fee: int):
    if closest_packable_transaction_fee(fee) != fee:
        raise ValueNotPackedError
    return pack_fee(fee)


def packed_amount_checked(amount: int):
    if closest_packable_amount(amount) != amount:
        raise ValueNotPackedError
    return pack_amount(amount)


def serialize_nonce(nonce: int):
    if nonce < 0:
        raise WrongValueError
    return int_to_bytes(nonce, 4)


def serialize_timestamp(timestamp: int):
    if timestamp < 0:
        raise WrongValueError
    return b"\x00" * 4 + int_to_bytes(timestamp, 4)


def serialize_token_id(token_id: int):
    if token_id < 0:
        raise WrongValueError
    if token_id > MAX_NUMBER_OF_TOKENS:
        raise WrongValueError
    return int_to_bytes(token_id, 4)


def serialize_account_id(account_id: int):
    if account_id < 0:
        raise WrongValueError
    if account_id > MAX_NUMBER_OF_ACCOUNTS:
        raise WrongValueError
    return int_to_bytes(account_id, 4)


def remove_address_prefix(address: str) -> str:
    if address.startswith('0x'):
        return address[2:]

    if address.startswith('sync:'):
        return address[5:]

    return address


def serialize_address(address: str) -> bytes:
    address = remove_address_prefix(address)
    address_bytes = bytes.fromhex(address)
    if len(address_bytes) != 20:
        raise WrongValueError
    return address_bytes


def serialize_content_hash(content_hash: str) -> bytes:
    if content_hash.startswith('0x'):
        content_hash = content_hash[2:]
    return bytes.fromhex(content_hash)


def serialize_ratio_part(part: int) -> bytes:
    # turn the number into bytes and 0-pad to length 15
    return bytes.fromhex(hex(part)[2:].zfill(15 * 2))
