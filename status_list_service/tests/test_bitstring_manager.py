"""
status_list_service/tests/test_bitstring_manager.py

Tests for bitstring allocation and bit flipping.
"""

import pytest
from services.bitstring_manager import flip_bit, compress_and_encode_bitstring, decode_bitstring


def test_flip_bit():
    """Test bit flipping."""
    # Create a zero bitstring
    bitstring = b'\x00\x00'

    # Flip bit 0 (MSB of byte 0)
    result = flip_bit(bitstring, 0)
    assert result[0] == 0x80  # 10000000 in binary
    assert result[1] == 0x00

    # Flip bit 7 (LSB of byte 0)
    result = flip_bit(bitstring, 7)
    assert result[0] == 0x01  # 00000001 in binary
    assert result[1] == 0x00

    # Flip bit 8 (MSB of byte 1)
    result = flip_bit(bitstring, 8)
    assert result[0] == 0x00
    assert result[1] == 0x80

    # Flip multiple bits
    result = bitstring
    result = flip_bit(result, 0)
    result = flip_bit(result, 7)
    result = flip_bit(result, 8)
    assert result[0] == 0x81  # 10000001
    assert result[1] == 0x80


def test_compress_and_encode():
    """Test compression and encoding."""
    # Create a large zero bitstring
    bitstring = b'\x00' * 16384

    # Compress and encode
    encoded = compress_and_encode_bitstring(bitstring)

    # Should be a base64url string
    assert isinstance(encoded, str)
    assert len(encoded) > 0

    # Decode should reverse
    decoded = decode_bitstring(encoded)
    assert decoded == bitstring


def test_compress_and_encode_with_data():
    """Test with actual data."""
    # Create a bitstring with some bits set
    bitstring = bytearray(16384)
    bitstring[0] = 0xFF  # All bits in byte 0 set
    bitstring[100] = 0x55  # Pattern
    bitstring = bytes(bitstring)

    # Compress and encode
    encoded = compress_and_encode_bitstring(bitstring)

    # Decode should give back the same
    decoded = decode_bitstring(encoded)
    assert decoded == bitstring
