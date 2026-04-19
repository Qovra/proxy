package proto

import (
	"encoding/binary"
	"errors"
)

// ReadString reads a length-prefixed UTF-8 string.
// Returns the string, bytes consumed, and any error.
func ReadString(data []byte) (string, int, error) {
	if len(data) < 2 {
		return "", 0, errors.New("data too short for string length")
	}
	length := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+length {
		return "", 0, errors.New("data too short for string content")
	}
	return string(data[2 : 2+length]), 2 + length, nil
}

// ReadVarInt reads a variable-length integer (QUIC style).
func ReadVarInt(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, errors.New("empty data")
	}
	prefix := data[0] >> 6
	length := 1 << prefix
	if len(data) < length {
		return 0, 0, errors.New("data too short for varint")
	}
	var value uint64
	switch length {
	case 1:
		value = uint64(data[0] & 0x3f)
	case 2:
		value = uint64(data[0]&0x3f)<<8 | uint64(data[1])
	case 4:
		value = uint64(data[0]&0x3f)<<24 | uint64(data[1])<<16 |
			uint64(data[2])<<8 | uint64(data[3])
	case 8:
		value = uint64(data[0]&0x3f)<<56 | uint64(data[1])<<48 |
			uint64(data[2])<<40 | uint64(data[3])<<32 |
			uint64(data[4])<<24 | uint64(data[5])<<16 |
			uint64(data[6])<<8 | uint64(data[7])
	}
	return value, length, nil
}
