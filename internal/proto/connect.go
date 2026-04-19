package proto

import (
	"errors"
	"fmt"
)

const ConnectPacketMinSize = 82

var (
	ErrConnectTooShort = errors.New("connect packet too short")
	ErrInvalidPacketID = errors.New("invalid packet id for this parser")
)

// ConnectPacket represents a parsed Connect packet (0x00000000).
type ConnectPacket struct {
	ProtocolHash  [32]byte
	ClientType    uint8
	UUID          [16]byte
	Language      string
	IdentityToken string
	Username      string
	ReferralData  []byte
}

// ParseConnect parses a Connect packet from raw data.
func ParseConnect(data []byte) (*ConnectPacket, error) {
	if len(data) < ConnectPacketMinSize {
		return nil, ErrConnectTooShort
	}

	cp := &ConnectPacket{}
	offset := 0

	copy(cp.ProtocolHash[:], data[offset:offset+32])
	offset += 32

	cp.ClientType = data[offset]
	offset++

	copy(cp.UUID[:], data[offset:offset+16])
	offset += 16

	if offset >= len(data) {
		return cp, nil
	}
	lang, n, err := ReadString(data[offset:])
	if err != nil {
		return cp, nil
	}
	cp.Language = lang
	offset += n

	if offset >= len(data) {
		return cp, nil
	}
	token, n, err := ReadString(data[offset:])
	if err != nil {
		return cp, nil
	}
	cp.IdentityToken = token
	offset += n

	if offset >= len(data) {
		return cp, nil
	}
	username, n, err := ReadString(data[offset:])
	if err != nil {
		return cp, nil
	}
	cp.Username = username
	offset += n

	if offset < len(data) {
		cp.ReferralData = make([]byte, len(data)-offset)
		copy(cp.ReferralData, data[offset:])
	}

	return cp, nil
}

// ParseConnectPacket parses a Connect packet from a Packet struct.
func ParseConnectPacket(p *Packet) (*ConnectPacket, error) {
	if p.ID != PacketConnect {
		return nil, ErrInvalidPacketID
	}
	return ParseConnect(p.Data)
}

// UUIDString returns the UUID as a formatted string.
func (cp *ConnectPacket) UUIDString() string {
	u := cp.UUID
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// ProtocolHashHex returns the protocol hash as a hex string.
func (cp *ConnectPacket) ProtocolHashHex() string {
	return fmt.Sprintf("%x", cp.ProtocolHash)
}
