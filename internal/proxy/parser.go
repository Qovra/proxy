package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/Qovra/core/internal/handler"
	"golang.org/x/crypto/hkdf"
)

// QUIC Version 1
const quicVersion1 = 0x00000001

// PacketType represents the type of a QUIC packet.
type PacketType int

const (
	PacketUnknown     PacketType = iota
	PacketInitial                // Long Header, Type 00
	PacketZeroRTT                // Long Header, Type 01
	PacketHandshake              // Long Header, Type 10
	PacketRetry                  // Long Header, Type 11
	PacketShortHeader            // Short Header (1-RTT)
)

func (t PacketType) String() string {
	switch t {
	case PacketInitial:
		return "Initial"
	case PacketZeroRTT:
		return "0-RTT"
	case PacketHandshake:
		return "Handshake"
	case PacketRetry:
		return "Retry"
	case PacketShortHeader:
		return "1-RTT"
	default:
		return "Unknown"
	}
}

// ClassifyPacket determines the type of a QUIC packet from its first byte.
func ClassifyPacket(packet []byte) PacketType {
	if len(packet) < 1 {
		return PacketUnknown
	}
	if packet[0]&0x80 == 0 {
		return PacketShortHeader
	}
	longType := (packet[0] & 0x30) >> 4
	switch longType {
	case 0x00:
		return PacketInitial
	case 0x01:
		return PacketZeroRTT
	case 0x02:
		return PacketHandshake
	case 0x03:
		return PacketRetry
	}
	return PacketUnknown
}

// ExtractDCID extracts the Destination Connection ID from any QUIC packet.
func ExtractDCID(packet []byte, dcidLen int) ([]byte, error) {
	if len(packet) < 1 {
		return nil, errors.New("packet too short")
	}
	if packet[0]&0x80 == 0 {
		if dcidLen <= 0 {
			return nil, errors.New("dcidLen required for short header")
		}
		if len(packet) < 1+dcidLen {
			return nil, errors.New("packet too short for DCID")
		}
		return packet[1 : 1+dcidLen], nil
	}
	if len(packet) < 6 {
		return nil, errors.New("packet too short for long header")
	}
	dcidLenFromPacket := int(packet[5])
	if len(packet) < 6+dcidLenFromPacket {
		return nil, errors.New("packet too short for DCID")
	}
	return packet[6 : 6+dcidLenFromPacket], nil
}

// ExtractDCIDAndSCID extracts both DCID and SCID from a Long Header packet.
func ExtractDCIDAndSCID(packet []byte) ([]byte, []byte, error) {
	if len(packet) < 1 {
		return nil, nil, errors.New("packet too short")
	}
	if packet[0]&0x80 == 0 {
		return nil, nil, errors.New("short header")
	}
	if len(packet) < 6 {
		return nil, nil, errors.New("packet too short for long header")
	}
	offset := 5
	dcidLen := int(packet[offset])
	offset++
	if offset+dcidLen > len(packet) {
		return nil, nil, errors.New("packet too short for DCID")
	}
	dcid := packet[offset : offset+dcidLen]
	offset += dcidLen
	if offset >= len(packet) {
		return nil, nil, errors.New("packet too short for SCID length")
	}
	scidLen := int(packet[offset])
	offset++
	if offset+scidLen > len(packet) {
		return nil, nil, errors.New("packet too short for SCID")
	}
	scid := packet[offset : offset+scidLen]
	return dcid, scid, nil
}

// ExtractAllSCIDs extracts SCIDs from all coalesced packets in a UDP datagram.
func ExtractAllSCIDs(datagram []byte) [][]byte {
	var scids [][]byte
	seen := make(map[string]bool)
	offset := 0
	for offset < len(datagram) {
		if datagram[offset]&0x80 == 0 {
			break
		}
		pkt := datagram[offset:]
		if len(pkt) < 6 {
			break
		}
		headerOffset := 5
		dcidLen := int(pkt[headerOffset])
		headerOffset++
		headerOffset += dcidLen
		if headerOffset >= len(pkt) {
			break
		}
		scidLen := int(pkt[headerOffset])
		headerOffset++
		if headerOffset+scidLen > len(pkt) {
			break
		}
		scid := pkt[headerOffset : headerOffset+scidLen]
		scidKey := string(scid)
		if !seen[scidKey] && len(scid) > 0 {
			seen[scidKey] = true
			scidCopy := make([]byte, len(scid))
			copy(scidCopy, scid)
			scids = append(scids, scidCopy)
		}
		headerOffset += scidLen
		if headerOffset >= len(pkt) {
			break
		}
		pktLen, lenBytes, err := readVarInt(pkt[headerOffset:])
		if err != nil || lenBytes == 0 {
			break
		}
		headerOffset += lenBytes
		nextOffset := headerOffset + int(pktLen)
		if nextOffset <= 0 || nextOffset > len(pkt) {
			break
		}
		offset += nextOffset
	}
	return scids
}

// CryptoFrame represents a CRYPTO frame with its offset.
type CryptoFrame struct {
	Offset uint64
	Data   []byte
}

// ExtractCryptoFramesFromPacket decrypts an Initial packet and extracts CRYPTO frames.
func ExtractCryptoFramesFromPacket(packet []byte) ([]CryptoFrame, error) {
	if len(packet) < 5 {
		return nil, errors.New("packet too short")
	}
	if ClassifyPacket(packet) != PacketInitial {
		return nil, errors.New("not an initial packet")
	}
	version := binary.BigEndian.Uint32(packet[1:5])
	if version != quicVersion1 {
		return nil, fmt.Errorf("unsupported QUIC version: 0x%08x", version)
	}
	offset := 5
	if offset >= len(packet) {
		return nil, errors.New("packet too short for DCID length")
	}
	dcidLen := int(packet[offset])
	offset++
	if offset+dcidLen > len(packet) {
		return nil, errors.New("packet too short for DCID")
	}
	dcid := packet[offset : offset+dcidLen]
	offset += dcidLen
	if offset >= len(packet) {
		return nil, errors.New("packet too short for SCID length")
	}
	scidLen := int(packet[offset])
	offset++
	offset += scidLen
	tokenLen, n, err := readVarInt(packet[offset:])
	if err != nil {
		return nil, fmt.Errorf("failed to read token length: %w", err)
	}
	offset += n
	offset += int(tokenLen)
	payloadLen, n, err := readVarInt(packet[offset:])
	if err != nil {
		return nil, fmt.Errorf("failed to read payload length: %w", err)
	}
	offset += n
	if offset+int(payloadLen) > len(packet) {
		return nil, errors.New("packet too short for payload")
	}
	encrypted := packet[offset : offset+int(payloadLen)]
	clientKey, clientIV, clientHP, err := deriveInitialKeys(dcid)
	if err != nil {
		return nil, fmt.Errorf("failed to derive keys: %w", err)
	}
	decrypted, err := decryptInitialPacket(packet, encrypted, clientKey, clientIV, clientHP)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	return extractCryptoFrames(decrypted), nil
}

var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

func deriveInitialKeys(dcid []byte) (key, iv, hp []byte, err error) {
	initialSecret := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt)
	clientSecret, err := hkdfExpandLabel(initialSecret, "client in", nil, 32)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err = hkdfExpandLabel(clientSecret, "quic key", nil, 16)
	if err != nil {
		return nil, nil, nil, err
	}
	iv, err = hkdfExpandLabel(clientSecret, "quic iv", nil, 12)
	if err != nil {
		return nil, nil, nil, err
	}
	hp, err = hkdfExpandLabel(clientSecret, "quic hp", nil, 16)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, iv, hp, nil
}

func hkdfExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	fullLabel := "tls13 " + label
	hkdfLabel := make([]byte, 2+1+len(fullLabel)+1+len(context))
	hkdfLabel[0] = byte(length >> 8)
	hkdfLabel[1] = byte(length)
	hkdfLabel[2] = byte(len(fullLabel))
	copy(hkdfLabel[3:], fullLabel)
	hkdfLabel[3+len(fullLabel)] = byte(len(context))
	if len(context) > 0 {
		copy(hkdfLabel[4+len(fullLabel):], context)
	}
	h := hkdf.Expand(sha256.New, secret, hkdfLabel)
	out := make([]byte, length)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
}

func decryptInitialPacket(packet, encrypted, key, iv, hp []byte) ([]byte, error) {
	if len(encrypted) < 20 {
		return nil, errors.New("encrypted payload too short")
	}
	hpCipher, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}
	return decryptWithCrypto(packet, encrypted, hpCipher, aead, iv)
}

func decryptWithCrypto(packet, encrypted []byte, hpCipher cipher.Block, aead cipher.AEAD, iv []byte) ([]byte, error) {
	if len(encrypted) < 20 {
		return nil, errors.New("encrypted payload too short")
	}
	sample := encrypted[4:20]
	var mask [16]byte
	hpCipher.Encrypt(mask[:], sample)
	bufPtr := handler.GetBuffer()
	defer handler.PutBuffer(bufPtr)
	packetCopy := (*bufPtr)[:len(packet)]
	copy(packetCopy, packet)
	if packetCopy[0]&0x80 == 0x80 {
		packetCopy[0] ^= mask[0] & 0x0f
	} else {
		packetCopy[0] ^= mask[0] & 0x1f
	}
	pnLen := (packetCopy[0] & 0x03) + 1
	pnOffset := len(packet) - len(encrypted)
	for i := 0; i < int(pnLen); i++ {
		packetCopy[pnOffset+i] ^= mask[1+i]
	}
	var pn uint64
	for i := 0; i < int(pnLen); i++ {
		pn = (pn << 8) | uint64(packetCopy[pnOffset+i])
	}
	var nonce [12]byte
	copy(nonce[:], iv)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= byte(pn >> (56 - 8*i))
	}
	ciphertext := encrypted[pnLen:]
	aad := packetCopy[:pnOffset+int(pnLen)]
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	return plaintext, nil
}

func extractCryptoFrames(data []byte) []CryptoFrame {
	var frames []CryptoFrame
	offset := 0
	for offset < len(data) {
		frameType, n, err := readVarInt(data[offset:])
		if err != nil {
			break
		}
		offset += n
		switch frameType {
		case 0x00:
			for offset < len(data) && data[offset] == 0x00 {
				offset++
			}
		case 0x01:
			// PING - no payload
		case 0x02, 0x03:
			if _, n, err := readVarInt(data[offset:]); err != nil {
				return frames
			} else {
				offset += n
			}
			if _, n, err := readVarInt(data[offset:]); err != nil {
				return frames
			} else {
				offset += n
			}
			rangeCount, n, err := readVarInt(data[offset:])
			if err != nil {
				return frames
			}
			offset += n
			if _, n, err := readVarInt(data[offset:]); err != nil {
				return frames
			} else {
				offset += n
			}
			for i := uint64(0); i < rangeCount; i++ {
				if _, n, err := readVarInt(data[offset:]); err != nil {
					return frames
				} else {
					offset += n
				}
				if _, n, err := readVarInt(data[offset:]); err != nil {
					return frames
				} else {
					offset += n
				}
			}
			if frameType == 0x03 {
				for i := 0; i < 3; i++ {
					if _, n, err := readVarInt(data[offset:]); err != nil {
						return frames
					} else {
						offset += n
					}
				}
			}
		case 0x06:
			cryptoOffset, n, err := readVarInt(data[offset:])
			if err != nil {
				break
			}
			offset += n
			length, n, err := readVarInt(data[offset:])
			if err != nil {
				break
			}
			offset += n
			if offset+int(length) > len(data) {
				break
			}
			frameData := make([]byte, length)
			copy(frameData, data[offset:offset+int(length)])
			frames = append(frames, CryptoFrame{
				Offset: cryptoOffset,
				Data:   frameData,
			})
			offset += int(length)
		default:
			return frames
		}
	}
	return frames
}

func parseTLSClientHello(data []byte) (*handler.ClientHello, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("TLS record too short: got %d bytes", len(data))
	}
	if data[0] != 0x01 {
		return nil, fmt.Errorf("expected ClientHello(1), got type %d", data[0])
	}
	hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+hsLen {
		return nil, errors.New("ClientHello truncated")
	}
	offset := 4
	offset += 2  // Client Version
	offset += 32 // Random
	if offset >= len(data) {
		return nil, errors.New("ClientHello too short for session ID")
	}
	sessionIDLen := int(data[offset])
	offset++
	offset += sessionIDLen
	if offset+2 > len(data) {
		return nil, errors.New("ClientHello too short for cipher suites")
	}
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	offset += cipherSuitesLen
	if offset >= len(data) {
		return nil, errors.New("ClientHello too short for compression")
	}
	compressionLen := int(data[offset])
	offset++
	offset += compressionLen
	if offset+2 > len(data) {
		return nil, errors.New("ClientHello too short for extensions")
	}
	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	hello := &handler.ClientHello{Raw: data}
	extEnd := offset + extensionsLen
	for offset < extEnd && offset+4 <= len(data) {
		extType := int(data[offset])<<8 | int(data[offset+1])
		offset += 2
		extLen := int(data[offset])<<8 | int(data[offset+1])
		offset += 2
		if offset+extLen > len(data) {
			break
		}
		switch extType {
		case 0x00:
			hello.SNI = parseSNI(data[offset : offset+extLen])
		case 0x10:
			hello.ALPNProtocols = parseALPN(data[offset : offset+extLen])
		}
		offset += extLen
	}
	return hello, nil
}

func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	offset := 2
	if data[offset] != 0 {
		return ""
	}
	offset++
	nameLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	if offset+nameLen > len(data) {
		return ""
	}
	return string(data[offset : offset+nameLen])
}

func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	offset := 2
	var protocols []string
	for offset < len(data) {
		protoLen := int(data[offset])
		offset++
		if offset+protoLen > len(data) {
			break
		}
		protocols = append(protocols, string(data[offset:offset+protoLen]))
		offset += protoLen
	}
	return protocols
}

func readVarInt(data []byte) (uint64, int, error) {
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
