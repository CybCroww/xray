package hysteria

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/hysteria"
)

const (
	// Max length values are for preventing DoS attacks

	MaxAddressLength = 2048
	MaxMessageLength = 2048
	MaxPaddingLength = 4096

	maxVarInt1 = 63
	maxVarInt2 = 16383
	maxVarInt4 = 1073741823
	maxVarInt8 = 4611686018427387903
)

// TCPRequest format:
// Address length (QUIC varint)
// Address (bytes)
// Padding length (QUIC varint)
// Padding (bytes)

func ReadTCPRequest(r io.Reader) (string, error) {
	bReader := quicvarint.NewReader(r)
	addrLen, err := quicvarint.Read(bReader)
	if err != nil {
		return "", err
	}
	if addrLen == 0 || addrLen > MaxAddressLength {
		return "", errors.New("invalid address length")
	}
	addrBuf := make([]byte, addrLen)
	_, err = io.ReadFull(r, addrBuf)
	if err != nil {
		return "", err
	}
	paddingLen, err := quicvarint.Read(bReader)
	if err != nil {
		return "", err
	}
	if paddingLen > MaxPaddingLength {
		return "", errors.New("invalid padding length")
	}
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, r, int64(paddingLen))
		if err != nil {
			return "", err
		}
	}
	return string(addrBuf), nil
}

func WriteTCPRequest(w io.Writer, addr string) error {
	padding := hysteria.TcpRequestPadding.String()
	paddingLen := len(padding)
	addrLen := len(addr)
	sz := int(quicvarint.Len(uint64(addrLen))) + addrLen +
		int(quicvarint.Len(uint64(paddingLen))) + paddingLen
	buf := make([]byte, sz)
	i := varintPut(buf, uint64(addrLen))
	i += copy(buf[i:], addr)
	i += varintPut(buf[i:], uint64(paddingLen))
	copy(buf[i:], padding)
	_, err := w.Write(buf)
	return err
}

// TCPResponse format:
// Status (byte, 0=ok, 1=error)
// Message length (QUIC varint)
// Message (bytes)
// Padding length (QUIC varint)
// Padding (bytes)

func ReadTCPResponse(r io.Reader) (bool, string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return false, "", err
	}
	bReader := quicvarint.NewReader(r)
	msgLen, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", err
	}
	if msgLen > MaxMessageLength {
		return false, "", errors.New("invalid message length")
	}
	var msgBuf []byte
	// No message is fine
	if msgLen > 0 {
		msgBuf = make([]byte, msgLen)
		_, err = io.ReadFull(r, msgBuf)
		if err != nil {
			return false, "", err
		}
	}
	paddingLen, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", err
	}
	if paddingLen > MaxPaddingLength {
		return false, "", errors.New("invalid padding length")
	}
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, r, int64(paddingLen))
		if err != nil {
			return false, "", err
		}
	}
	return status[0] == 0, string(msgBuf), nil
}

func WriteTCPResponse(w io.Writer, ok bool, msg string) error {
	padding := hysteria.TcpResponsePadding.String()
	paddingLen := len(padding)
	msgLen := len(msg)
	sz := 1 + int(quicvarint.Len(uint64(msgLen))) + msgLen +
		int(quicvarint.Len(uint64(paddingLen))) + paddingLen
	buf := make([]byte, sz)
	if ok {
		buf[0] = 0
	} else {
		buf[0] = 1
	}
	i := varintPut(buf[1:], uint64(msgLen))
	i += copy(buf[1+i:], msg)
	i += varintPut(buf[1+i:], uint64(paddingLen))
	copy(buf[1+i:], padding)
	_, err := w.Write(buf)
	return err
}

// UDPMessage format:
// Session ID (uint32 BE)
// Packet ID (uint16 BE)
// Fragment ID (uint8)
// Fragment count (uint8)
// Address length (QUIC varint)
// Address (bytes)
// Data...

type UDPMessage struct {
	SessionID uint32 // 4
	PacketID  uint16 // 2
	FragID    uint8  // 1
	FragCount uint8  // 1
	Addr      string // varint + bytes
	Data      []byte
}

func (m *UDPMessage) HeaderSize() int {
	lAddr := len(m.Addr)
	return 4 + 2 + 1 + 1 + int(quicvarint.Len(uint64(lAddr))) + lAddr
}

func (m *UDPMessage) Size() int {
	return m.HeaderSize() + len(m.Data)
}

func (m *UDPMessage) Serialize(buf []byte) int {
	// Make sure the buffer is big enough
	if len(buf) < m.Size() {
		return -1
	}
	// binary.BigEndian.PutUint32(buf, m.SessionID)
	binary.BigEndian.PutUint16(buf[4:], m.PacketID)
	buf[6] = m.FragID
	buf[7] = m.FragCount
	i := varintPut(buf[8:], uint64(len(m.Addr)))
	i += copy(buf[8+i:], m.Addr)
	i += copy(buf[8+i:], m.Data)
	return 8 + i
}

func ParseUDPMessage(msg []byte) (*UDPMessage, error) {
	if len(msg) < 9 {
		return nil, io.ErrUnexpectedEOF
	}
	m := &UDPMessage{
		SessionID: binary.BigEndian.Uint32(msg[:4]),
		PacketID:  binary.BigEndian.Uint16(msg[4:6]),
		FragID:    msg[6],
		FragCount: msg[7],
	}
	lAddr, n, err := quicvarint.Parse(msg[8:])
	if err != nil {
		return nil, err
	}
	if lAddr == 0 || lAddr > MaxMessageLength {
		return nil, errors.New("invalid address length")
	}
	offset := 8 + n
	if len(msg)-offset <= int(lAddr) {
		// We use <= instead of < here as we expect at least one byte of data after the address
		return nil, errors.New("invalid message length")
	}
	m.Addr = string(msg[offset : offset+int(lAddr)])
	m.Data = msg[offset+int(lAddr):]
	return m, nil
}

// varintPut is like quicvarint.Append, but instead of appending to a slice,
// it writes to a fixed-size buffer. Returns the number of bytes written.
func varintPut(b []byte, i uint64) int {
	if i <= maxVarInt1 {
		b[0] = uint8(i)
		return 1
	}
	if i <= maxVarInt2 {
		b[0] = uint8(i>>8) | 0x40
		b[1] = uint8(i)
		return 2
	}
	if i <= maxVarInt4 {
		b[0] = uint8(i>>24) | 0x80
		b[1] = uint8(i >> 16)
		b[2] = uint8(i >> 8)
		b[3] = uint8(i)
		return 4
	}
	if i <= maxVarInt8 {
		b[0] = uint8(i>>56) | 0xc0
		b[1] = uint8(i >> 48)
		b[2] = uint8(i >> 40)
		b[3] = uint8(i >> 32)
		b[4] = uint8(i >> 24)
		b[5] = uint8(i >> 16)
		b[6] = uint8(i >> 8)
		b[7] = uint8(i)
		return 8
	}
	panic(fmt.Sprintf("%#x doesn't fit into 62 bits", i))
}

func FragUDPMessage(m *UDPMessage, maxSize int) []UDPMessage {
	if m.Size() <= maxSize {
		return []UDPMessage{*m}
	}
	fullPayload := m.Data
	maxPayloadSize := maxSize - m.HeaderSize()
	if maxPayloadSize <= 0 {
		return nil
	}
	off := 0
	fragID := uint8(0)
	fragCount := uint8((len(fullPayload) + maxPayloadSize - 1) / maxPayloadSize) // round up
	frags := make([]UDPMessage, fragCount)
	for off < len(fullPayload) {
		payloadSize := len(fullPayload) - off
		if payloadSize > maxPayloadSize {
			payloadSize = maxPayloadSize
		}
		frag := *m
		frag.FragID = fragID
		frag.FragCount = fragCount
		frag.Data = fullPayload[off : off+payloadSize]
		frags[fragID] = frag
		off += payloadSize
		fragID++
	}
	return frags
}

const mobileUDPReassemblyBudget = 16 * 1024

// Defragger bounds the number of incomplete UDP packets kept for a connection.
type Defragger struct {
	slots        [8]fragmentSlot
	generation   uint64
	byteLimit    int
	pendingBytes int
}

type fragmentSlot struct {
	pktID     uint16
	count     int
	size      int
	bytes     int
	lastSeen  uint64
	addr      string
	fragments [][]byte
}

func (d *Defragger) Feed(m *UDPMessage) *UDPMessage {
	return d.feed(m, nil)
}

// feed assembles into out when supplied. Each retained fragment owns its data,
// because UDPReader reuses its read buffer for the next fragment.
func (d *Defragger) feed(m *UDPMessage, out []byte) *UDPMessage {
	if m.FragCount <= 1 {
		return m
	}
	if m.FragID >= m.FragCount || len(m.Data) == 0 {
		return nil
	}

	slot := d.findSlot(m.PacketID)
	if slot != nil && (len(slot.fragments) != int(m.FragCount) || slot.addr != m.Addr) {
		d.release(slot)
		slot = nil
	}
	limit := int(^uint16(0)) - 8 // Maximum UDP payload with a 16-bit length field.
	if out != nil {
		limit = min(limit, len(out))
	}
	size := len(m.Data)
	if slot != nil {
		if slot.fragments[m.FragID] != nil {
			return nil
		}
		size += slot.size
	}
	if size > limit {
		if slot != nil {
			d.release(slot)
		}
		return nil
	}

	if slot != nil && slot.count+1 == len(slot.fragments) {
		if out == nil {
			out = make([]byte, size)
		}
		// The newest fragment can alias out. Move it before writing earlier fragments.
		offset := 0
		for _, fragment := range slot.fragments[:m.FragID] {
			offset += len(fragment)
		}
		copy(out[offset:], m.Data)
		offset = 0
		for i, fragment := range slot.fragments {
			if i == int(m.FragID) {
				offset += len(m.Data)
			} else {
				offset += copy(out[offset:], fragment)
			}
		}
		m.Data = out[:size]
		m.FragID = 0
		m.FragCount = 1
		d.release(slot)
		return m
	}

	extraBytes := len(m.Data)
	if slot == nil {
		// Count the retained address and fragment table, using 64-bit slice headers.
		extraBytes += len(m.Addr) + int(m.FragCount)*24
	}
	if d.byteLimit > 0 {
		if extraBytes > d.byteLimit || (slot != nil && slot.bytes+extraBytes > d.byteLimit) {
			if slot != nil {
				d.release(slot)
			}
			return nil
		}
		for d.pendingBytes+extraBytes > d.byteLimit {
			d.release(d.oldestSlot(slot))
		}
	}
	if slot == nil {
		slot = d.newSlot()
		slot.pktID = m.PacketID
		slot.addr = m.Addr
		slot.fragments = make([][]byte, m.FragCount)
	}
	d.generation++
	slot.lastSeen = d.generation
	slot.fragments[m.FragID] = make([]byte, len(m.Data))
	copy(slot.fragments[m.FragID], m.Data)
	slot.count++
	slot.size = size
	slot.bytes += extraBytes
	d.pendingBytes += extraBytes
	return nil
}

func (d *Defragger) findSlot(packetID uint16) *fragmentSlot {
	for i := range d.slots {
		if d.slots[i].fragments != nil && d.slots[i].pktID == packetID {
			return &d.slots[i]
		}
	}
	return nil
}

func (d *Defragger) oldestSlot(exclude *fragmentSlot) *fragmentSlot {
	var oldest *fragmentSlot
	for i := range d.slots {
		slot := &d.slots[i]
		if slot == exclude || slot.fragments == nil {
			continue
		}
		if oldest == nil || slot.lastSeen < oldest.lastSeen {
			oldest = slot
		}
	}
	return oldest
}

func (d *Defragger) newSlot() *fragmentSlot {
	for i := range d.slots {
		if d.slots[i].fragments == nil {
			return &d.slots[i]
		}
	}
	slot := d.oldestSlot(nil)
	d.release(slot)
	return slot
}

func (d *Defragger) release(slot *fragmentSlot) {
	d.pendingBytes -= slot.bytes
	*slot = fragmentSlot{}
}
