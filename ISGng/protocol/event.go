package isg

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type EventType uint32

const (
	/* From Userspace to Kernel */
	EventListenerReg   EventType = 0x01
	EventListenerRegV1 EventType = 0x101
	EventListenerUnreg EventType = 0x02
	EventSessApprove   EventType = 0x04
	EventSessChange    EventType = 0x05
	EventSessClear     EventType = 0x09
	EventSessGetlist   EventType = 0x10
	EventSessGetcount  EventType = 0x12
	EventNEAddQueue    EventType = 0x14
	EventNESweepQueue  EventType = 0x15
	EventNECommit      EventType = 0x16
	EventServApply     EventType = 0x17
	EventSDescAdd      EventType = 0x18
	EventSDescSweepTC  EventType = 0x19
	EventServGetlist   EventType = 0x20

	/* From Kernel to Userspace */
	EventSessCreate EventType = 0x03
	EventSessStart  EventType = 0x06
	EventSessUpdate EventType = 0x07
	EventSessStop   EventType = 0x08
	EventSessInfo   EventType = 0x11
	EventSessCount  EventType = 0x13

	EventKernelAck  EventType = 0x98
	EventKernelNack EventType = 0x99

	NSecsPerSec uint64 = 1e9
)

// Event abstracts away any ISG query
type Event interface {
	Type() EventType
}

// EventHead is common part for all events
type EventHead struct {
	EventType EventType
}

// Type implements Event interface
func (e EventHead) Type() EventType {
	return e.EventType
}

func eventHeadMarshalBinaryTo(e *EventHead, b []byte) {
	binary.BigEndian.PutUint32(b, uint32(e.EventType))
}

func sessionInfoToBinary(si *SessionInfo) []byte {
	var buf Buffer
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, si.Id)
	buf.Write(tmp)

	buf.Write(si.Cookie)

	binary.BigEndian.PutUint32(tmp, si.IpAddr)
	buf.Write(tmp[:4])
	binary.BigEndian.PutUint32(tmp, si.NatIpAddr)
	buf.Write(tmp[:4])

	buf.Write(si.MacAddr)

	binary.BigEndian.PutUint32(tmp, si.Flags)
	buf.Write(tmp[:4])
	binary.BigEndian.PutUint32(tmp, si.PortNumber)
	buf.Write(tmp[:4])

	// TODO: change to v1
	binary.BigEndian.PutUint32(tmp, uint32(si.ExportInterval/NSecsPerSec))
	buf.Write(tmp[:4])
	binary.BigEndian.PutUint32(tmp, uint32(si.IdleTimeout/NSecsPerSec))
	buf.Write(tmp[:4])
	binary.BigEndian.PutUint32(tmp, uint32(si.MaxDuration/NSecsPerSec))
	buf.Write(tmp[:4])

	binary.BigEndian.PutUint32(tmp, si.Rate[0].Rate)
	buf.Write(tmp[:4])
	binary.BigEndian.PutUint32(tmp, si.Rate[0].Burst)
	buf.Write(tmp[:4])
	binary.BigEndian.PutUint32(tmp, si.Rate[1].Rate)
	buf.Write(tmp[:4])
	binary.BigEndian.PutUint32(tmp, si.Rate[1].Burst)
	buf.Write(tmp[:4])

	return buf.Bytes()
}

func unmarshalEventHead(e *TLVHead, b *bytes.Reader) error {
	if b.Len() < 4 {
		return fmt.Errorf("not enough data to decode event")
	}
	var tmp uint32
	binary.Read(b, binary.BigEndian, &tmp)
	e.EventType = EventType(tmp)
	return nil
}

func unmarshalSessionInfo(si *SessionInfo, b *bytes.Reader) error {
	binary.Read(b, binary.BigEndian, &si.Id)
	binary.Read(b, binary.BigEndian, si.Cookie)

	binary.Read(b, binary.BigEndian, &si.IpAddr)
	binary.Read(b, binary.BigEndian, &si.NatIpAddr)
	binary.Read(b, binary.BigEndian, si.MacAddr)
	binary.Read(b, binary.BigEndian, &si.Flags)
	binary.Read(b, binary.BigEndian, &si.PortNumber)
	// TODO: Change to v1
	var tmp uint32
	binary.Read(b, binary.BigEndian, &tmp)
	si.ExportInterval = unit64(tmp) * NSecsPerSec
	binary.Read(b, binary.BigEndian, &tmp)
	si.IdleTimeout = unit64(tmp) * NSecsPerSec
	binary.Read(b, binary.BigEndian, &tmp)
	si.MaxDuration = unit64(tmp) * NSecsPerSec
	binary.Read(b, binary.BigEndian, &si.Rate[0].Rate)
	binary.Read(b, binary.BigEndian, &si.Rate[0].Burst)
	binary.Read(b, binary.BigEndian, &si.Rate[1].Rate)
	binary.Read(b, binary.BigEndian, &si.Rate[1].Burst)
	return nil
}

func unmarshalEventSessionStat(s *EventSessionStat, b *bytes.Reader) error {
	binary.Read(b, binary.BigEndian, &s.duration)
	binary.Read(b, binary.BigEndian, &s.padding)
	binary.Read(b, binary.BigEndian, &s.inPackets)
	binary.Read(b, binary.BigEndian, &s.inBytes)
	binary.Read(b, binary.BigEndian, &s.outPackets)
	binary.Read(b, binary.BigEndian, &s.outBytes)
	return nil
}

func DeserializeKernelEvent(b []byte) (*KernelEvent, error) {
	ev := KernelEvent{}

	r := bytes.NewReader(b)
	err := unmarshalEventHead(&ev.EventHead, r)
	if err != nil {
		return nil, err
	}
	_ = unmarshalSessionInfo(&ev.Sinfo, r)
	_ = unmarshalEventSessionStat(&ev.Sstat, r)
	_ = binary.Read(r, binary.BigEndian, &ev.ParentSessionID)
	binary.Read(r, binary.BigEndian, ev.ServiceName)

	return &ev, nil
}

func SerializeUserSessionEvent(ev *UserEventSessionInfo) []byte {
	var b []byte
	eventHeadMarshalBinaryTo(&ev.EventHead, b)
	b += sessionInfoToBinary(&ev.Sinfo)

	return b
}

type EventSessionStat struct {
	duration uint32
	padding  uint32

	inPackets  uint64
	inBytes    uint64
	outPackets uint64
	outBytes   uint64
}

// Kernel events

type KernelEvent struct {
	EventHead
	Sinfo           SessionInfo
	Sstat           EventSessionStat
	ParentSessionID uint64
	ServiceName     [64]byte
}

// User-space events

type UserEventSessionInfo struct {
	EventHead
	Sinfo       SessionInfo
	ServiceName [32]byte
	Flags       byte
}

type UserEventNetworkEntry struct {
	EventHead
	Prefix uint32
	Mask   uint32
	TCName [32]byte
}

type UserEventServiceDescription struct {
	TCName      [32]byte
	ServiceName [32]byte
	Flags       byte
}
