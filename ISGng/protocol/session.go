package isg

type SessionInfo struct {
	Id     uint64
	Cookie [32]uint8

	IpAddr    uint32
	NatIpAddr uint32
	MacAddr   [6]uint8

	Flags uint32

	PortNumber     uint32
	ExportInterval uint64
	IdleTimeout    uint64
	MaxDuration    uint64

	Rate [2]SessionRate
}

type SessionRate struct {
	Rate  uint32
	Burst uint32
}

type SessionStat struct {
	Duration   uint64
	InPackets  uint64
	InBytes    uint64
	OutPackets uint64
	OutBytes   uint64
}
