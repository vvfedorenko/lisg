package main

import (
	"fmt"

	"github.com/vishvananda/netlink/nl"
	"../protocol"
)

const ISG_NETLINK_FAM int = 32

func Main() {
	fmt.Println("Linux ISG CLI tool")

	ev := UserEventSessionInfo{
		EventType := EventSessGetlist
	}

	req := nl.NewNetlinkRequest(ISG_NETLINK_FAM, 0)
	req.AddRawData(SerializeUserSessionEvent(&ev))
	res := req.Execute(ISG_NETLINK_FAM, 0)
	for rmsg = range res {
		msg, err := protocol.DeserializeKernelEvent(rmsg)
		fmt.Println("%d  %v  %s")
	}
}
