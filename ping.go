package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func ping(target string) bool {
	//isIpv6 := false
	ip, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		ip, err = net.ResolveIPAddr("ip6", target)
		if err != nil {
			fmt.Printf("Ping Error on ListenPacket")
			return false
		} else {
			//isIpv6 = true
		}
	}
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Printf("Ping Error on ListenPacket ", err)
		return false
	}
	defer conn.Close()
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte("are_you_alive"),
		},
	}
	msg_bytes, err := msg.Marshal(nil)
	if err != nil {
		fmt.Printf("Ping Error on Marshal %v ", err)
		return false
	}

	// Write the message to the listening connection
	netAddr := &net.IPAddr{IP: net.ParseIP(ip.IP.String())}
	if _, err := conn.WriteTo(msg_bytes, netAddr); err != nil {
		fmt.Printf("Ping Error on WriteTo %v ", err)
		return false
	}
	timeOut := time.Second * time.Duration(config.PingTimeOut)
	err = conn.SetReadDeadline(time.Now().Add(timeOut))
	if err != nil {
		fmt.Printf("Ping Error on SetReadDeadline %v ", err)
		return false
	}
	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		fmt.Printf("Ping Error on ReadFrom %v ", err)
		return false
	}
	parsed_reply, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		fmt.Printf("Ping Error on ParseMessage %v ", err)
		return false
	}
	switch parsed_reply.Code {
	case 0:
		// Got a reply so we can save this
		return true
	case 11:
		// Time Exceeded so we can assume our network is slow
		fmt.Printf("Ping Host %s is slow\n", target)
		return false
	default:
		// We don't know what this is so we can assume it's unreachable
		fmt.Printf("Ping Host %s is unreachable\n", target)
		return false
	}
}
