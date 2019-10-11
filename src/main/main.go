package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	manuf "github.com/timest/gomanuf"
)

var log = logrus.New()

// ipNet stores IP address and subnet mask
var ipNet *net.IPNet

// The mac address of this machine needs to be used to send Ethernet packets.
var localHaddr net.HardwareAddr
var iface string

// Store the final data, key[string] stores the IP address
var data map[string]Info

// Timer, no new data is written to data for a period of time, exit the program, and reset the timer
var t *time.Ticker
var do chan string

const (
	// 3 second timer
	START = "start"
	END   = "end"
)

type Info struct {
	// IP address
	Mac net.HardwareAddr
	// CPU name
	Hostname string
	// Vendor information
	Manuf string
}

// Formatted output
// xxx.xxx.xxx.xxx  xx:xx:xx:xx:xx:xx  hostname  manuf
func PrintData() {
	var keys IPSlice
	for k := range data {
		keys = append(keys, ParseIPString(k))
	}
	sort.Sort(keys)
	for _, k := range keys {
		d := data[k.String()]
		mac := ""
		if d.Mac != nil {
			mac = d.Mac.String()
		}
		fmt.Printf("%-15s %-17s %-30s %-10s\n", k.String(), mac, d.Hostname, d.Manuf)
	}
}

// Add the captured data set to the data and reset the timer
func pushData(ip string, mac net.HardwareAddr, hostname, manuf string) {
	// Stop timer
	do <- START
	var mu sync.RWMutex
	mu.RLock()
	defer func() {
		// Reset timer
		do <- END
		mu.RUnlock()
	}()
	if _, ok := data[ip]; !ok {
		data[ip] = Info{Mac: mac, Hostname: hostname, Manuf: manuf}
		return
	}
	info := data[ip]
	if len(hostname) > 0 && len(info.Hostname) == 0 {
		info.Hostname = hostname
	}
	if len(manuf) > 0 && len(info.Manuf) == 0 {
		info.Manuf = manuf
	}
	if mac != nil {
		info.Mac = mac
	}
	data[ip] = info
}

func setupNetInfo(f string) {
	var ifs []net.Interface
	var err error
	if f == "" {
		ifs, err = net.Interfaces()
	} else {
		// Already selected interface
		var it *net.Interface
		it, err = net.InterfaceByName(f)
		if err == nil {
			ifs = append(ifs, *it)
		}
	}
	if err != nil {
		log.Fatal("Unable to get local network information:", err)
	}
	for _, it := range ifs {
		addr, _ := it.Addrs()
		for _, a := range addr {
			if ip, ok := a.(*net.IPNet); ok && !ip.IP.IsLoopback() {
				if ip.IP.To4() != nil {
					ipNet = ip
					localHaddr = it.HardwareAddr
					iface = it.Name
					goto END
				}
			}
		}
	}
END:
	if ipNet == nil || len(localHaddr) == 0 {
		log.Fatal("Unable to get local network information.")
	}
}

func localHost() {
	host, _ := os.Hostname()
	data[ipNet.IP.String()] = Info{Mac: localHaddr, Hostname: strings.TrimSuffix(host, ".local"), Manuf: manuf.Search(localHaddr.String())}
}

func sendARP() {
	// ips is a collection of intranet IP addresses
	ips := Table(ipNet)
	for _, ip := range ips {
		go sendArpPackage(ip)
	}
}

func main() {
	// allow non root user to execute by compare with euid
	if os.Geteuid() != 0 {
		log.Fatal("goscan must run as root.")
	}
	flag.StringVar(&iface, "I", "", "Network interface name")
	flag.Parse()
	// Initialize data
	data = make(map[string]Info)
	do = make(chan string)
	// Initialize network information
	setupNetInfo(iface)

	ctx, cancel := context.WithCancel(context.Background())
	go listenARP(ctx)
	go listenMDNS(ctx)
	go listenNBNS(ctx)
	go sendARP()
	go localHost()

	t = time.NewTicker(4 * time.Second)
	for {
		select {
		case <-t.C:
			PrintData()
			cancel()
			goto END
		case d := <-do:
			switch d {
			case START:
				t.Stop()
			case END:
				// Receive new data, reset the counter for 2 seconds
				t = time.NewTicker(2 * time.Second)
			}
		}
	}
END:
}
