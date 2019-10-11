package main

import (
    "net"
    "strconv"
    "bytes"
    "math"
    "strings"
)

type IP uint32

// Convert IP(uint32) to a readable IP string
func (ip IP) String() string {
    var bf bytes.Buffer
    for i := 1; i <= 4; i++ {
        bf.WriteString(strconv.Itoa(int((ip >> ((4 - uint(i)) * 8)) & 0xff)))
        if i != 4 {
            bf.WriteByte('.')
        }
    }
    return bf.String()
}

// Table -- Convert intranet IP range based on IP and mask
func Table(ipNet *net.IPNet) []IP {
    ip := ipNet.IP.To4()
    log.Info("Native IP: ", ip)
    var min, max IP
    var data []IP
    for i := 0; i < 4; i++ {
        b := IP(ip[i] & ipNet.Mask[i])
        min += b << ((3 - uint(i)) * 8)
    }
    one, _ := ipNet.Mask.Size()
    max = min | IP(math.Pow(2, float64(32 - one)) - 1)
    log.Infof("Intranet IP range:%s --- %s: ", min, max)
    // max is the broadcast address, ignored
    // i & 0x000000ff == 0 if the IP with a trailing segment of 0, ignored according to the RFC rules.
    for i := min; i < max; i++ {
        if i & 0x000000ff == 0 {
            continue
        }
        data = append(data, i)
    }
    return data
}

// ParseIP -- []byte --> IP
func ParseIP(b []byte) IP {
    return IP(IP(b[0]) << 24 + IP(b[1]) << 16 + IP(b[2]) << 8 + IP(b[3]))
}

// ParseIPString -- string --> IP
func ParseIPString(s string) IP{
    var b []byte
    for _, i := range strings.Split(s, ".") {
        v, _ := strconv.Atoi(i)
        b = append(b, uint8(v))
    }
    return ParseIP(b)
}

// IPSlice -- implements the sort interface of sort
type IPSlice []IP
func (ip IPSlice) Len() int { return len(ip) }
func (ip IPSlice) Swap(i, j int) {
    ip[i], ip[j] = ip[j], ip[i]
}
func (ip IPSlice) Less(i, j int) bool {
    return ip[i] < ip[j]
}