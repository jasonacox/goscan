# GoScan (Network Scanning Tool)

![image](https://user-images.githubusercontent.com/1621058/32154543-63c4e560-bcff-11e7-8a92-5281e18f221e.png)
 
**Features:**
 * Scan the whole IPv4 address space
 * Scan your local network with ARP packets
 * Display the IP address, MAC address, hostname and vendor associated
 * Using SMB(Windows devices) and mDNS(Apple devices) to detect hostname
 
 
### Usage: ###

# Option 1 - Run Build Script

```sh
$ ./build.sh
Building goscan MacOS binary...
Build complete...
-rwxr-xr-x  1 coxj  staff   5.7M Oct 11 16:21 scan

# execute
$ sudo ./scan  
# or
$ sudo ./scan -I en0
```

# Option 2 - Run Build Script for Docker
```sh
$ ./build-docker.sh 
Building goscan Linux binary...
Sending build context to Docker daemon  6.561MB
Successfully built 7e1fcc9b28de
Successfully tagged goscan:latest
Build complete...
-rwxr-xr-x  1 coxj  staff   4.7M Oct 11 16:31 scan

# execute
$ sudo ./scan  
# or
$ sudo ./scan -I en0
```

NOTE: Goscan must run as **root**.

Goscan works on Linux/Mac using [libpcap](http://www.tcpdump.org/) and on Windows with [WinPcap](https://www.winpcap.org/install/). 

# Credit

Fork from https://github.com/timest/goscan


