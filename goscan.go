package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
	"strconv"
)

func makeRange(min, max int) []int {
    a := make([]int, max-min+1)
    for i := range a {
    	a[i] = min + i
    }
    return a
}

func main() {
	// command line args
	allPortsPtr := flag.Bool("all-ports", false, "Scan all TCP Ports")
	portPtr := flag.String("ports", "21,22,23,25,53,80,81,88,110,111,123,137,138,139,143,161,389,443,445,500,512,513,548,623,624,1099,1241,1433,1434,1521,2049,2483,2484,3268,3269,3306,3389,4333,4786,4848,5432,5800,5900,5901,5985,5986,6000,6001,7001,8000,8080,8181,8443,10000,16992,16993,27017,32764", "Specify TCP ports to scan, comma separated.")
	targetPtr := flag.String("target", "scanme.nmap.org", "Target IP address, network address in CIDR format, or hostname")
	flag.Parse()

	var wg sync.WaitGroup

	// create a channel to scan 256 concurrent ports
	ipchan := make(chan string, 256)

	tcpports := strings.Split(*portPtr, ",")

	if *allPortsPtr == true {
		intports := makeRange(1,65535)
		tcpports = []string{}
		for i := range intports {
			number := intports[i]
			text := strconv.Itoa(number)
			tcpports = append(tcpports, text)
		}
	}
	

	// If the target is a network address, extract hosts from network and scan,
	// otherwise send straight to the scanHost func
	if strings.Contains(*targetPtr, "/") {
		hosts := cidrHosts(*targetPtr)
		for i := 0; i < cap(ipchan); i++ {
			go scanHost(ipchan, &wg)
		}
		for _, h := range hosts {
			for _, p := range tcpports {
				wg.Add(1)
				ipchan <- h + ":" + p
			}
		}
		close(ipchan)
	} else {
		for i := 0; i < cap(ipchan); i++ {
			go scanHost(ipchan, &wg)
		}
		for _, p := range tcpports {
			wg.Add(1)
			ipchan <- *targetPtr + ":" + p
		}
		close(ipchan)
	}

	wg.Wait()
}

func cidrHosts(netw string) []string {
	// convert string to IPNet struct
	_, ipv4Net, err := net.ParseCIDR(netw)
	if err != nil {
		log.Fatal(err)
	}
	// convert IPNet struct mask and address to uint32
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	// fing the start IP address
	start := binary.BigEndian.Uint32(ipv4Net.IP)
	// find the final IP address
	finish := (start & mask) | (mask ^ 0xffffffff)
	// make a slice to return host addresses
	var hosts []string
	// loop through addresses as uint32
	for i := start + 1; i <= finish-1; i++ {
		// convert back to net.IPs
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		hosts = append(hosts, ip.String())
	}
	// return a slice of strings containing IP addresses
	return hosts
}

func scanHost(ipchan chan string, wg *sync.WaitGroup) {
	for i := range ipchan {
		conn, err := net.DialTimeout("tcp", i, 1*time.Second)
		if err != nil {
			wg.Done()
			continue
		}
		conn.Close()
		fmt.Println(i)
		wg.Done()
	}
}
