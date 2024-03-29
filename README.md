# goscan
Goscan is a standalone, fast IPv4 TCP scanner I created while learning Golang. I created this project for those times when you need to upload a self contained scanner to a pivot host, because scanning through proxychains is too damn slow!

## Build:

For Linux/Mac: `CGO_ENABLED=0 go build goscan.go`

For Windows: `GOOS=windows go build -o goscan.exe goscan.go`

## Usage:

```
./goscan -h
Usage of goscan:
  -all-ports
    	Scan all TCP Ports
  -ports string
    	Specify TCP ports to scan, comma separated. (default "21,22,23,25,53,80,81,88,110,111,123,137,138,139,143,161,389,443,445,500,512,513,548,623,624,1099,1241,1433,1434,1521,2049,2483,2484,3268,3269,3306,3389,4333,4786,4848,5432,5800,5900,5901,5985,5986,6000,6001,7001,8000,8080,8181,8443,10000,16992,16993,27017,32764")
  -target string
    	Target IPv4 IP address, IPv4 network address in CIDR format, or hostname (default "scanme.nmap.org")
```

The output is easy to grep (no annoying banners):

```
192.168.1.1:80
192.168.1.1:443
192.168.1.25:21
192.168.1.25:445
192.168.1.25:8080
```

Time to scan the 55 default ports on a Class C network:

```
real	0m5.027s
user	0m0.112s
sys	0m0.062s
```

Time to scan all 65k ports on one host:

```
real	4m16.089s
user	0m1.687s
sys	0m2.107s
```
