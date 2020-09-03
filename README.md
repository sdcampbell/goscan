# goscan
Goscan is a fast TCP scanner I created while learning Golang.

Usage:

```
./portscan -h
Usage of ./portscan:
  -ports string
    	TCP ports to scan, comma separated. (default "21,22,23,25,53,80,81,88,110,111,123,137,138,139,143,161,389,443,445,500,512,513,548,623,624,1099,1241,1433,1434,1521,2049,2483,2484,3268,3269,3306,3389,4333,4786,4848,5432,5800,5900,5901,6000,6001,7001,8000,8080,8181,8443,10000,16992,16993,27017,32764")
  -target string
    	Target IP address, network address in CIDR format, or hostname (default "scanme.nmap.org")
```

Time to scan the 55 default ports on a Class C network:

```
real	0m5.027s
user	0m0.112s
sys	0m0.062s
```
