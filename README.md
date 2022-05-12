# Traceroute Utility
    Accepts IP address or hostname as input.
    Generates ICMP echo request messages of increasing TTL (three requests per hop) until the destination is reached. You can hardcode a reasonable max TTL.
    Each hop is written as a line of output with the hop IP and RTT of each of the three requests.
        Note: No requirements around live/updating output -- 
        program produces no output until the end of execution.
    User can optionally specify a --tcp option which uses TCP SYN packets instead of ICMP echo requests.

## Build Instructions
Either use containerized build or build on a Linux host

### Containerized build
```
./build.sh
```

### On Linux host
The traceroute binary is generated in the build directory  
(Min requirements build-essential tools,  cmake (version 3.10 and above))
``` 
cd build
cmake ..
make 
```  

### Run Instructions
Note RTT for packets not received by the application are displayed as 0.000ms
```
./traceroute <IP|domain> [--tcp]
```

### Tests Done
#### ICMP traceroute
1. any domain
```
sudo ./traceroute google.com
ICMP traceroute to google.com (142.251.46.238), 30 hops max 
.................................
  1  10.0.2.2  0.620ms 0.560ms  0.756ms 
  2  192.168.4.1  3.664ms 2.868ms  2.928ms 
  3  96.120.91.105  12.689ms 12.360ms  12.451ms 
  4  24.124.158.129  11.782ms 11.905ms  12.301ms 
  5  162.151.78.249  13.272ms 11.800ms  11.507ms 
  6  68.87.226.109  12.545ms 13.190ms  12.419ms 
  7  68.86.143.93  12.566ms 12.511ms  12.732ms 
  8  96.112.146.18  12.513ms 13.726ms  15.864ms 
  9  142.251.70.43  15.865ms 13.435ms  18.564ms 
 10  142.251.228.83  13.592ms 14.936ms  9.829ms 
 11  142.251.46.238  14.802ms 13.479ms  17.793ms 
```

2. any Dest IP
```
sudo ./traceroute 1.1.1.1
ICMP traceroute to 1.1.1.1 (1.1.1.1), 30 hops max 
....................................
  1  10.0.2.2  0.666ms 0.529ms  0.389ms 
  2  192.168.4.1  4.825ms 3.872ms  4.025ms 
  3  96.120.91.105  12.411ms 12.548ms  11.639ms 
  4  24.124.158.129  14.993ms 11.526ms  11.344ms 
  5  162.151.78.86  13.647ms 16.475ms  12.049ms 
  6  162.151.79.153  11.886ms 11.263ms  11.155ms 
  7  68.87.193.177  14.107ms 13.109ms  13.455ms 
  8  68.86.93.253  14.172ms 13.606ms  13.881ms 
  9  96.110.32.254  15.767ms 16.400ms  15.153ms 
 10  50.242.151.238  14.524ms 14.533ms  21.585ms 
 11  172.69.132.2  14.045ms 14.157ms  17.006ms 
 12  1.1.1.1  13.685ms 14.158ms  13.271ms 
 ```

3. Unreachable IP
```
sudo build/traceroute 1.2.3.4
ICMP traceroute to 1.2.3.4 (1.2.3.4), 30 hops max 
.......................................................................................
```

#### SYN traceroute
1. any domain
```
sudo ./traceroute google.com --tcp
SYN traceroute to google.com (142.251.46.238), 30 hops max 
......
  1  10.0.2.2  0.516ms 0.498ms  0.515ms 
  2  142.251.46.238  13.777ms 12.771ms  12.153ms
```
Note : For SYN with TTL=1, the first hop returns with ICMP time exceeded  
       but for SYN with TTL= 2, packet is still forwarded to the server, and the SYNACK response is received. (Verified with packet trace)
       It appears that intermediate servers do not decrement ttl for SYN packets


2. any IP
```
sudo ./traceroute 1.1.1.1 --tcp
SYN traceroute to 1.1.1.1 (1.1.1.1), 30 hops max 
......
  1  10.0.2.2  0.605ms 0.382ms  0.524ms 
  2  1.1.1.1  15.306ms 14.768ms  14.731ms
```

#### Invalid Parameters
```
sudo build/traceroute 1.2.3.4 --udp
Usage : traceroute <ip address>|<hostname> [--tcp]
```
