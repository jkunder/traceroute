# Traceroute Utility
    Accepts IP address or hostname as input.
    Generates ICMP echo request messages of increasing TTL (three requests per hop) until the destination is reached. You can hardcode a reasonable max TTL.
    Each hop is written as a line of output with the hop IP and RTT of each of the three requests.
        Note: No requirements around live/updating output -- 
        program produces no output until the end of execution.
    User can optionally specify a --tcp option which uses TCP SYN packets instead of ICMP echo requests.

## Build Instructions
Either use containerized build or build on a Linux host.
The traceroute binary is generated in the build directory. "build/traceroute"

### Containerized build
```
./build.sh
```

### On Linux host
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
sudo build/traceroute 1.2.1.9
ICMP traceroute to 1.2.1.9 (1.2.1.9), 30 hops max 
.......................................................................................
  1  10.0.2.2  0.379ms 0.332ms  0.490ms 
  2  192.168.4.1  3.514ms 3.523ms  3.496ms 
  3  96.120.91.105  11.572ms 11.059ms  10.738ms 
  4  24.124.158.129  11.618ms 12.799ms  11.722ms 
  5  162.151.78.249  11.499ms 13.732ms  12.614ms 
  6  68.87.226.109  20.919ms 24.493ms  11.346ms 
  7  0.0.0.0  0.000ms 0.000ms  0.000ms 
  8  0.0.0.0  0.000ms 0.000ms  0.000ms 
  9  0.0.0.0  0.000ms 0.000ms  0.000ms 
 10  0.0.0.0  0.000ms 0.000ms  0.000ms 
 11  0.0.0.0  0.000ms 0.000ms  0.000ms 
 12  0.0.0.0  0.000ms 0.000ms  0.000ms 
 13  0.0.0.0  0.000ms 0.000ms  0.000ms 
 14  0.0.0.0  0.000ms 0.000ms  0.000ms 
 15  0.0.0.0  0.000ms 0.000ms  0.000ms 
 16  0.0.0.0  0.000ms 0.000ms  0.000ms 
 17  0.0.0.0  0.000ms 0.000ms  0.000ms 
 18  0.0.0.0  0.000ms 0.000ms  0.000ms 
 19  0.0.0.0  0.000ms 0.000ms  0.000ms 
 20  0.0.0.0  0.000ms 0.000ms  0.000ms 
 21  0.0.0.0  0.000ms 0.000ms  0.000ms 
 22  0.0.0.0  0.000ms 0.000ms  0.000ms 
 23  0.0.0.0  0.000ms 0.000ms  0.000ms 
 24  0.0.0.0  0.000ms 0.000ms  0.000ms 
 25  0.0.0.0  0.000ms 0.000ms  0.000ms 
 26  0.0.0.0  0.000ms 0.000ms  0.000ms 
 27  0.0.0.0  0.000ms 0.000ms  0.000ms 
 28  0.0.0.0  0.000ms 0.000ms  0.000ms 
 29  0.0.0.0  0.000ms 0.000ms  0.000ms 
```
Only hops which have default gateway will respond..

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
       Further packet tracing, found out that the host doing the NAT on my setup is updating the TTL to 64.

Repeated test from a different host (Raspberry Pi), instead of the Vagrant environment
```
sudo build/traceroute google.com --tcp
SYN traceroute to google.com (172.217.6.78), 30 hops max 
..............................
  1  192.168.10.1  20.674ms 51.671ms  38.899ms 
  2  96.120.91.105  10.962ms 10.487ms  10.929ms 
  3  24.124.158.129  12.242ms 11.020ms  12.937ms 
  4  162.151.78.249  11.241ms 12.071ms  10.830ms 
  5  68.87.226.109  11.379ms 18.322ms  11.106ms 
  6  68.86.143.93  12.230ms 13.723ms  11.690ms 
  7  96.112.146.22  11.797ms 12.516ms  12.658ms 
  8  142.251.70.49  13.856ms 13.307ms  14.436ms 
  9  209.85.248.35  12.375ms 11.907ms  11.295ms 
 10  172.217.6.78  12.570ms 11.537ms  11.226ms 
 ```

2. any IP
```
sudo build/traceroute 1.1.1.1 --tcp
SYN traceroute to 1.1.1.1 (1.1.1.1), 30 hops max 
........................................................................
  1  192.168.10.1  43.101ms 111.083ms  10.974ms 
  2  96.120.91.105  63.870ms 97.687ms  9.564ms 
  3  24.124.158.129  13.274ms 13.499ms  13.979ms 
  4  162.151.78.86  10.616ms 11.103ms  10.858ms 
  5  162.151.79.153  10.614ms 11.582ms  11.499ms 
  6  68.87.193.177  39.553ms 13.435ms  15.516ms 
  7  68.86.93.249  11.259ms 13.117ms  13.600ms 
  8  96.110.32.254  14.524ms 13.466ms  14.288ms 
  9  50.242.151.238  30.752ms 13.930ms  13.703ms 
 10  172.68.188.20  15.695ms 18.746ms  13.729ms 
 11  1.1.1.1  15832.248ms 16831.040ms  16830.681ms
 ```

3. Unreachable IP
```
sudo build/traceroute 1.2.1.1 --tcp
SYN traceroute to 1.2.1.1 (1.2.1.1), 30 hops max 
.......................................................................................
  1  192.168.10.1  7.102ms 2.132ms  2.416ms 
  2  96.120.91.105  12.680ms 13.030ms  14.494ms 
  3  24.124.158.129  12.665ms 12.168ms  11.024ms 
  4  162.151.78.249  11.089ms 10.428ms  12.361ms 
  5  68.87.226.109  11.395ms 13.802ms  12.923ms 
  6  0.0.0.0  0.000ms 0.000ms  0.000ms 
  7  0.0.0.0  0.000ms 0.000ms  0.000ms 
  8  0.0.0.0  0.000ms 0.000ms  0.000ms 
  9  0.0.0.0  0.000ms 0.000ms  0.000ms 
 10  0.0.0.0  0.000ms 0.000ms  0.000ms 
 11  0.0.0.0  0.000ms 0.000ms  0.000ms 
 12  0.0.0.0  0.000ms 0.000ms  0.000ms 
 13  0.0.0.0  0.000ms 0.000ms  0.000ms 
 14  0.0.0.0  0.000ms 0.000ms  0.000ms 
 15  0.0.0.0  0.000ms 0.000ms  0.000ms 
 16  0.0.0.0  0.000ms 0.000ms  0.000ms 
 17  0.0.0.0  0.000ms 0.000ms  0.000ms 
 18  0.0.0.0  0.000ms 0.000ms  0.000ms 
 19  0.0.0.0  0.000ms 0.000ms  0.000ms 
 20  0.0.0.0  0.000ms 0.000ms  0.000ms 
 21  0.0.0.0  0.000ms 0.000ms  0.000ms 
 22  0.0.0.0  0.000ms 0.000ms  0.000ms 
 23  0.0.0.0  0.000ms 0.000ms  0.000ms 
 24  0.0.0.0  0.000ms 0.000ms  0.000ms 
 25  0.0.0.0  0.000ms 0.000ms  0.000ms 
 26  0.0.0.0  0.000ms 0.000ms  0.000ms 
 27  0.0.0.0  0.000ms 0.000ms  0.000ms 
 28  0.0.0.0  0.000ms 0.000ms  0.000ms 
 29  0.0.0.0  0.000ms 0.000ms  0.000ms 
``` 


4. Non open port (ex with port 22)
```
sudo build/traceroute 1.1.1.1 --tcp
SYN traceroute to 1.1.1.1 (1.1.1.1), 30 hops max 
.......................................................................................
  1  192.168.10.1  1.994ms 2.409ms  1.924ms 
  2  96.120.91.105  10.789ms 9.885ms  12.374ms 
  3  24.124.158.129  10.818ms 10.718ms  11.220ms 
  4  162.151.78.86  13.838ms 11.537ms  10.954ms 
  5  162.151.79.153  11.907ms 10.334ms  11.159ms 
  6  68.87.193.177  12.742ms 12.872ms  12.273ms 
  7  68.86.93.253  14.282ms 13.751ms  13.919ms 
  8  96.110.32.246  13.356ms 13.487ms  14.704ms 
  9  0.0.0.0  0.000ms 0.000ms  0.000ms 
 10  0.0.0.0  0.000ms 0.000ms  0.000ms 
 11  0.0.0.0  0.000ms 0.000ms  0.000ms 
 12  0.0.0.0  0.000ms 0.000ms  0.000ms 
 13  0.0.0.0  0.000ms 0.000ms  0.000ms 
 14  0.0.0.0  0.000ms 0.000ms  0.000ms 
 15  0.0.0.0  0.000ms 0.000ms  0.000ms 
 16  0.0.0.0  0.000ms 0.000ms  0.000ms 
 17  0.0.0.0  0.000ms 0.000ms  0.000ms 
 18  0.0.0.0  0.000ms 0.000ms  0.000ms 
 19  0.0.0.0  0.000ms 0.000ms  0.000ms 
 20  0.0.0.0  0.000ms 0.000ms  0.000ms 
 21  0.0.0.0  0.000ms 0.000ms  0.000ms 
 22  0.0.0.0  0.000ms 0.000ms  0.000ms 
 23  0.0.0.0  0.000ms 0.000ms  0.000ms 
 24  0.0.0.0  0.000ms 0.000ms  0.000ms 
 25  0.0.0.0  0.000ms 0.000ms  0.000ms 
 26  0.0.0.0  0.000ms 0.000ms  0.000ms 
 27  0.0.0.0  0.000ms 0.000ms  0.000ms 
 28  0.0.0.0  0.000ms 0.000ms  0.000ms 
 29  0.0.0.0  0.000ms 0.000ms  0.000ms 

```
No response is received from the server if the port is closed.

#### Invalid Parameters
```
sudo build/traceroute 1.2.3.4 --udp
Usage : traceroute <ip address>|<hostname> [--tcp]
```
