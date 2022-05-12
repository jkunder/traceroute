# Traceroute Utility
    Accepts IP address or hostname as input.
    Generates ICMP echo request messages of increasing TTL (three requests per hop) until the destination is reached. You can hardcode a reasonable max TTL.
    Each hop is written as a line of output with the hop IP and RTT of each of the three requests.
        Note: No requirements around live/updating output -- 
        program produces no output until the end of execution.
    User can optionally specify a --tcp option which uses TCP SYN packets instead of ICMP echo requests.

## Build Instructions
### On Linux host
Executable traceroute in build directory
(Min requirements build-essential tools cmake (version 3.10 and above))
``` 
cd build
cmake ..
make 
```  

### Containerize build
```
./build.sh
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
sudo build/traceroute google.com
ICMP traceroute to google.com (142.250.189.174), 30 hops max 
.................................
  1  10.0.2.2  0.628ms 0.567ms  0.797ms 
  2  192.168.4.1  3.843ms 3.338ms  2.730ms 
  3  96.120.91.105  11.882ms 11.580ms  12.436ms 
  4  24.124.158.129  13.020ms 11.586ms  12.131ms 
  5  162.151.78.249  13.502ms 11.078ms  11.466ms 
  6  68.87.226.109  14.494ms 12.061ms  12.141ms 
  7  68.86.143.93  126.963ms 42.189ms  11.709ms 
  8  96.112.146.22  11.923ms 12.146ms  12.005ms 
  9  142.251.70.43  16.607ms 19.500ms  13.506ms 
 10  142.251.66.109  20.726ms 12.457ms  11.703ms 
 11  142.250.189.174  13.901ms 0.000ms  0.000ms 
```

2. any Dest IP
```
sudo build/traceroute 1.1.1.1
ICMP traceroute to 1.1.1.1 (1.1.1.1), 30 hops max 
....................................
  1  10.0.2.2  0.567ms 0.640ms  0.561ms 
  2  192.168.4.1  3.300ms 3.004ms  2.853ms 
  3  96.120.91.105  11.818ms 11.171ms  11.693ms 
  4  24.124.158.129  12.795ms 22.555ms  12.793ms 
  5  162.151.78.86  13.931ms 11.851ms  14.497ms 
  6  162.151.79.153  11.231ms 13.339ms  12.340ms 
  7  68.87.193.177  15.015ms 20.374ms  13.148ms 
  8  68.86.93.253  14.608ms 14.878ms  14.533ms 
  9  96.110.32.254  15.265ms 14.541ms  13.138ms 
 10  50.242.151.238  34.179ms 15.265ms  15.361ms 
 11  172.69.132.2  57.325ms 30.264ms  23.729ms 
 12  1.1.1.1  11.696ms 0.000ms  0.000ms 
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
sudo build/traceroute google.com --tcp
SYN traceroute to google.com (142.250.189.174), 30 hops max 
......
1  10.0.2.2  0.460ms 0.689ms  0.600ms 
2  142.250.189.174  12.744ms 0.000ms  0.000ms 
```
Note : For SYN with TTL=1, the first hop returns with ICMP time exceeded
       but for SYN with TTL= 2, packet is still forwarded to the server, and SYNACK received. (Verified with packet trace)


2. any IP
```
sudo build/traceroute 1.1.1.1 --tcp
SYN traceroute to 1.1.1.1 (1.1.1.1), 30 hops max 
......
  1  10.0.2.2  0.986ms 0.487ms  0.495ms 
  2  1.1.1.1  13.094ms 0.000ms  0.000ms 
  ```

#### Invalid Parameters
```
sudo build/traceroute 1.2.3.4 --udp
Usage : traceroute <ip address>|<hostname> [--tcp]
```
