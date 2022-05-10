# Traceroute Utility
    Accepts IP address or hostname as input.
    Generates ICMP echo request messages of increasing TTL (three requests per hop) until the destination is reached. You can hardcode a reasonable max TTL.
    Each hop is written as a line of output with the hop IP and RTT of each of the three requests.
        Note: No requirements around live/updating output -- it's ok if the program produces no output until the end of execution.
    User can optionally specify a --tcp option which uses TCP SYN packets instead of ICMP echo requests.

### Build Instructions
``` cmake ```  
``` make ```  

### Run Instructions
./traceroute <IP|domain> [--tcp]