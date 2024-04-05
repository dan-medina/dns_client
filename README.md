**DNS Client**
DNS client implemented from scratch. 
Effectively performs a forward DNS lookup that resolves the IP address for specified domain name.
Constructs DNS request packets from scratch and utilizes python socket API to send/receive UDP packets.
After IP address is resolved, attempts to send an HTTP GET request to web server.
RTT is measured for all DNS servers.
