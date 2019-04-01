
# Bitcoin Erebus - Bitcoin emulator - Data

## Description

The Bitcoin emulator requires several data to run. We include here the sample files:

* The addr messages dataset: this file include all the IPs to be received the Bitcoin emulator. Each line includes a timestamp, the IP of the peer relaying the IP, the IP itself, whether the IP is a shadow IP and whether the IP is being received via an outbound connection.
	````
	cat addr-msg.txt
	1542584783 192.95.29.22 18.203.200.221 0 1 
	...
	````

* The DNS seed dataset: this file simply include a list of IPs that are relayed by DNS seeds when the node starts.
	````
	cat dns-seed.txt
	136.144.149.53
	...
	````

* The reachability dataset: each file represents the life cycles of an IP. Each cycle is presented by a starting timestamp and an ending timestamp. The IP is reachable within a life cycle.
	````
	cat ./ip-life-cycle/80.136.61.212.txt
	80.136.61.212 1548187649-1548213683 ts_start-ts_end ...
	````