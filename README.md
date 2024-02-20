# Network Reconnaissance

<p>Uses the Python Scapy library to monitor ARP traffic and find active hosts on a network. Passive mode continuously monitors ARP packets from each host. Active mode performs a ping scan and reports addresses that send an ICMP reply.</p>

### Usage

`./net_recon.py -i <interface> [-a or -p]`

The correct usage will be printed if the arguments are incorrect.  

**Network interface**

`-i <interface>` or `--iface <interface>`

**Passive Mode**

`-p` or `--passive`

Launch in passive mode to monitor ARP traffic for identifying MAC-IP address pairings. Results are printed out in real time and include the number of hosts and the total packets from each. Halt operation with ctrl-c. 

**Active Mode**

`-a` or `--active` 

Launch in active mode to perform a ping sweep for every address in the network and list replies.  Assumes a /24 network.

### Example output

<img width="800" alt="Screenshot 2024-02-19 at 10 01 34 PM" src="https://github.com/quantumscript/net_recon/assets/60626826/d2e21fa0-9e86-41c9-b16d-9a786bc207da">

