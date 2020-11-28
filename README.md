# EE555-Openflow
  
  Topic: Openflow Based SDN Controller Design using Pox Library
  
  Protocols Concerned: Arp, ICMP, Ethernet, IPv4

## Commands to Run Scenario 1 ~ 4.5
  - Please start **Pox** before **Mininet** to make sure controllers are discoverable
  - Scenario 1: **Flow Installation Tutorial**
    - Start Mininet: *sudo mn --topo single,3 --mac --switch ovsk --controller remote*
    - Start Pox: *./pox/pox.py log.level --DEBUG misc.of_tutorial*
  - Scenario 2: **Arp & ICMP Handling In Single-Host Subnets & Single Switch**
    - Start Mininet: *sudo mn --custom topology2.py --topo mytopo --mac --controller remote*
    - Start Pox: *./pox/pox.py log.level --DEBUG misc.controller2 misc.full_payload*
  - Scenario 3: **Multi-Host Subnets & Multiple Switch**
    - Start Mininet: *sudo mn --custom topology3.py --topo mytopo --mac --controller remote*
    - Start Pox: *./pox/pox.py log.level --DEBUG misc.controller3 misc.full_payload*
  - Scenario 4: **Looped Connection Between Switches**
    - Start Mininet: *sudo mn --custom topology4.py --topo mytopo --mac --controller remotee*
    - Start Pox: *./pox/pox.py log.level --DEBUG misc.controller4 misc.full_payload*
  - Scenario 4.5: **Firewalling TCP Packets**
    - Start Mininet: *sudo mn --topo single,3 --mac --switch ovsk --controller remote*
    - Start Pox: *./pox/pox.py log.level --DEBUG misc.firewall misc.full_payload*

## Comments:
  - Scenario 2 & 3 provides *\*_messy.py* & *\*_neat.py* of the controller.
    - They both work, however ICMP & TCP/UDP situations in *\*_neat.py* are jointly handled
    - *\*_messy.py* is served for convenience during development 
  - Majority part of Scenario 4 is identical to that of Scenario 3's
    - Only routing tables are changed
  - Arp Request Forwarding is done in iterative manner
  - Expected TCP bandwidth using ***iperf hi hj***: 40+ Gbits/s

### Reference & Special Thanks Gives to ***zjx727***:

#### [zjx727/openflow](https://github.com/zjx727/openflow)
