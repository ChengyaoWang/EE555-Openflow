"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo(Topo):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        host3 = self.addHost('h3', ip = '10.0.1.2/24', defaultRoute = 'via 10.0.1.1')
        host4 = self.addHost('h4', ip = '10.0.1.3/24', defaultRoute = 'via 10.0.1.1')
        host5 = self.addHost('h5', ip = '10.0.2.2/24', defaultRoute = 'via 10.0.2.1')

        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')

        # Add links
        self.addLink(host3, switch1, port1 = 1, port2 = 2)
        self.addLink(host4, switch1, port1 = 1, port2 = 3)
        self.addLink(host5, switch2, port1 = 1, port2 = 2)
        self.addLink(switch1, switch2, port1 = 1, port2 = 1)


topos = { 'mytopo': ( lambda: MyTopo() ) }
