# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.addresses import IPAddr
from pox.lib.addresses import EthAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.icmp import *
from pox.lib.packet.ipv4 import ipv4


log = core.getLogger()

# This data structure enables easy use of routing tables
class SwitchConfig:
  ip_to_port = {
    IPAddr('10.0.1.1'): 1, IPAddr('10.0.2.1'): 2, IPAddr('10.0.3.1'): 3,
    IPAddr('10.0.1.100'): 1, IPAddr('10.0.2.100'): 2, IPAddr('10.0.3.100'): 3
  }
  port_to_host = {1: IPAddr('10.0.1.100'), 2: IPAddr('10.0.2.100'), 3: IPAddr('10.0.3.100')}
  port_to_interface = {1: IPAddr('10.0.1.1'), 2: IPAddr('10.0.2.1'), 3: IPAddr('10.0.3.1')}
  host_tofrom_interface = {
    IPAddr('10.0.1.1'): IPAddr('10.0.1.100'), IPAddr('10.0.2.1'): IPAddr('10.0.2.100'),
    IPAddr('10.0.3.1'): IPAddr('10.0.3.100'), IPAddr('10.0.1.100'): IPAddr('10.0.1.1'),
    IPAddr('10.0.2.100'): IPAddr('10.0.2.1'), IPAddr('10.0.3.100'): IPAddr('10.0.3.1')
  }
  interface_set = set([IPAddr('10.0.1.1'), IPAddr('10.0.2.1'), IPAddr('10.0.3.1')])
  host_set = set([IPAddr('10.0.1.100'), IPAddr('10.0.2.100'), IPAddr('10.0.3.100')])


'''
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
'''
class Controller2 (object):

  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    self.table = SwitchConfig
    self.arp_cache = {
      IPAddr('10.0.1.1'): EthAddr('f6:96:df:b6:9c:8f'),
      IPAddr('10.0.2.1'): EthAddr('9a:56:68:d7:bf:e8'),
      IPAddr('10.0.3.1'): EthAddr('f2:ca:23:bc:b3:71'),
    }
    self.q = {}


  def resend_packet (self, packet_in, out_port):

    msg = of.ofp_packet_out()
    msg.data = packet_in

    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    self.connection.send(msg)


  def act_like_hub (self, packet, packet_in):

    self.resend_packet(packet_in, of.OFPP_ALL)


  '''-----------------------------Arp handler on switch-----------------------------'''
  #   *** Address Information Handled by the function caller ***
  #   op = arp.REQUEST -> switch query other hosts' MAC address for routing
  #   op = arp.REPLY -> switch reply to other hosts' Arp Request
  def _arp_handler(self, hwsrc, hwdst, protosrc, protodst, op = arp.REQUEST):
    log.debug('ARP: %s %s %s %s %s' % (hwsrc, hwdst, protosrc, protodst, of.OFPP_ALL if op == arp.REQUEST else self.table.ip_to_port[protodst]))
    
    arpPkt = arp()
    arpPkt.hwtype = arp.HW_TYPE_ETHERNET
    arpPkt.prototype = arp.PROTO_TYPE_IP
    arpPkt.hwsrc = hwsrc
    arpPkt.hwdst = hwdst
    arpPkt.opcode = op
    arpPkt.protosrc = protosrc
    arpPkt.protodst = protodst

    ethPkt = ethernet(src = hwsrc, dst = hwdst, type = ethernet.ARP_TYPE)
    ethPkt.payload = arpPkt

    # if op == arp.REPLY:
    self._push_to_switch(
      packet = ethPkt,
      dstip = protodst,
      out_port = self.table.ip_to_port[protodst]
    )
    # else:
    self.resend_packet(ethPkt, of.OFPP_ALL if op == arp.REQUEST else self.table.ip_to_port[protodst])

    return True

  '''-----------------------------Ip handler on switch-----------------------------'''
  #   *** Address Information Handled by the function caller ***
  #   Responsible for sending Ip Packets (including ICMP)
  #   packet_out is the payload for ipv4
  def _ip_handler(self, hwsrc, hwdst, srcip, dstip, packet_out = None, protocol = ipv4.TCP_PROTOCOL):
    log.debug('IP: %s %s %s %s %s' % (hwsrc, hwdst, srcip, dstip, self.table.ip_to_port[dstip]))
    # Build ip Packet
    ipv4Pkt = ipv4()
    ipv4Pkt.srcip = srcip
    ipv4Pkt.dstip = dstip
    ipv4Pkt.ttl = 64
    ipv4Pkt.payload = packet_out
    ipv4Pkt.protocol = protocol
    # Build Ether Packet
    etherPkt = ethernet(src = hwsrc, dst = hwdst, type = ethernet.IP_TYPE)
    etherPkt.payload = ipv4Pkt

    self.resend_packet(etherPkt, self.table.ip_to_port[dstip])
    return True

  '''-----------------------------Short ICMP Constructor-----------------------------'''
  def _icmp_handler(self, icmpType, icmpCode, payload):
    icmpPkt = icmp()
    icmpPkt.type = icmpType
    icmpPkt.code = icmpCode
    icmpPkt.payload = payload
    return icmpPkt

  '''-----------------------------Helper Function Installing Flow-----------------------------'''
  def _push_to_switch(self, packet, dstip, out_port):

      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match()

      msg.match.dl_type = ethernet.IP_TYPE
      msg.match.nw_dst = dstip
      
      msg.idle_timeout = 50
      msg.hard_timeout = 1000
      
      msg.actions.append(of.ofp_action_dl_addr.set_src(packet.src))
      msg.actions.append(of.ofp_action_dl_addr.set_dst(packet.dst))
      msg.actions.append(of.ofp_action_output(port = out_port))

      self.connection.send(msg)


  '''-----------------------------Main Function-----------------------------'''
  def act_like_switch (self, packet, packet_in):
    
    # hx is making arp query to switch
    if packet.find('arp'):
      arpPkt = packet.find('arp')
      # Switch is Responding to hosts' Arp request
      if arpPkt.opcode == arp.REQUEST:
        self.arp_cache[IPAddr(arpPkt.protosrc)] = EthAddr(arpPkt.hwsrc)
        log.debug('-----------> arp.REQUEST section')
        self._arp_handler(
          hwsrc = self.arp_cache[IPAddr(arpPkt.protodst)],
          hwdst = EthAddr(arpPkt.hwsrc),
          protosrc = IPAddr(arpPkt.protodst),
          protodst = IPAddr(arpPkt.protosrc),
          op = arp.REPLY
        )
      # If switch is sending arp.REPLY, it's in the middle of routing & queue is not empty
      elif arpPkt.opcode == arp.REPLY:
        log.debug('-----------> arp.REPLY section')
        # Update arp cache
        self.arp_cache[IPAddr(arpPkt.protosrc)] = EthAddr(arpPkt.hwsrc)
        packet_out, protocol, srcip = self.q[IPAddr(arpPkt.protosrc)]
        # Resend Pkt
        self._ip_handler(
          hwsrc = EthAddr(arpPkt.hwdst),
          hwdst = EthAddr(arpPkt.hwsrc),
          srcip = IPAddr(srcip),
          dstip = IPAddr(arpPkt.protosrc),
          packet_out = packet_out,
          protocol = protocol
        )
      else:
        log.warning('Unknown Opcode for ARP Packet')
    
    elif packet.find('icmp'):
      ipv4Pkt = packet.find('ipv4')
      icmpPkt = packet.find('icmp')
      # If the Host is Pinging the Switch
      if IPAddr(ipv4Pkt.dstip) in self.table.interface_set:
        self._ip_handler(
          hwsrc = EthAddr(packet.dst),
          hwdst = EthAddr(packet.src),
          srcip = IPAddr(ipv4Pkt.dstip),
          dstip = IPAddr(ipv4Pkt.srcip),
          packet_out = self._icmp_handler(
            icmpType = TYPE_ECHO_REPLY,
            icmpCode = CODE_UNREACH_NET,
            payload = icmpPkt.payload
          ),
          protocol = ipv4.ICMP_PROTOCOL
        )

      # If the Host is Pinging another Host
      elif IPAddr(ipv4Pkt.dstip) in self.table.host_set:
        interfaceIP = self.table.host_tofrom_interface[IPAddr(ipv4Pkt.dstip)]
        # If Destination ARP already cached, Just Forward (No Matter Request or Reply)
        if IPAddr(ipv4Pkt.dstip) in self.arp_cache:
          self._ip_handler(
            hwsrc = self.arp_cache[interfaceIP],
            hwdst = self.arp_cache[IPAddr(ipv4Pkt.dstip)],
            srcip = IPAddr(ipv4Pkt.srcip),
            dstip = IPAddr(ipv4Pkt.dstip),
            packet_out = self._icmp_handler(
              icmpType = icmpPkt.type,
              icmpCode = icmpPkt.code,
              payload = icmpPkt.payload
            ),
            protocol = ipv4.ICMP_PROTOCOL
          )
        # If Destination ARP not done
        else:
          self.q[IPAddr(ipv4Pkt.dstip)] = (ipv4Pkt.payload, ipv4Pkt.protocol, ipv4Pkt.srcip) 
          interfaceIP = self.table.host_tofrom_interface[IPAddr(ipv4Pkt.dstip)]
          self._arp_handler(
            hwsrc = self.arp_cache[interfaceIP],
            hwdst = EthAddr('ff:ff:ff:ff:ff:ff'),
            protosrc = interfaceIP,
            protodst = IPAddr(ipv4Pkt.dstip),
            op = arp.REQUEST
          )
      # Unreachable Host
      else:
        interfaceIP = self.table.host_tofrom_interface[IPAddr(ipv4Pkt.srcip)]
        self._ip_handler(
          hwsrc = EthAddr(packet.dst),
          hwdst = EthAddr(packet.src),
          srcip = interfaceIP,
          dstip = IPAddr(ipv4Pkt.srcip),
          packet_out = self._icmp_handler(
            icmpType = TYPE_DEST_UNREACH,
            icmpCode = CODE_UNREACH_HOST,
            payload = icmpPkt.payload
          ),
          protocol = ipv4.ICMP_PROTOCOL
        )




      

    elif packet.find('ipv4'):

      ipv4Pkt = packet.find('ipv4')

      if IPAddr(ipv4Pkt.dstip) in self.arp_cache:
        log.debug('-----------> ipv4.ArpSeen section')
        # Destination IP -> Interface IP
        interfaceIP = self.table.host_tofrom_interface[IPAddr(ipv4Pkt.dstip)]
        self._ip_handler(
          hwsrc = self.arp_cache[interfaceIP],
          hwdst = self.arp_cache[IPAddr(ipv4Pkt.dstip)],
          srcip = IPAddr(ipv4Pkt.srcip),
          dstip = IPAddr(ipv4Pkt.dstip),
          packet_out = ipv4Pkt.payload,
          protocol = ipv4Pkt.protocol
        )
      else:
        log.debug('-----------> ipv4.ArpQuery section')
        # Buffer the Message
        self.q[IPAddr(ipv4Pkt.dstip)] = (ipv4Pkt.payload, ipv4Pkt.protocol, ipv4Pkt.srcip) 
        # Destination IP -> Interface IP
        interfaceIP = self.table.host_tofrom_interface[IPAddr(ipv4Pkt.dstip)]
        self._arp_handler(
          hwsrc = self.arp_cache[interfaceIP],
          hwdst = EthAddr('ff:ff:ff:ff:ff:ff'),
          protosrc = interfaceIP,
          protodst = IPAddr(ipv4Pkt.dstip),
          op = arp.REQUEST
        )

    else:
      log.warning('Unknown Packet Type Received')



  '''
    Handles packet in messages from the switch.
  '''
  def _handle_PacketIn (self, event):

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    self.act_like_switch(packet, packet_in)


'''
  Starts the component
'''
def launch ():

  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Controller2(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
