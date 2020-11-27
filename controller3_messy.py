from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.addresses import IPAddr
from pox.lib.addresses import EthAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet, ETHER_ANY
from pox.lib.packet.icmp import *
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger()





'''
    Highlights of this Scenrio:
        1. Handling Arp Protocol in a Multi-host Subnet
            * Subnet Switch Should (additionally) be able to relay Arp Packets 
        2. Cross - Subnet IP Packet Routing
'''
# Defined for Better Organization of the Code
class EtherInfo_t:
    def __init__(self, src, dst, pType):
        self.src = src
        self.dst = dst
        self.pType = pType
class ArpInfo_t:
    def __init__(self, hwsrc, hwdst, protosrc, protodst, op):
        self.hwsrc = hwsrc
        self.hwdst = hwdst
        self.protosrc = protosrc
        self.protodst = protodst
        self.op = op
class IpInfo_t:
    def __init__(self, srcip, dstip, protocol, payload):
        self.srcip = srcip
        self.dstip = dstip
        self.protocol = protocol
        self.payload = payload

# This data structure enables easy use of routing tables
class Switch1Config:
    selfIP = IPAddr('10.0.1.1')
    selfSubnet = IPAddr('10.0.1.0')
    ip_to_port = {IPAddr('10.0.2.1'): 1, IPAddr('10.0.1.2'): 2, IPAddr('10.0.1.3'): 3}
    port_to_ip = {1: IPAddr('10.0.2.1'), 2: IPAddr('10.0.1.2'), 3: IPAddr('10.0.1.3')}
    adjacent_ip = set([IPAddr('10.0.2.1'), IPAddr('10.0.1.2'), IPAddr('10.0.1.3')])

class Switch2Config:
    selfIP = IPAddr('10.0.2.1')
    selfSubnet = IPAddr('10.0.2.0')
    ip_to_port = {IPAddr('10.0.1.1'): 1, IPAddr('10.0.2.2'): 2}
    port_to_ip = {1: IPAddr('10.0.1.1'), 2: IPAddr('10.0.2.2')}
    adjacent_ip = set([IPAddr('10.0.1.1'), IPAddr('10.0.2.2')])




class Controller3 (object):

    def __init__ (self, connection):
        self.connection = connection
        connection.addListeners(self)

        self.table = {
            1: Switch1Config,
            2: Switch2Config
        }
        self.arp_cache = {
            1: {IPAddr('10.0.1.1'): EthAddr('f6:96:df:b6:9c:8f')},
            2: {IPAddr('10.0.2.1'): EthAddr('9a:56:68:d7:bf:e8')}
        }
        self.subNet = {
            IPAddr('10.0.1.0'): set([IPAddr('10.0.1.1'), IPAddr('10.0.1.2'), IPAddr('10.0.1.3')]),
            IPAddr('10.0.2.0'): set([IPAddr('10.0.2.1'), IPAddr('10.0.2.2')])
        }
        
        self.q = {1: {}, 2: {}}

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
    def _arp_handler(self, arpInfo, etherInfo, sPid):
        
        # Arp Packet
        arpPkt = arp()
        arpPkt.hwsrc, arpPkt.hwdst = arpInfo.hwsrc, arpInfo.hwdst
        arpPkt.protosrc, arpPkt.protodst = arpInfo.protosrc, arpInfo.protodst
        arpPkt.opcode = arpInfo.op
        
        # Ethernet Packet
        ethPkt = ethernet(src = etherInfo.src, dst = etherInfo.dst, type = etherInfo.pType)
        ethPkt.payload = arpPkt

        # The Only Situation Where arp.REQUEST is Needed
        FLAG_needFlood = ((arpInfo.op == arp.REQUEST) and (arpInfo.protosrc == self.table[sPid].selfIP))

        log.debug('Ethernet To Send:\n\tSrc %s Dst %s' % (ethPkt.src, ethPkt.dst))
        p = ethPkt.payload
        log.debug('Arp To Send:\n\thwsrc %s hwdst %s\n\tprotosrc %s protodst %s' % (p.hwsrc, p.hwdst, p.protosrc, p.protodst))
        log.debug('OutPort: %s' % (self.table[sPid].ip_to_port[arpInfo.protodst]))

        self.resend_packet(ethPkt, of.OFPP_ALL if FLAG_needFlood else self.table[sPid].ip_to_port[arpInfo.protodst])

        return True

    '''-----------------------------Ip handler on switch-----------------------------'''
    #   *** Address Information Handled by the function caller ***
    #   Responsible for sending Ip Packets (including ICMP)
    #   packet_out is the payload for ipv4
    def _ip_handler(self, ipInfo, etherInfo, out_port):
        # Build ip Packet
        ipv4Pkt = ipv4()
        ipv4Pkt.srcip = ipInfo.srcip
        ipv4Pkt.dstip = ipInfo.dstip
        ipv4Pkt.protocol = ipInfo.protocol
        ipv4Pkt.payload = ipInfo.payload
        # Build Ether Packet
        etherPkt = ethernet(src = etherInfo.src, dst = etherInfo.dst, type = etherInfo.pType)
        etherPkt.payload = ipv4Pkt

        self.resend_packet(etherPkt, out_port)
        return True

    '''-----------------------------Short ICMP Constructor-----------------------------'''
    def _icmp_handler(self, icmpType, icmpCode, payload):
        icmpPkt = icmp()
        icmpPkt.type = icmpType
        icmpPkt.code = icmpCode
        icmpPkt.payload = payload
        return icmpPkt

    '''-----------------------------Get IP of Next Hop Within - Across Subnet-----------------------------'''
    def _next_hop_ip(self, dstip, curSubnet):
        dstSubnet = str(dstip)[:-1] + '0'
        curSubnet = str(curSubnet)[:-1] + '0'
        # log.debug('-----------> Subnet Parse Part %s %s' % (dstSubnet, curSubnet))
        return IPAddr(dstip) if dstSubnet == curSubnet else IPAddr(dstSubnet[:-1] + '1')

    '''-----------------------------Helper Function Installing Flow-----------------------------'''
    def _push_to_switch(self, hwsrc, hwdst, dstip, out_port):

        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()

        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_dst = dstip
        
        msg.idle_timeout = 65535
        msg.hard_timeout = 65535
        
        msg.actions.append(of.ofp_action_dl_addr.set_src(hwsrc))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(hwdst))
        msg.actions.append(of.ofp_action_output(port = out_port))

        self.connection.send(msg)

    '''-----------------------------Main Function-----------------------------'''
    def act_like_switch (self, packet, packet_in, sPid):

        # log.debug('Event from %d' % (sPid))
        log.debug('Ethernet Received:\n\tSrc %s Dst %s' % (packet.src, packet.dst))
        # if packet.find('arp'):
        #     p = packet.find('arp')
        #     log.debug('Arp Received:\n\thwsrc %s hwdst %s\n\tprotosrc %s protodst %s' % (p.hwsrc, p.hwdst, p.protosrc, p.protodst))
        # if packet.find('ipv4'):
        #     p = packet.find('ipv4')
        #     log.debug('Ip ReceivedL: scrip %s dstip %s' % (p.srcip, p.dstip))
        
        # Some Global Variables
        etherSx = self.arp_cache[sPid][self.table[sPid].selfIP]
        in_port = packet_in.in_port


        if packet.find('arp'):
            if packet.find('arp'):
                p = packet.find('arp')
                log.debug('Arp Received:\n\thwsrc %s hwdst %s\n\tprotosrc %s protodst %s' % (p.hwsrc, p.hwdst, p.protosrc, p.protodst))
            # Get Arp Packet & Update arp cache
            arpPkt = packet.find('arp')
            self.arp_cache[sPid][IPAddr(arpPkt.protosrc)] = EthAddr(arpPkt.hwsrc)
            '''
                Boolean Variables for Determining Operations
                    1. If the Arp Packet is intended for Current Switch
                    2. If the Arp Packet is intended for Adjacent Node of the Currennt Switch
                        This Variable is mask current switch from answering Arp Request
                        In this scenrio, it's used to stop reverse propagation of Arp Request
            '''
            FLAG_FOR_Sx = (arpPkt.protodst == self.table[sPid].selfIP)
            FLAG_ArpCheckValve = (arpPkt.protodst in self.table[sPid].adjacent_ip) or FLAG_FOR_Sx
            destinationIP = self._next_hop_ip(IPAddr(arpPkt.protosrc), self.table[sPid].selfIP)
            # Switch Meets Arp Request
            if arpPkt.opcode == arp.REQUEST and FLAG_ArpCheckValve:
                log.debug('-----------> arp.REQUEST section of %s' % (sPid))
                self._arp_handler(
                    arpInfo = ArpInfo_t(
                        hwsrc = etherSx if FLAG_FOR_Sx else arpPkt.hwsrc,
                        hwdst =  arpPkt.hwsrc if FLAG_FOR_Sx else arpPkt.hwdst,
                        protosrc = arpPkt.protodst if FLAG_FOR_Sx else arpPkt.protosrc,
                        protodst = arpPkt.protosrc if FLAG_FOR_Sx else arpPkt.protodst,
                        op = arp.REPLY if FLAG_FOR_Sx else arp.REQUEST
                    ),
                    etherInfo = EtherInfo_t(
                        src = etherSx,
                        dst = packet.src if FLAG_FOR_Sx else EthAddr('ff:ff:ff:ff:ff:ff'),
                        pType = ethernet.ARP_TYPE
                    ),
                    sPid = sPid
                )
            # Switch Meets Arp Reply
            elif arpPkt.opcode == arp.REPLY:
                log.debug('-----------> arp.REPLY section of %s' % (sPid))
                # The Corresponding Arp Request is from Switch
                if FLAG_FOR_Sx:
                    numPktToSend = len(self.q[sPid].get(destinationIP, []))
                    for _ in range(numPktToSend):
                        ipv4Pkt = self.q[sPid][destinationIP].pop()
                        # Resend Pkt
                        self._ip_handler(
                            ipInfo = IpInfo_t(
                                srcip = ipv4Pkt.srcip,
                                dstip = ipv4Pkt.dstip,
                                protocol = ipv4Pkt.protocol,
                                payload = ipv4Pkt.payload
                            ),
                            etherInfo = EtherInfo_t(
                                src = etherSx,
                                dst = self.arp_cache[sPid][destinationIP],
                                pType = ethernet.IP_TYPE
                            ),
                            out_port = self.table[sPid].ip_to_port[destinationIP]
                        )
                # Else Relay the Arp Reply
                else:
                    log.debug('Relaying Arp Reply')
                    self._arp_handler(
                        arpInfo = ArpInfo_t(
                            hwsrc = arpPkt.hwsrc,
                            hwdst = arpPkt.hwdst,
                            protosrc = arpPkt.protosrc,
                            protodst = arpPkt.protodst,
                            op = arp.REPLY
                        ),
                        etherInfo = EtherInfo_t(
                            src = etherSx,
                            dst = arpPkt.hwdst,
                            pType = ethernet.ARP_TYPE
                        ),
                        sPid = sPid
                    )
            else:
                log.warning('Unknown Opcode for ARP Packet')
            
            # Push To Switch
            print 'Rules Installed'

            if str(arpPkt.protosrc)[:-1] != str(arpPkt.protodst)[:-1]:
                for hostsInSubnet in self.subNet[IPAddr(str(arpPkt.protosrc)[:-1] + '0')]:
                    self._push_to_switch(hwsrc = etherSx, hwdst = packet.src, dstip = hostsInSubnet, out_port = in_port)
                    print 'For DstIP %s, New HW src %s dst %s, Out port %s' % (hostsInSubnet, etherSx, packet.src, in_port)
            else:
                self._push_to_switch(hwsrc = etherSx, hwdst = packet.src, dstip = arpPkt.protosrc, out_port = in_port)
                print 'For DstIP %s, New HW src %s dst %s, Out port %s' % (arpPkt.protosrc, etherSx, packet.src, in_port)
            
            
            
        elif packet.find('icmp'):
            ipv4Pkt = packet.find('ipv4')
            icmpPkt = packet.find('icmp')
            destinationIP = self._next_hop_ip(IPAddr(ipv4Pkt.srcip), self.table[sPid].selfIP)
            sourceIP = self._next_hop_ip(IPAddr(ipv4Pkt.dstip), self.table[sPid].selfIP)
            # If the Host is Pinging the current switch, Direct Respond
            if IPAddr(ipv4Pkt.dstip) == self.table[sPid].selfIP:
                self._ip_handler(
                    ipInfo = IpInfo_t(
                        srcip = ipv4Pkt.dstip,
                        dstip = ipv4Pkt.srcip,
                        protocol = ipv4.ICMP_PROTOCOL,
                        payload = self._icmp_handler(
                            icmpType = TYPE_ECHO_REPLY,
                            icmpCode = CODE_UNREACH_NET,
                            payload = icmpPkt.payload
                        )
                    ),
                    etherInfo = EtherInfo_t(
                        src = etherSx,
                        dst = self.arp_cache[sPid][destinationIP],
                        pType = ethernet.IP_TYPE
                    ),
                    out_port = self.table[sPid].ip_to_port[destinationIP]
                )

            # If the Host is Pinging another Host / Switch, Relay the Packet
            elif sourceIP in self.table[sPid].adjacent_ip:

                # If Destination ARP already cached, Just Forward (No Matter Request or Reply)
                if sourceIP in self.arp_cache:
                    self._ip_handler(
                        ipInfo = IpInfo_t(
                            srcip = ipv4Pkt.srcip,
                            dstip = ipv4Pkt.dstip,
                            protocol = ipv4.ICMP_PROTOCOL,
                            payload = self._icmp_handler(
                                icmpType = icmpPkt.type,
                                icmpCode = icmpPkt.code,
                                payload = icmpPkt.payload
                            )
                        ),
                        etherInfo = EtherInfo_t(
                            src = etherSx,
                            dst = self.arp_cache[sPid][sourceIP],
                            pType = ethernet.IP_TYPE
                        ),
                        out_port = self.table[sPid].ip_to_port[sourceIP]
                    )
                
                # If Destination ARP not done
                else:
                    if sourceIP not in self.q[sPid]:
                        self.q[sPid][sourceIP] = []
                    self.q[sPid][sourceIP].append(ipv4Pkt)
                    self._arp_handler(
                        arpInfo = ArpInfo_t(
                            hwsrc = etherSx,
                            hwdst = EthAddr('ff:ff:ff:ff:ff:ff'),
                            protosrc = self.table[sPid].selfIP,
                            protodst = sourceIP,
                            op = arp.REQUEST
                        ),
                        etherInfo = EtherInfo_t(
                            src = packet.dst,
                            dst = EthAddr('ff:ff:ff:ff:ff:ff'),
                            pType = ethernet.ARP_TYPE
                        ),
                        sPid = sPid
                    )
            # Unreachable Host, Reply Back
            else:
                self._ip_handler(
                    ipInfo = IpInfo_t(
                        srcip = self.table[sPid].selfIP,
                        dstip = ipv4Pkt.srcip,
                        protocol = ipv4.ICMP_PROTOCOL,
                        payload = self._icmp_handler(
                            icmpType = TYPE_DEST_UNREACH,
                            icmpCode = CODE_UNREACH_HOST,
                            payload = icmpPkt.payload
                        )
                    ),
                    etherInfo = EtherInfo_t(
                        src = etherSx,
                        dst = self.arp_cache[sPid][destinationIP],
                        pType = ethernet.IP_TYPE
                    ),
                    out_port = self.table[sPid].ip_to_port[destinationIP]
                )

        elif packet.find('ipv4'):
            ipv4Pkt = packet.find('ipv4')
            destinationIP = self._next_hop_ip(IPAddr(ipv4Pkt.dstip), self.table[sPid].selfIP)
            # log.debug('IP: %s %s %s' % (ipv4Pkt.srcip, ipv4Pkt.dstip, destinationIP))
            # Case Handling
            if destinationIP in self.arp_cache[sPid]:
                log.debug('-----------> ipv4.ArpSeen section of %s' % (sPid))
                self._ip_handler(
                    ipInfo = IpInfo_t(
                        srcip = ipv4Pkt.srcip,
                        dstip = ipv4Pkt.dstip,
                        protocol = ipv4Pkt.protocol,
                        payload = ipv4Pkt.payload
                    ),
                    etherInfo = EtherInfo_t(
                        src = etherSx,
                        dst = self.arp_cache[sPid][destinationIP],
                        pType = ethernet.IP_TYPE
                    ),
                    out_port = self.table[sPid].ip_to_port[destinationIP]
                )
            else:
                log.debug('-----------> ipv4.ArpQuery section of %s' % (sPid))
                # Buffer the Message
                if IPAddr(ipv4Pkt.dstip) not in self.q[sPid]:
                    self.q[sPid][destinationIP] = []
                self.q[sPid][destinationIP].append(ipv4Pkt)
                # Send Arp Request
                self._arp_handler(
                    arpInfo = ArpInfo_t(
                        hwsrc = packet.dst,
                        hwdst = EthAddr('ff:ff:ff:ff:ff:ff'),
                        protosrc = self.table[sPid].selfIP,
                        protodst = destinationIP,
                        op = arp.REQUEST
                    ),
                    etherInfo = EtherInfo_t(
                        src = packet.dst,
                        dst = EthAddr('ff:ff:ff:ff:ff:ff'),
                        pType = ethernet.ARP_TYPE
                    ),
                    sPid = sPid
                )

        else:
            log.warning('Unknown Packet Type Received')

        log.debug('\n')

    '''
        Handles packet in messages from the switch.
    '''
    def _handle_PacketIn (self, event):

        packet = event.parsed # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp # The actual ofp_packet_in message.
        sPid = event.connection.dpid

        self.act_like_switch(packet, packet_in, sPid)


'''
  Starts the component
'''
def launch ():

  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Controller3(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)