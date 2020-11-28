from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger()


class FireWall(object):
  def __init__ (self, connection):
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    self.mac_to_port = {}


  def resend_packet (self, packet_in, out_port):
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def act_like_switch (self, packet, packet_in):

    self.mac_to_port[packet.src] = packet_in.in_port

    if packet.type == ethernet.IP_TYPE and packet.next.protocol == ipv4.TCP_PROTOCOL:
      return

    if packet.dst in self.mac_to_port :
      
      log.debug("Installing flow...")
      
      msg = of.ofp_flow_mod()

      msg.match = of.ofp_match.from_packet(packet)
      msg.match.in_port = packet_in.in_port
      msg.data = packet_in

      msg.idle_timeout = 50
      msg.hard_timeout = 1000
      msg.buffer_id = packet_in.buffer_id
      
      action = of.ofp_action_output(port = self.mac_to_port[packet.dst])
      msg.actions.append(action)

      self.connection.send(msg)

    else:
      self.resend_packet(packet_in, of.OFPP_ALL)

  def _handle_PacketIn (self, event):
    packet = event.parsed
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp
    self.act_like_switch(packet, packet_in)



def launch ():
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    FireWall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
