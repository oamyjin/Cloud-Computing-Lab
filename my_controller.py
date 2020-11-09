from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        data_path = ev.msg.datapath
        ofproto = data_path.ofproto
        parser = data_path.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(data_path, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        msg = ev.msg
        data_path = msg.datapath
        ofproto = data_path.ofproto
        parser = data_path.ofproto_parser
        in_port = msg.match['in_port']

        # create a packet
        pkt = packet.Packet(msg.data)

        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        # ARP
        # get APR packet from switch_# and reply a pkt with dst_ip
        if arp_pkt:
            # replace dst_mac_addr(ff:ff:ff:ff:ff:ff) by getting the real dst_mac_addr from dst_ip_addr
            dst_mac_addr = "10:00:00:00:00:0" + str(arp_pkt.dst_ip[-1])
            # create a response packet
            new_pkt = packet.Packet()
            # add ethernet info
            new_pkt.add_protocol(ethernet.ethernet(ethertype=eth_pkt.ethertype,
                                                   src=dst_mac_addr, dst=eth_pkt.src
                                                   ))
            # add arp REPLY info
            new_pkt.add_protocol(arp.arp(src_mac=dst_mac_addr, dst_mac=arp_pkt.src_mac,
                                         src_ip=arp_pkt.dst_ip, dst_ip=arp_pkt.src_ip,
                                         opcode=arp.ARP_REPLY
                                         ))
            # reply to the sender switch
            self._send_packet(data_path, in_port, new_pkt)

        # IP
        elif ipv4_pkt:
            # ICMP
            if icmp_pkt:
                # get the out put port from current switch to the destination according to specific protocol
                out_port = self.get_out_port(eth_pkt.dst[-1], data_path.id, 'ICMP')
                # add flow to the switch
                match = parser.OFPMatch(eth_src=eth_pkt.src, eth_dst=eth_pkt.dst, eth_type=0x0800,
                                        ip_proto=ipv4_pkt.proto, in_port=in_port)
                actions = [parser.OFPActionOutput(port=out_port)]
                self.add_flow(data_path, 1, match, actions)
                # send packet out
                self._send_packet(data_path, out_port, pkt)
            # TCP
            elif tcp_pkt:
                # HTTP RST: H2 and H4 cannot send HTTP traffic (TCP with dst_port:80)
                if tcp_pkt.dst_port == 80 and (int(ipv4_pkt.src[-1]) == 2 or int(ipv4_pkt.src[-1]) == 4):
                    # generate an HTTP RST packet and send it
                    new_pkt = packet.Packet()
                    new_pkt.add_protocol(ethernet.ethernet(ethertype=eth_pkt.ethertype,
                                                           src=eth_pkt.dst, dst=eth_pkt.src
                                                           ))
                    new_pkt.add_protocol(ipv4.ipv4(src=ipv4_pkt.dst, dst=ipv4_pkt.src, proto=6))
                    new_pkt.add_protocol(tcp.tcp(src_port=tcp_pkt.dst_port, dst_port=tcp_pkt.src_port,
                                                 ack=tcp_pkt.seq + 1, bits=0b010100))
                    self._send_packet(data_path, in_port, new_pkt)
                # No RST: HTTP is allowed from h1 or h3
                else:
                    # get the out port
                    out_port = self.get_out_port(ipv4_pkt.dst[-1], data_path.id, 'TCP')
                    # add flow
                    match = parser.OFPMatch(eth_src=eth_pkt.src, eth_dst=eth_pkt.dst, eth_type=0x0800,
                                            ip_proto=ipv4_pkt.proto, in_port=in_port)
                    actions = [parser.OFPActionOutput(port=out_port)]
                    self.add_flow(data_path, 1, match, actions)
                    # send packet
                    self._send_packet(data_path, out_port, pkt)
                    # add http flow to h2 or h4
                    if ipv4_pkt.src[-1] == 2 or ipv4_pkt.src[-1] == 4:
                        # match: http from h2 or h4, action: ask the controller for help
                        match = parser.OFPMatch(eth_src=eth_pkt.src, eth_type=0x0800,
                                                ip_proto=ipv4_pkt.proto, tcp_dst=80, in_port=in_port)
                        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
                        self.add_flow(data_path, 2, match, actions)
            # UDP
            elif udp_pkt:
                # H1 and H4 cannot send UDP traffic
                if int(ipv4_pkt.src[-1]) == 1 or int(ipv4_pkt.src[-1]) == 4:
                    # add flow: simply drop packets at switches
                    match = parser.OFPMatch(eth_src=eth_pkt.src, eth_type=0x0800,
                                            ip_proto=ipv4_pkt.proto, in_port=in_port)
                    actions = []
                    self.add_flow(data_path, 1, match, actions)
                else:
                    # get the out port
                    out_port = self.get_out_port(ipv4_pkt.dst[-1], data_path.id, 'UDP')
                    # add flow
                    match = parser.OFPMatch(eth_src=eth_pkt.src, eth_dst=eth_pkt.dst, eth_type=0x0800,
                                            ip_proto=ipv4_pkt.proto, in_port=in_port)
                    actions = [parser.OFPActionOutput(port=out_port)]
                    self.add_flow(data_path, 1, match, actions)
                    # send packet
                    self._send_packet(data_path, out_port, pkt)

    '''
        Calculate the out port according to specific protocol 
    '''

    def get_out_port(self, dst, sw, proto):
        # port_rule[i-1][j-1]: port from i -> j
        tcp_icmp_port_rule = [[1, 2, 2, 3], [2, 1, 2, 2], [2, 3, 1, 2], [2, 2, 3, 1]]
        udp_port_rule = [[1, 2, 3, 3], [3, 1, 2, 3], [3, 3, 1, 2], [2, 3, 3, 1]]

        # if it arrive the switch which is directly connected to the destination host, it should go to port 1
        if dst == sw:
            return 1

        # set the out port according to protocol
        if proto == 'ICMP' or proto == 'TCP':
            port = tcp_icmp_port_rule[int(sw) - 1][int(dst) - 1]
        else:
            port = udp_port_rule[int(sw) - 1][int(dst) - 1]

        return port

    '''
       Add a flow entry to the switch's flow table
    '''

    def add_flow(self, data_path, priority, match, actions):
        ofproto = data_path.ofproto
        parser = data_path.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=data_path, priority=priority,
                                match=match, instructions=inst)
        data_path.send_msg(mod)

    '''
        Sent the packet out 
    '''

    def _send_packet(self, data_path, port, pkt):
        ofproto = data_path.ofproto
        parser = data_path.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=data_path,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        data_path.send_msg(out)
