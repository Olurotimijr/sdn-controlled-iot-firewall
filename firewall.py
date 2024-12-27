import os
import ipaddress
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp


class SimpleFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleFirewall, self).__init__(*args, **kwargs)

        # File for dynamically managing trusted MAC addresses
        self.trusted_macs_file = "trusted_macs.txt"
        self.TRUSTED_MACS = self.load_trusted_macs()

        # Subnets to block
        self.blocked_subnets = ["192.168.1.0/24", "10.0.0.0/8"]

    # Load Trusted MAC Addresses
    def load_trusted_macs(self):
        """
        Load the trusted MAC addresses from a file.
        """
        if not os.path.exists(self.trusted_macs_file):
            self.logger.warning(f"Trusted MACs file not found: {self.trusted_macs_file}")
            return []
        with open(self.trusted_macs_file, "r") as file:
            return [line.strip() for line in file.readlines()]

    def refresh_trusted_macs(self):
        """
        Refresh the trusted MAC addresses dynamically.
        """
        self.TRUSTED_MACS = self.load_trusted_macs()
        self.logger.info(f"Trusted MACs updated: {self.TRUSTED_MACS}")

    # Check if IP is Blocked
    def is_ip_blocked(self, src_ip):
        """
        Check if a given IP address belongs to a blocked subnet.
        """
        for subnet in self.blocked_subnets:
            if ipaddress.ip_address(src_ip) in ipaddress.ip_network(subnet):
                return True
        return False

    # Send Feedback to Blocked Devices
    def send_block_notification(self, datapath, src_ip, dst_ip):
        """
        Send an ICMP destination unreachable message to blocked devices.
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Create ICMP error packet
        icmp_pkt = icmp.icmp(
            type_=icmp.ICMP_DEST_UNREACH, code=icmp.ICMP_CODE_PORT_UNREACH,
            csum=0, data=icmp.dest_unreach(data=b"Blocked by Firewall")
        )
        ipv4_pkt = ipv4.ipv4(
            dst=src_ip, src=dst_ip, proto=ipv4.inet.IPPROTO_ICMP
        )
        eth_pkt = ethernet.ethernet(
            src="00:00:00:00:00:FF", dst=src_ip, ethertype=ethernet.ether.ETH_TYPE_IP
        )
        pkt = packet.Packet()
        pkt.add_protocol(eth_pkt)
        pkt.add_protocol(ipv4_pkt)
        pkt.add_protocol(icmp_pkt)
        pkt.serialize()

        # Send the packet out
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data
        )
        datapath.send_msg(out)

    # Main Packet Processing Logic
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def block_untrusted(self, ev):
        """
        Process incoming packets and block unauthorized traffic.
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        src_mac = eth.src
        src_ip = ip_pkt.src if ip_pkt else None

        # Refresh trusted MAC addresses dynamically
        self.refresh_trusted_macs()

        # Check if MAC address is trusted
        if src_mac not in self.TRUSTED_MACS:
            self.logger.warning(f"Blocked unauthorized MAC: {src_mac}")
            if src_ip:
                self.send_block_notification(datapath, src_ip, "192.168.1.1")  # Replace with a real destination
            return  # Drop the packet

        # Check if IP address is blocked
        if src_ip and self.is_ip_blocked(src_ip):
            self.logger.warning(f"Blocked unauthorized IP: {src_ip}")
            self.send_block_notification(datapath, src_ip, "192.168.1.1")  # Replace with a real destination
            return  # Drop the packet

        # Allow traffic from trusted MAC addresses
        self.logger.info(f"Allowed traffic from MAC: {src_mac}")
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, None, actions)

    # Add Flow Rule to Switch
    def add_flow(self, datapath, match, actions, priority=1):
        """
        Add a flow rule to the switch to process traffic.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match, instructions=inst
        )
        datapath.send_msg(mod)
