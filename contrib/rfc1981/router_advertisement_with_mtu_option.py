from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class RouterAdvertisementWithMTUOptionTestCase(ComplianceTestCase):
    """
    Router Advertisement with MTU Option

    Verifies that a host properly processes a Router Advertisement with an MTU
    option and reduces its estimate.

    @private
    Source          IPv6 Ready Logo Program Phase-1/Phase-2 Test Specification
                    Core Protocols (v6LC.4.1.8)
    """

    restart_uut = True
    disabled_ra = True
    disabled_nd = True
    

    def common_test_setup(self):
        """ This is the test setup method that should be common to a 
        whole bunch of tests, but unfortunately the original author
        chose to implement this in a totally different way. 

        TODO: make this actually common"""
        self.logger.info("Executing common test setup 1.1")
        self.logger.info("Sending a router solicitation from TR1")
        self.router(1).send(
            IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst='ff02::1')/\
            ICMPv6ND_RA(routerlifetime=1800, reachabletime=30000, retranstimer=1000)/\
            ICMPv6NDOptPrefixInfo(
                prefixlen = self.router(1).global_ip(iface=1).prefix_size,
                prefix = self.router(1).global_ip(iface=1).network()
            ),
        iface=1)
        self.logger.info("Sending an ICMPv6 Echo Request from TR1")
        self.router(1).send(
            IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()))/\
            ICMPv6EchoRequest(seq=self.next_seq()),
        iface=1)
        self.logger.info("Checking for a Neighbor Solicitation")
        rcvd = self.router(1).received(src=self.target(1).link_local_ip(), dst=self.router(1).link_local_ip(iface=1).solicited_node(),
            type=ICMPv6ND_NS, iface=1)
        assertGreaterThanOrEqualTo(1, len(rcvd), "expected the NUT to send a Neighbor Solictation to TR1's solicited node address")
        assertEqual(self.router(1).link_local_ip(iface=1), rcvd[0][ICMPv6ND_NS].tgt, 
            "expected the NUT to send a Neighbor Solicitation targeting TR1's link-local address")
        self.logger.info("Sending a Neighbor Advertisement")
        self.router(1).send(
            IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()))/\
            ICMPv6ND_NA(R=1, S=1, O=1, tgt=str(self.router(1).link_local_ip(iface=1)))/\
            ICMPv6NDOptDstLLAddr(lladdr=self.router(1).iface(1).ll_addr),
        iface=1)
        self.logger.info("Checking for an ICMPv6 Echo Reply")
        rcvd = self.router(1).received(src=self.target(1).link_local_ip(), dst=self.router(1).link_local_ip(iface=1), 
            seq=self.seq(), type=ICMPv6EchoReply, iface=1)
        assertEqual(1, len(rcvd), "expected the NUT to send an ICMPv6 Echo Reply to TR1")
        self.router(1).clear_received()

    def run(self):
        self.common_test_setup()
        self.logger.info("Forwarding ICMPv6 echo request from TN2 to NUT...")
        self.node(2).send( \
            util.pad( \
                IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True))

        self.logger.info("Checking for a reply...")
        r1 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))
        assertNotFragmented(r1[0])
        self.node(2).clear_received()
        
        self.logger.info("Sending Router Advertisement from TR1, with the MTU option set to 1280")
        self.router(1).send(
            IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1")/
                ICMPv6ND_RA()/
                    ICMPv6NDOptMTU(mtu=1280), iface=1)

        self.logger.info("Forwarding another ICMPv6 echo request from TN2 to NUT...")
        for f in fragment6(util.pad(IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoRequest(seq=self.next_seq()), 1500, True), 1280):
            self.node(2).send(f)

        self.ui.wait(5)
        self.logger.info("Checking for replies...")
        r2 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r2), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))
        assertFragmented(r2[0], self.node(2).received(), count=2, size=1280, reassemble_to=1500)
        
