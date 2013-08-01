from constants import *
from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class OnLinkDeterminationTestCase(ComplianceTestCase):
    """
    Router Advertisement Processing, On-link determination

    Verify that a host properly rejects an invalid prefix length, however the
    prefix length is still valid for on-link determination when the on-link
    flag is true.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.19)
    """

    disabled_nd = True
    disabled_ra = True
    restart_uut = True

    def run(self):
        self.logger.info("Sending a Router Advertisement from TR1...")
        self.router(1).send(
            IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1")/
                ICMPv6ND_RA(prf=1)/
                    ICMPv6NDOptPrefixInfo(prefixlen=96, prefix=str(self.node(2).global_ip()), L=True)/
                    ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr), iface=1)

        self.logger.info("Sending an Echo Request from TN1...")
        self.node(1).send(
            IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a Neighbor Solicitation")
        r1 = self.node(1).received(dst=self.node(2).global_ip().solicited_node(), src=self.target(1).link_local_ip(), type=ICMPv6ND_NS)
        assertGreaterThanOrEqualTo(1, len(r1), "expected the NUT to send a Neighbor Solicitation to the on-link address")
        assertEqual(self.node(2).global_ip(), r1[0][ICMPv6ND_NS].tgt, "expected the target of the neighbor solicitation"
            " to be %s, but it was %s" % (self.node(2).global_ip(), r1[0][ICMPv6ND_NS].tgt)
        )

        self.logger.info("Sending a Neighbor Advertisement")
        self.node(1).send(
            IPv6(src=str(self.node(2).global_ip()), dst=r1[0][IPv6].src)/
                ICMPv6ND_NA(tgt=str(self.node(2).global_ip()), R=False, S=True, O=True)/
                    ICMPv6NDOptDstLLAddr(lladdr=self.node(1).iface(0).ll_addr))


        self.logger.info("Checking for an ICMPv6 Echo Reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), dst=self.node(2).global_ip(), seq=self.seq(), type=ICMPv6EchoReply, raw=True)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))

        self.logger.info("Grabbing the Echo Reply to see if TR1 forwarded it...")
        r2 = self.router(1).received(iface=1, src=self.target(1).global_ip(), dst=self.node(2).global_ip(), seq=self.seq(), type=ICMPv6EchoReply, raw=True)

        assertEqual(self.node(2).global_ip(), r1[0][IPv6].dst, "expected the ICMPv6 Echo Reply dst to be TN2's global address")
        assertEqual(self.target(1).ll_addr(), r1[0][Ether].src, "expected the ICMPv6 Echo Reply Ethernet src to be the UUT")
        assertNotEqual(self.router(1).iface(1).ll_addr, r1[0][Ether].dst, "did not expect the ICMPv6 Echo Reply to be sent through TR1")
