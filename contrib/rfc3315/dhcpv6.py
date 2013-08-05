from contrib.rfc3315 import builder
from contrib.rfc3315.constants import *
from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class DHCPv6Helper(ComplianceTestCase):

    def build_dhcpv6_advertisement(self, s, server, client, options=True, ias=True, T1=300, T2=300):
        a = DHCP6_Advertise(trid=s.trid)/ \
                DHCP6OptServerId(duid=builder.duid(server.iface(0).ll_addr))/ \
                    DHCP6OptClientId(duid=s[DHCP6OptClientId].duid)
        if options:
            for option in builder.options(s[DHCP6OptOptReq].reqopts):
                a = a/option
        if ias:
            for ia in builder.ias(s[DHCP6OptIA_NA], client, T1, T2):
                a = a/ia
        a = a/DHCP6OptPref()

        return a

    def build_dhcpv6_confirm(self, server, client, ip, iaid=0x87654322, trid=0x1235, T1=300, T2=300):
        p = DHCP6_Confirm(trid=trid)/ \
                DHCP6OptClientId(duid=builder.duid(client.iface(0).ll_addr))/ \
                    DHCP6OptIA_NA(iaid=iaid, T1=T1, T2=T2, ianaopts=DHCP6OptIAAddress(addr=ip))

        return p

    def build_dhcpv6_decline(self, q, server, client, T1=5400, T2=3600):
        p = DHCP6_Decline(trid=q.trid)/ \
                DHCP6OptServerId(duid=q[DHCP6OptServerId].duid)/ \
                    DHCP6OptClientId(duid=q[DHCP6OptClientId].duid)/ \
                        DHCP6OptIA_NA(iaid=q.iaid, T1=T1, T2=T2, ianaopts=DHCP6OptIAAddress(addr=q[DHCP6OptIAAddress].addr))

        return p

    def build_dhcpv6_reply(self, q, server, client, ias=True, T1=300, T2=300):
        p = DHCP6_Reply(trid=q.trid)/ \
                DHCP6OptServerId(duid=builder.duid(server.iface(0).ll_addr))/ \
                    DHCP6OptClientId(duid=q[DHCP6OptClientId].duid)
        if ias:
            for ia in builder.ias(q[DHCP6OptIA_NA], client, T1, T2):
                p = p/ia
        p = p/DHCP6OptPref()

        return p

    def build_dhcpv6_rebind(self, p, server, client):
        p = DHCP6_Rebind(trid=p.trid+1)/ \
                DHCP6OptClientId(duid=p[DHCP6OptClientId].duid)/ \
                    DHCP6OptServerId(duid=p[DHCP6OptServerId].duid)/ \
                        DHCP6OptIA_NA(iaid=p[DHCP6OptIA_NA].iaid + 1, ianaopts=DHCP6OptIAAddress(addr=self.ip_from(p)))
        return p

    def build_dhcpv6_release(self, p, server, client):
        p = DHCP6_Release(trid=p.trid+1)/ \
                DHCP6OptClientId(duid=p[DHCP6OptClientId].duid)/ \
                    DHCP6OptServerId(duid=p[DHCP6OptServerId].duid)/ \
                        DHCP6OptIA_NA(iaid=p[DHCP6OptIA_NA].iaid + 1, ianaopts=DHCP6OptIAAddress(addr=self.ip_from(p)))
        return p

    def build_dhcpv6_request(self, a, server, client):
        p = DHCP6_Request(trid=a.trid)/ \
                DHCP6OptClientId(duid=a[DHCP6OptClientId].duid)/ \
                    DHCP6OptServerId(duid=a[DHCP6OptServerId].duid)/ \
                        DHCP6OptIA_NA(ianaopts=DHCP6OptIAAddress(addr=a[DHCP6OptIAAddress].addr))
        return p

    def build_dhcpv6_renew(self, p, server, client):
        p = DHCP6_Renew(trid=p.trid+1)/ \
                DHCP6OptClientId(duid=p[DHCP6OptClientId].duid)/ \
                    DHCP6OptServerId(duid=p[DHCP6OptServerId].duid)/ \
                        DHCP6OptIA_NA(iaid=p[DHCP6OptIA_NA].iaid + 1, ianaopts=DHCP6OptIAAddress(addr=self.ip_from(p)))
        return p
    
    def build_dhcpv6_solicit(self, client, iaid=0x4321, trid=0x1234, T1=300, T2=300):
        p = DHCP6_Solicit(trid=trid)/ \
                DHCP6OptClientId(duid=builder.duid(client.iface(0).ll_addr))/ \
                    DHCP6OptOptReq()/ \
                        DHCP6OptIA_NA(iaid=iaid, T1=T1, T2=T2)
        return p

    def do_dhcpv6_handshake_as_client(self, server, client, iaid=0x00004321, trid=0x1234, T1=300, T2=300):
        self.logger.info("Building a DHCPv6 Solicit message")
        s = self.build_dhcpv6_solicit(client, iaid=iaid, trid=trid)

        self.logger.info("Sending the DHCPv6 Solicit message, to request addressing parameters...")
        client.send(IPv6(src=str(client.link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/s)

        self.logger.info("Checking for a DHCPv6 Advertise message...")
        r1 = client.received(src=str(server.link_local_ip()), type=DHCP6_Advertise)
        assertEqual(1, len(r1), "expected to receive a DHCPv6 Advertise")
        a = r1[0]

        assertHasLayer(DHCP6OptIA_NA, a, "expected the DHCPv6 Advertise to contain an IA")
        assertHasLayer(DHCP6OptIAAddress, a, "expected the IA to contain an Address")

        self.logger.info("Building a DHCPv6 Request message...")
        q = self.build_dhcpv6_request(a, server, client)

        self.logger.info("Sending the DHCPv6 Request message...")
        client.send(IPv6(src=str(client.link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q)

        self.logger.info("Checking for a DHCPv6 Reply message...")
        r2 = client.received(src=str(server.link_local_ip()), type=DHCP6_Reply)
        assertEqual(1, len(r2), "expected to receive a DHCPv6 Reply")
        p = r2[0]

        assertHasLayer(DHCP6OptIA_NA, p, "expected the DHCPv6 Reply to contain an IA")
        assertHasLayer(DHCP6OptIAAddress, p, "expected the IA to contain an Address")
        assertEqual(self.ip_from(q), self.ip_from(p), "expected the IA to contain the requested address")

        return (self.ip_from(p), p)
    
    def do_dhcpv6_handshake_as_server(self, server, client, wait=True, T1=300, T2=300):
        self.restart_interface_confirm()

        self.logger.info("Checking for a DHCPv6 Solicit message...")
        r1 = server.received(src=str(client.link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers, type=DHCP6_Solicit)
        assertGreaterThanOrEqualTo(1, len(r1), "expected to receive a DHCPv6 Solicit message")
        s = r1[0][UDP]

        self.logger.info("Building a DHCPv6 Advertisement for the client")
        a = self.build_dhcpv6_advertisement(s, server, client, T1=T1, T2=T2)

        self.logger.info("Sending the DHCPv6 Advertise message, to offer the client addressing parameters...")
        server.send(IPv6(src=str(server.link_local_ip()), dst=str(client.link_local_ip()))/UDP(sport=s.dport, dport=s.sport)/a)

        self.logger.info("Waiting for the UUT to respond to the DHCPv6 Advertisement...")
        r2 = server.received(src=str(client.link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers, type=DHCP6_Request)
        assertGreaterThanOrEqualTo(1, len(r2), "expected to receive a DHCPv6 Request")
        q = r2[0][UDP]

        assertHasLayer(DHCP6OptIA_NA, q, "expected the DHCPv6 Request to contain an IA")
        assertHasLayer(DHCP6OptIAAddress, q, "expected the IA to contain an Address")
        assertEqual(client.global_ip(), q[DHCP6OptIAAddress].addr, "expected the DHCPv6 Client to request the IP address offered")

        self.logger.info("Building a DHCPv6 Reply message, to confirm the client's addressing parameters...")
        p = self.build_dhcpv6_reply(q, server, client, T1=T1, T2=T2)

        self.logger.info("Sending the DHCPv6 Reply message...")
        server.send(IPv6(src=str(server.link_local_ip()), dst=str(client.link_local_ip()))/UDP(sport=s.dport, dport=s.sport)/p)

        if wait:
            self.logger.info("Waiting for the UUT to configure its network interface...")
            self.ui.wait(5)

    def ip_from(self, something_with_ia):
        return something_with_ia[DHCP6OptIAAddress].addr
    
