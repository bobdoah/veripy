from contrib.rfc4443 import error_condition_with_non_unique_source_multicast as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class NonUniqueSourceMulticastUDPPortUnreachableTestCase(ComplianceTestTestCase):

    def test_port_unreachable_valid(self):
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.NonUniqueSourceMulticastUDPPortUnreachableTestCase)

        self.assertCheckPasses(o)
        
    def test_port_unreachable_invalid_user_response(self):
        self.ui.inputs.append('y')
        
        o = self.get_outcome(suite.NonUniqueSourceMulticastUDPPortUnreachableTestCase)

        self.assertCheckFails(o)

    def test_port_unreachable_valid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.NonUniqueSourceMulticastUDPPortUnreachableTestCase)

        self.assertCheckPasses(o)
        
    def test_port_unreachable_invalid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach())
        self.ui.inputs.append('n')
        
        o = self.get_outcome(suite.NonUniqueSourceMulticastUDPPortUnreachableTestCase)

        self.assertCheckFails(o)
    
    
class NonUniqueSourceMulticastEchoRequestTooBigTestCase(ComplianceTestTestCase):

    def test_packet_too_big_valid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.NonUniqueSourceMulticastEchoRequestTooBigTestCase)

        self.assertCheckPasses(o)


    def test_packet_too_big_invalid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6PacketTooBig())

        o = self.get_outcome(suite.NonUniqueSourceMulticastEchoRequestTooBigTestCase)

        self.assertCheckFails(o)


class NonUniqueSourceMulticastReassemblyTimeoutTestCase(ComplianceTestTestCase):

    def test_reassembly_timeout_valid(self):
        o = self.get_outcome(suite.NonUniqueSourceMulticastReassemblyTimeoutTestCase)

        self.assertCheckPasses(o)

    def test_reassembly_timeout_invalid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded())

        o = self.get_outcome(suite.NonUniqueSourceMulticastReassemblyTimeoutTestCase)

        self.assertCheckFails(o)

    def test_reassembly_timeout_valid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.NonUniqueSourceMulticastReassemblyTimeoutTestCase)

        self.assertCheckPasses(o)


class NonUniqueSourceMulticastInvalidDestinationOptionsTestCase(ComplianceTestTestCase):

    def test_unknown_dest_options_valid(self):
        o = self.get_outcome(suite.NonUniqueSourceMulticastInvalidDestinationOptionsTestCase)
        
        self.assertCheckPasses(o)


    def test_unknown_dest_options_invalid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem())

        o = self.get_outcome(suite.NonUniqueSourceMulticastInvalidDestinationOptionsTestCase)

        self.assertCheckFails(o)

    def test_unknown_dest_options_valid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.NonUniqueSourceMulticastInvalidDestinationOptionsTestCase)

        self.assertCheckPasses(o)
    