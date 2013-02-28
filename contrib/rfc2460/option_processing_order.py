from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase

class FirstOptionHasMostSignificantBits00TestCase(ComplianceTestCase):
    """
    Option Processing Order - First Option has Most Significant Bits 00b.
    
    Common methods for the subsequent test classes. 

    """
    def run(self):
        raise NotImplementedError("Test sub-class should implement this method.")

    @staticmethod
    def zero_filled_destination_option(option_type, option_length):
        return HBHOptUnknown(otype=option_type, optlen=option_length, optdata = (option_length * '\x00'))

    def option_type_7(self):
        return self.zero_filled_destination_option(option_type=7, option_length=4)

    def option_type_71(self):
        return self.zero_filled_destination_option(option_type=71, option_length=6)

    def option_type_135(self):
        return self.zero_filled_destination_option(option_type=135, option_length=6)

    def option_type_199(self):
        return self.zero_filled_destination_option(option_type=199, option_length=6)

class FirstOptionHasMostSignificantBits00NextHasMostSignificantBits01TestCase(FirstOptionHasMostSignificantBits00TestCase):
    """
    Option Processing Order - First Option has Most Significant Bits 00b,
    Next has Most Significant Bits 01b
    
    Verify that a node properly processes the options in a single header in
    the order of occurrence.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.5a)
    """
    
    def run(self):
        self.logger.info("Sending an IPv6 packet header with a destination options header, with multiple options.")
        data_byte = '\x00'
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=60)/
                IPv6ExtHdrDestOpt(nh=44,len=0,options=[
                    self.option_type_7(),
                    self.option_type_71(),
                    self.option_type_135(),
                    self.option_type_199()
                ])/
                ICMPv6EchoRequest(seq=self.next_seq()))
                    
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        self.logger.info("Got %s. Expecting no reply (None).", repr(r1))
        assertEqual(0, len(r1), "did not expect to receive a reply")


class FirstOptionHasMostSignificantBits00NextHasMostSignificantBits10TestCase(FirstOptionHasMostSignificantBits00TestCase):
    """
    Option Processing Order - First Option has Most Significant Bits 00b,
    Next has Most Significant Bits 10b
    
    Verify that a node properly processes the options in a single header in
    the order of occurrence.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.5b)
    """
    
    def run(self):
        self.logger.info("Sending IPv6 packet header with a destination options header, with multiple options.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=60)/
                IPv6ExtHdrDestOpt(nh=58,len=3,options=[
                    self.option_type_7(),
                    self.option_type_135(),
                    self.option_type_199(),
                    self.option_type_71(),
                ])/
                ICMPv6EchoRequest(seq=self.next_seq()))
                    
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6ParamProblem)

        assertEqual(1, len(r1), "expected to receive an ICMPv6 Parameter Problem")
        assertEqual(2, r1[0].getlayer(ICMPv6ParamProblem).code, "expected the Parameter Problem message to have a Code Field of 2")
        assertEqual(48, r1[0].getlayer(ICMPv6ParamProblem).ptr, "expected the Parameter Problem message to have a Pointer Field of 0x30")


class FirstOptionHasMostSignificantBits00NextHasMostSignificantBits11TestCase(FirstOptionHasMostSignificantBits00TestCase):
    """
    Option Processing Order - First Option has Most Significant Bits 00b,
    Next has Most Significant Bits 11b
    
    Verify that a node properly processes the options in a single header in
    the order of occurrence.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.5c)
    """
    
    def run(self):
        self.logger.info("Sending an IPv6 packet header with a destination options header, with multiple options.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=60)/
                IPv6ExtHdrDestOpt(nh=58,len=3,options=[
                    self.option_type_7(),
                    self.option_type_199(),
                    self.option_type_71(),
                    self.option_type_135(),
                ])/
                ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6ParamProblem)
        
        assertEqual(1, len(r1), "expected to receive an ICMPV6 Parameter Problem")
        assertEqual(2, r1[0].getlayer(ICMPv6ParamProblem).code, "expected the Parameter Problem message to have a Code Field of 2")
        assertEqual(48, r1[0].getlayer(ICMPv6ParamProblem).ptr, "expected the Parameter Problem message to have a Pointer Field of 0x30")
