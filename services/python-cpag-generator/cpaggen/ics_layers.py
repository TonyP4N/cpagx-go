"""
Custom ICS (Industrial Control System) layers for Scapy
Replaces the functionality of scapy-ics package
"""

from scapy.all import *
from scapy.fields import *

# Modbus TCP Layer
class ModbusTCP(Packet):
    name = "ModbusTCP"
    fields_desc = [
        ShortField("transaction_id", 0),
        ShortField("protocol_id", 0),
        ShortField("length", 0),
        ByteField("unit_id", 1),
        ByteField("function_code", 0),
        StrField("data", "")
    ]

# DNP3 Layer
class DNP3(Packet):
    name = "DNP3"
    fields_desc = [
        ByteField("start", 0x05),
        ByteField("length", 0),
        ByteField("control", 0),
        ByteField("destination", 0),
        ByteField("source", 0),
        ByteField("transport", 0),
        StrField("data", "")
    ]

# IEC 60870-5-104 Layer
class IEC60870_5_104(Packet):
    name = "IEC60870-5-104"
    fields_desc = [
        ByteField("start", 0x68),
        ByteField("length", 0),
        IntField("send_seq", 0),
        IntField("recv_seq", 0),
        ByteField("type_id", 0),
        ByteField("sq", 0),
        ByteField("number", 0),
        StrField("data", "")
    ]

# EtherNet/IP Layer
class EtherNetIP(Packet):
    name = "EtherNetIP"
    fields_desc = [
        ShortField("command", 0),
        ShortField("length", 0),
        IntField("session_handle", 0),
        IntField("status", 0),
        LongField("sender_context", 0),
        IntField("options", 0),
        StrField("data", "")
    ]

# S7 Protocol Layer
class S7(Packet):
    name = "S7"
    fields_desc = [
        ByteField("version", 3),
        ByteField("reserved", 0),
        ShortField("length", 0),
        ShortField("pdu_type", 0),
        ShortField("redundancy_id", 0),
        ShortField("protocol_data_unit_reference", 0),
        StrField("data", "")
    ]

# Bind layers to ports
bind_layers(TCP, ModbusTCP, dport=502)
bind_layers(TCP, ModbusTCP, sport=502)
bind_layers(TCP, DNP3, dport=20000)
bind_layers(TCP, DNP3, sport=20000)
bind_layers(TCP, IEC60870_5_104, dport=2404)
bind_layers(TCP, IEC60870_5_104, sport=2404)
bind_layers(TCP, EtherNetIP, dport=44818)
bind_layers(TCP, EtherNetIP, sport=44818)
bind_layers(TCP, S7, dport=102)
bind_layers(TCP, S7, sport=102)

# ICS Protocol Detection Functions
def detect_ics_protocol(packet):
    """Detect ICS protocols in a packet"""
    protocols = []
    
    if packet.haslayer(ModbusTCP):
        protocols.append("ModbusTCP")
    if packet.haslayer(DNP3):
        protocols.append("DNP3")
    if packet.haslayer(IEC60870_5_104):
        protocols.append("IEC60870-5-104")
    if packet.haslayer(EtherNetIP):
        protocols.append("EtherNetIP")
    if packet.haslayer(S7):
        protocols.append("S7")
    
    return protocols

def is_ics_traffic(packet):
    """Check if packet contains ICS traffic"""
    # Check common ICS ports
    ics_ports = [502, 20000, 2404, 44818, 102, 9600, 5020, 5021]
    
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        if tcp.dport in ics_ports or tcp.sport in ics_ports:
            return True
    
    if packet.haslayer(UDP):
        udp = packet[UDP]
        if udp.dport in ics_ports or udp.sport in ics_ports:
            return True
    
    # Check for ICS protocols
    if detect_ics_protocol(packet):
        return True
    
    return False 