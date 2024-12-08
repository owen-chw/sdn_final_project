from scapy.all import *

TYPE_PROBE = 0x812

class RoutingLabel(Packet):
   fields_desc = [ BitField("egress_spec", 0, 7),
                   BitField("bos", 0, 1)]

class Counter(Packet):
   fields_desc = [ ByteField("visited_count", 0, 7),]

class ProbeData(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("switch_id", 0, 7),
                   ByteField("rule_id", 0),
                   BitField("in_port", 0, 7),
                   BitField("out_port", 0, 7)]
   

bind_layers(Ether, RoutingLabel, type=TYPE_PROBE)
bind_layers(RoutingLabel, RoutingLabel, bos=0)
bind_layers(RoutingLabel, Counter, bos=1)
bind_layers(Counter, IP, visited_count=0)
bind_layers(Counter, ProbeData)
bind_layers(ProbeData, ProbeData, bos=0)
bind_layers(ProbeData, IP, bos=1)