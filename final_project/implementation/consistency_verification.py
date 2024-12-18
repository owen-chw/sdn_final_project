import os
import sys
import glob
import json
import dataclasses

from typing import List

from scapy.all import *
from probe_hdrs import *


bind_layers(Ether, Counter, type=TYPE_PROBE)
bind_layers(Counter, IP, visited_count=0)
bind_layers(Counter, ProbeData)
bind_layers(ProbeData, ProbeData, bos=0)
bind_layers(ProbeData, IP, bos=1)


@dataclasses.dataclass
class Probe:
    switch_id: int
    rule_id: int
    in_port: int
    out_port: int


@dataclasses.dataclass
class SymbolicPacket:
    probes: List[Probe]

    def __iter__(self):
        return iter(self.probes)


class ErrorReport(Exception):
    pass


def check(sp: SymbolicPacket, rule: dict) -> bool:
    rule_id = rule["action_params"]["rule_id"]
    rule_port = rule["action_params"]["port"]

    for probe in sp.probes:
        if probe.rule_id == rule_id and probe.out_port == rule_port:
            return True


def expand(x: Packet):
    yield x
    while x.payload:
        x = x.payload
        yield x


def pkt2sp(pkt: Packet) -> SymbolicPacket:
    if ProbeData in pkt:
        probes = []

        data_layers = [l for l in expand(pkt) if l.name == 'ProbeData']
        data_layers.reverse() # probe is stack

        for p in data_layers:
            probe = Probe(p.switch_id, p.rule_id, p.in_port, p.out_port)
            probes.append(probe)

        return SymbolicPacket(probes)


def parse_path_spec(sp: SymbolicPacket) -> List[str]:
    path = []
    for p in sp.probes:
        path.append(f"s{p.switch_id}")
    return path


def load_switches_rules():
    rules = dict()

    for fn in glob("pod-topo/*-runtime.json"):
        switch_rules = load_switch_rules(fn)
        switch_name = os.path.basename(fn).split(".")[0].split("-")[0]
        rules[switch_name] = switch_rules

    return rules


def load_switch_rules(fn):
    with open(fn, "r") as f:
        data = json.load(f)

    rules = dict()

    for entry in data["table_entries"]:
        if "rule_id" in entry["action_params"]:
            rule_id = entry["action_params"]["rule_id"]
            rules[rule_id] = entry

    return rules


pcap = rdpcap(sys.argv[1])

sps = []

for pkt in pcap:
    sp = pkt2sp(pkt)

    if sp:
        sps.append(sp)

switch_rules = load_switches_rules()

for sp in sps:
    switch_check = False
    path_check = False

    path = parse_path_spec(sp)

    for i, sw in enumerate(parse_path_spec(sp)):
        rules = switch_rules[sw]

        if i == (len(path) - 1): # last switch
            for rule_id in rules:
                rule = rules[rule_id]
                if check(sp, rule):
                    path_check = True # no faults in this given path
                    break
            else:
                switch_check = False
                path_check = False # inconsistent path
                raise ErrorReport(sw, rule)
        else:
            for rule_id in rules:
                rule = rules[rule_id]
                if check(sp, rule):
                    switch_check = True
                    break
            else:
                switch_check = False
                path_check = False # inconsistent path
                raise ErrorReport(sw, rule)
    
    print("============")
    print(sp, path_check)