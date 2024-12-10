#!/usr/bin/env python3

from probe_hdrs import *


bind_layers(Ether, Counter, type=TYPE_PROBE)
bind_layers(Counter, IP, visited_count=0)
bind_layers(Counter, ProbeData)
bind_layers(ProbeData, ProbeData, bos=0)
bind_layers(ProbeData, IP, bos=1)

def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x

def handle_pkt(pkt):
    if ProbeData in pkt:
        data_layers = [l for l in expand(pkt) if l.name=='ProbeData']
        data_layers.reverse()
        print("")
        for sw in data_layers:
            # utilization = 0 if sw.cur_time == sw.last_time else 8.0*sw.byte_cnt/(sw.cur_time - sw.last_time)
            switch_id = sw.switch_id
            rule_id = sw.rule_id
            in_port = sw.in_port
            out_port = sw.out_port
            # print("Switch {} - Port {}: {} Mbps".format(sw.swid, sw.port, utilization))
            print("Switch {} - Rule {}: In Port {} Out Port {}".format(switch_id, rule_id, in_port, out_port))
    else:
        print("No ProbeData layer found")
    print("-"*30)

def main():
    iface = 'eth0'
    print("sniffing on {}".format(iface))
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
