#!/usr/bin/env python3

from probe_hdrs import *


def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x

def handle_pkt(pkt):
    if ProbeData in pkt:
        data_layers = [l for l in expand(pkt) if l.name=='ProbeData']
        print("")
        for sw in data_layers:
            # utilization = 0 if sw.cur_time == sw.last_time else 8.0*sw.byte_cnt/(sw.cur_time - sw.last_time)
            switch_id = sw.switch_id
            rule_id = sw.rule_id
            in_port = sw.in_port
            out_port = sw.out_port
            # print("Switch {} - Port {}: {} Mbps".format(sw.swid, sw.port, utilization))
            print("Switch {} - Rule {}: In Port {} Out Port {}".format(switch_id, rule_id, in_port, out_port))

def main():
    iface = 'eth0'
    print("sniffing on {}".format(iface))
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
