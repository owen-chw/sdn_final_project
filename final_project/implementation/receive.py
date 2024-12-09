#!/usr/bin/env python3

from probe_hdrs import *


def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x

def handle_pkt(pkt):
    print("Received a packet")
    for l in expand(pkt):
        print(l.name)
    if ProbeData in pkt:
        data_layers = [l for l in expand(pkt) if l.name=='ProbeData']
        print("")
        for sw in data_layers:
            # utilization = 0 if sw.cur_time == sw.last_time else 8.0*sw.byte_cnt/(sw.cur_time - sw.last_time)
            switch_id = sw.switch_id
            port = sw.port
            byte_cnt = sw.byte_cnt
            last_time = sw.last_time
            cur_time = sw.cur_time
            utilization = 0 if cur_time == last_time else 8.0*byte_cnt/(cur_time - last_time)
            # print("Switch {} - Port {}: {} Mbps".format(sw.swid, sw.port, utilization))
            print("Switch {} - OutPort {}: {} Mbps".format(switch_id, port, utilization))
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
