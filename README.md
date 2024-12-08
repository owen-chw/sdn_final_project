# Source Routing Based In-band Network Telemetry
## 不時輕聲地以Source Routing探測網路的鄰座艾莉同學

## packet format
```
---------------------------------------------------------------------------
|  ethernet | routing_label_stack | counter | probe_data_stack | ipv4|
---------------------------------------------------------------------------
```
- `routing_label_stack`: Store source routing label
  - include:
    - egress_spec: 7 bits
    - bos: bottom of stacks, 1 bit
  - total: N * 8 bits

- `counter`: 
  - `visited_count`: Store how many hops the probing packet has visited
    - 8 bits

- `probe_data_stack`: Stack to Store telemetry data from each hop
  - include:
    - switch ID: 8 bits
    - rule ID: 17 bits
    - in port: 7 bits
    - out port: 7 bits
    - bos: bottom of stack, 1 bit

## datail packet format:w
```c=
#define MAX_HOPS 256  
#define MAX_PORTS 128

typedef bit<7>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> ruleId_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

// Routing label, indicate the egress port at each switch
header routing_label_t {
    egressSpec_t   egress_spec;
    bit<1>  bos;
}

// counter header, indicates how many hops this probe
// packet has traversed so far.
header counter_t {
    bit<8> visited_count;
}

// Probe data header, store telemetry data from each hop
// The data added to the stack by each switch at each hop.
header probe_data_t {
    bit<1>          bos;
    bit<8>          switch_id;
    bit<17>         rule_id;
    egressSpec_t   in_port;
    egressSpec_t   out_port;
}


struct metadata {
    ruleId_t rule_id;
}

struct headers {
    ethernet_t                  ethernet;
    routing_label_t[MAX_HOPS]   routing_label_stack;
    counter_t                   counter;
    probe_data_t[MAX_HOPS]      probe_data_stack;
    ipv4_t                      ipv4;
}
```