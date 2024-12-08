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
