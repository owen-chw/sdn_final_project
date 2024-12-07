# Source Routing Based In-band Network Telemetry
## 不時輕聲地以Source Routing探測網路的鄰座艾莉同學

## packet format
```
---------------------------------------------------------------------------
|  Ethernet | routing_label_stack | visited_count | Probe_data_stack | IPv4|
---------------------------------------------------------------------------
```
- `routing_label_stack`: Store source routing label
  - include:
    - out port: 16 bits
    - bos: bottom of stacks, 1 bit
  - total: N * 17 bits

- `visited_count`: Store how many hops the probing packet has visited
  - 8 bits

- `Probe_data_stack`: Stack to Store telemetry data from each hop
  - include:
    - switch ID: 8 bits
    - rule ID: 16 bits
    - in port: 16 bits
    - out port: 16 bits
    - bos: bottom of stack, 1 bit
