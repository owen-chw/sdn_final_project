# Source Routing Based In-band Network Telemetry
## 不時輕聲地以Source Routing探測網路的鄰座艾莉同學

## packet format
```
---------------------------------------------------------------------------
|  Ethernet | routing_label_stack | visited_count | Probe_data_stack | IPv4|
---------------------------------------------------------------------------
```
- `routing_label_stack`: Store source routing label
  - N * 5 bits
- `visited_count`: Store how many hops the probing packet has visited
  - 10 bits
- `Probe_data_stack`: Stack to Store telemetry data from each hop
  - include:
    - switch ID
    - rule ID
    - in port: 16 bits
    - out port: 16 bits
