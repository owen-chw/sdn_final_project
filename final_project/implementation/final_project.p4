/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4  = 0x800;
const bit<16> TYPE_PROBE = 0x812;

#define MAX_HOPS 256  
#define MAX_PORTS 512 

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> ruleId_t;
typedef bit<48> time_t;


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
    bit<16>         rule_id;
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

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_PROBE: parse_routing_label;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_routing_label {
        packet.extract(hdr.routing_label_stack.next);
        transition select(hdr.routing_label_stack.last.bos){
            1: parse_counter;
            default: parse_routing_label;
        }
    }

    state parse_counter {
        packet.extract(hdr.counter);
        transition select(hdr.counter.visited_count) {
            0: parse_ipv4;
            default: parse_probe_data;
        }
    }

    state parse_probe_data {
        packet.extract(hdr.probe_data_stack.next);
        transition select(hdr.probe_data_stack.last.bos) {
            1: parse_ipv4;
            default: parse_probe_data;
        }
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    //(1) for ipv4 forwarding table
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port, ruleId_t rule_id) {
        standard_metadata.egress_spec = port;
        meta.rule_id = rule_id;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    //(2) for probe data
    //(2-1) for switch_id setting table
    action set_swid(bit<8> swid){
        hdr.probe_data_stack[0].switch_id = swid;
    }

    table swid{
        actions = {
            set_swid;
            NoAction;
        }
        default_action = NoAction;
    }

    //(3) for source_routing
    action srcRoute_forward(){
        standard_metadata.egress_spec = hdr.routing_label_stack[0].egress_spec;
        hdr.routing_label_stack.pop_front(1);
    }


    apply {
        //(1) apply ipv4 forwarding
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }

        //(2) fill out probe data
        if (hdr.counter.isValid()) {
            hdr.probe_data_stack.push_front(1);
            hdr.probe_data_stack[0].setValid();
            if (hdr.counter.visited_count == 0) {
                hdr.probe_data_stack[0].bos = 1;
            }
            else {
                hdr.probe_data_stack[0].bos = 0;
            }
            swid.apply();
            hdr.counter.visited_count =  hdr.counter.visited_count + 1;
            //TODO: refer to link_monitor L230

        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    // count the number of bytes seen since the last probe
    register<bit<32>>(MAX_PORTS) byte_cnt_reg;
    // remember the time of the last probe
    register<time_t>(MAX_PORTS) last_time_reg;

    

    apply {
        bit<32> byte_cnt;
        bit<32> new_byte_cnt;
        time_t last_time;
        time_t cur_time = standard_metadata.egress_global_timestamp;
        // increment byte cnt for this packet's port
        byte_cnt_reg.read(byte_cnt, (bit<32>)standard_metadata.egress_port);
        byte_cnt = byte_cnt + standard_metadata.packet_length;
        // reset the byte count when a probe packet passes through
        new_byte_cnt = (hdr.probe_data_stack[0].isValid()) ? 0 : byte_cnt;
        byte_cnt_reg.write((bit<32>)standard_metadata.egress_port, new_byte_cnt);

        if (hdr.probe_data_stack[0].isValid()) {
            // fill out probe fields
            
            // The probe_data is pushed in the Ingress part.
            
            // set switch ID field
            // swid.apply(); // applied in Ingress
            
            // TODO: fill out the rest of the probe packet fields
            hdr.probe_data_stack[0].in_port = standard_metadata.ingress_port;
            hdr.probe_data_stack[0].out_port = standard_metadata.egress_spec;
            hdr.probe_data_stack[0].rule_id = meta.rule_id;
            // hdr.probe_data[0].byte_cnt = ...
            // TODO: read / update the last_time_reg
            // last_time_reg.read(<val>, <index>);
            // last_time_reg.write(<index>, <val>);
            // hdr.probe_data[0].last_time = ...
            // hdr.probe_data[0].cur_time = ...
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   ***************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.probe_data_stack);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
