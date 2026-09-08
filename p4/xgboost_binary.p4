/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> PROTO_INT = 253;
const bit<8> PROTO_TCP = 6;

#define MAX_HOPS 10

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_v;
typedef bit<32> ip4Addr_v;

typedef bit<16> flowID_t;
typedef bit<32> int_t;
typedef bit<48> timestamp_t;

typedef bit<31> switchID_v;
typedef bit<9> ingress_port_v;
typedef bit<9> egress_port_v;
typedef bit<9>  egressSpec_v;
typedef bit<48>  ingress_global_timestamp_v;
typedef bit<48>  egress_global_timestamp_v;
typedef bit<32>  enq_timestamp_v;
typedef bit<19> enq_qdepth_v;
typedef bit<32> deq_timedelta_v;
typedef bit<19> deq_qdepth_v;

header ethernet_h {
    macAddr_v dstAddr;
    macAddr_v srcAddr;
    bit<16>   etherType;
}

header ipv4_h {
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
    ip4Addr_v srcAddr;
    ip4Addr_v dstAddr;
}

header tcp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header nodeCount_h{
    bit<16>  count;
}

header InBandNetworkTelemetry_h {
    switchID_v swid;
    ingress_port_v ingress_port;
    egress_port_v egress_port;
    egressSpec_v egress_spec;
    ingress_global_timestamp_v ingress_global_timestamp;
    egress_global_timestamp_v egress_global_timestamp;
    enq_timestamp_v enq_timestamp;
    enq_qdepth_v enq_qdepth;
    deq_timedelta_v deq_timedelta;
    deq_qdepth_v deq_qdepth;
}

struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}

struct metadata {
    ingress_metadata_t   ingress_metadata;
    parser_metadata_t   parser_metadata;
    flowID_t flowID;
    bit<8> diffserv;
    bit<14> action_select1;
    bit<16> window;
    bit<14> action_select2;
    bit<32> frame_size;
    bit<14> action_select3;
    bit<48> ipi;
    bit<14> action_select4;
    bit<64> xgb_score; 
    bit<3>  result;
}

struct headers {
    ethernet_h         ethernet;
    ipv4_h             ipv4;
    tcp_h              tcp;
    nodeCount_h        nodeCount;
    InBandNetworkTelemetry_h[MAX_HOPS] INT;
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
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            PROTO_TCP: parse_tcp;
            PROTO_INT: parse_count;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_count{
        packet.extract(hdr.nodeCount);
        meta.parser_metadata.remaining = hdr.nodeCount.count;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_int;
        }
    }

    state parse_int {
        packet.extract(hdr.INT.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining  - 1;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_int;
        }
    }
}

/*************************************************************************
************ C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
************** I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    register<bit<48>>(0xffff) ipi_register;
    register<bit<48>>(0xffff) lpt_register;

    counter(2, CounterType.packets) resultCounter;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action find_flowID_ipv4() {
        bit<1> base = 0;
        bit<16> max = 0xffff;
        bit<16> hash_result;

        hash(
            hash_result,
            HashAlgorithm.crc16,
            base,
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.ipv4.protocol
            },
            max
        );

        meta.flowID = hash_result;
    }

    action set_actionselect1(bit<14> featurevalue1) {
        meta.action_select1 = featurevalue1;
    }

    table feature1_exact {
        key = {
            meta.diffserv: range ;
        }
        actions = {
            NoAction;
            set_actionselect1;
        }
        size = 1024;
    }
    action set_actionselect2(bit<14> featurevalue2) {
        meta.action_select2 = featurevalue2;
    }

    table feature2_exact {
        key = {
            meta.window: range ;
        }
        actions = {
            NoAction;
            set_actionselect2;
        }
        size = 1024;
    }
    action set_actionselect3(bit<14> featurevalue3) {
        meta.action_select3 = featurevalue3;
    }

    table feature3_exact {
        key = {
            meta.frame_size: range ;
        }
        actions = {
            NoAction;
            set_actionselect3;
        }
        size = 1024;
    }
    action set_actionselect4(bit<14> featurevalue4) {
        meta.action_select4 = featurevalue4;
    }

    table feature4_exact {
        key = {
            meta.ipi: range ;
        }
        actions = {
            NoAction;
            set_actionselect4;
        }
        size = 1024;
    }

// ************************* //
// XGBOOST BINARY CLASSIFIER //
// ************************* //

    action add_tree_weight(bit<64> scaled_weight) {
        meta.xgb_score = meta.xgb_score + scaled_weight;
    }


    table tree0_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree1_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree2_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree3_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree4_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree5_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree6_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree7_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree8_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree9_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree10_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree11_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree12_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree13_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree14_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree15_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree16_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree17_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree18_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree19_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree20_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree21_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree22_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree23_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree24_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree25_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree26_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree27_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree28_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree29_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree30_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree31_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree32_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree33_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree34_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree35_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree36_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree37_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree38_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree39_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree40_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree41_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree42_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree43_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree44_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree45_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree46_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree47_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree48_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree49_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree50_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree51_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree52_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree53_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree54_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree55_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree56_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree57_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree58_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree59_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree60_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree61_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree62_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree63_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree64_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree65_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree66_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree67_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree68_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree69_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree70_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree71_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree72_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree73_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree74_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree75_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree76_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree77_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree78_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree79_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree80_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree81_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree82_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree83_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree84_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree85_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree86_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree87_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree88_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree89_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree90_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree91_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree92_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree93_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree94_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree95_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree96_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree97_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree98_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }
    table tree99_exact {
        key = {
            meta.action_select1: range;
            meta.action_select2: range;
            meta.action_select3: range;
            meta.action_select4: range;
        }
        actions = {
            add_tree_weight;
            NoAction;
        }
        size = 1024;
    }

    action set_final_result(bit<3> result) {
        meta.result = result;
    }

    // Tabela para comparar a soma total com o limiar
    table apply_threshold {
        key = { meta.xgb_score: range; }
        actions = { set_final_result; NoAction; drop; }
        size = 16;
    }

// ***************************** //
// XGBOOST BINARY CLASSIFIER END //
// ***************************** //

    action extract_features() {
        meta.diffserv = hdr.ipv4.diffserv;
        meta.window = hdr.tcp.window;
        meta.frame_size = standard_metadata.packet_length;
        timestamp_t ipi = 0;
        int<48> diff_ts = 0;

        timestamp_t current_time = standard_metadata.ingress_global_timestamp;
        timestamp_t last_packet_time = 0;

        ipi_register.read(ipi, (bit<32>)meta.flowID);
        lpt_register.read(last_packet_time, (bit<32>)meta.flowID);

        if (last_packet_time == 0) {
            last_packet_time = current_time;
        } else {
            /* IPI */
            ipi = current_time - last_packet_time;
            last_packet_time = current_time;
        }

        ipi_register.write((bit<32>)meta.flowID, ipi);
        lpt_register.write((bit<32>)meta.flowID, last_packet_time);

        meta.ipi = ipi;
    }

    action ipv4_forward(macAddr_v dstAddr, egressSpec_v port) {
        standard_metadata.egress_spec = port;
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
        default_action = NoAction();
    }

    apply {
        meta.flowID = 0;
        if (hdr.ipv4.isValid()) {
            if (hdr.tcp.isValid() && !hdr.nodeCount.isValid() && hdr.tcp.srcPort != 5201 && hdr.tcp.dstPort != 5201) {
                find_flowID_ipv4();
                extract_features();

                feature1_exact.apply();
                feature2_exact.apply();
                feature3_exact.apply();
                feature4_exact.apply();

                meta.xgb_score = 0;
                tree0_exact.apply();
                tree1_exact.apply();
                tree2_exact.apply();
                tree3_exact.apply();
                tree4_exact.apply();
                tree5_exact.apply();
                tree6_exact.apply();
                tree7_exact.apply();
                tree8_exact.apply();
                tree9_exact.apply();
                tree10_exact.apply();
                tree11_exact.apply();
                tree12_exact.apply();
                tree13_exact.apply();
                tree14_exact.apply();
                tree15_exact.apply();
                tree16_exact.apply();
                tree17_exact.apply();
                tree18_exact.apply();
                tree19_exact.apply();
                tree20_exact.apply();
                tree21_exact.apply();
                tree22_exact.apply();
                tree23_exact.apply();
                tree24_exact.apply();
                tree25_exact.apply();
                tree26_exact.apply();
                tree27_exact.apply();
                tree28_exact.apply();
                tree29_exact.apply();
                tree30_exact.apply();
                tree31_exact.apply();
                tree32_exact.apply();
                tree33_exact.apply();
                tree34_exact.apply();
                tree35_exact.apply();
                tree36_exact.apply();
                tree37_exact.apply();
                tree38_exact.apply();
                tree39_exact.apply();
                tree40_exact.apply();
                tree41_exact.apply();
                tree42_exact.apply();
                tree43_exact.apply();
                tree44_exact.apply();
                tree45_exact.apply();
                tree46_exact.apply();
                tree47_exact.apply();
                tree48_exact.apply();
                tree49_exact.apply();
                tree50_exact.apply();
                tree51_exact.apply();
                tree52_exact.apply();
                tree53_exact.apply();
                tree54_exact.apply();
                tree55_exact.apply();
                tree56_exact.apply();
                tree57_exact.apply();
                tree58_exact.apply();
                tree59_exact.apply();
                tree60_exact.apply();
                tree61_exact.apply();
                tree62_exact.apply();
                tree63_exact.apply();
                tree64_exact.apply();
                tree65_exact.apply();
                tree66_exact.apply();
                tree67_exact.apply();
                tree68_exact.apply();
                tree69_exact.apply();
                tree70_exact.apply();
                tree71_exact.apply();
                tree72_exact.apply();
                tree73_exact.apply();
                tree74_exact.apply();
                tree75_exact.apply();
                tree76_exact.apply();
                tree77_exact.apply();
                tree78_exact.apply();
                tree79_exact.apply();
                tree80_exact.apply();
                tree81_exact.apply();
                tree82_exact.apply();
                tree83_exact.apply();
                tree84_exact.apply();
                tree85_exact.apply();
                tree86_exact.apply();
                tree87_exact.apply();
                tree88_exact.apply();
                tree89_exact.apply();
                tree90_exact.apply();
                tree91_exact.apply();
                tree92_exact.apply();
                tree93_exact.apply();
                tree94_exact.apply();
                tree95_exact.apply();
                tree96_exact.apply();
                tree97_exact.apply();
                tree98_exact.apply();
                tree99_exact.apply();
                apply_threshold.apply();
                resultCounter.count((bit<32>)meta.result);

                if (meta.result == 1) {
                    standard_metadata.priority = 1;
                } else {
                    standard_metadata.priority = 0;
                }
            }

            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
**************** E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action add_swtrace(switchID_v swid) {
        hdr.nodeCount.count = hdr.nodeCount.count + 1;
        hdr.INT.push_front(1);
        hdr.INT[0].setValid();
        hdr.INT[0].swid = swid;
        hdr.INT[0].ingress_port = (ingress_port_v)standard_metadata.ingress_port;
        hdr.INT[0].ingress_global_timestamp = (ingress_global_timestamp_v)standard_metadata.ingress_global_timestamp;
        hdr.INT[0].egress_port = (egress_port_v)standard_metadata.egress_port;
        hdr.INT[0].egress_spec = (egressSpec_v)standard_metadata.egress_spec;
        hdr.INT[0].egress_global_timestamp = (egress_global_timestamp_v)standard_metadata.egress_global_timestamp;
        hdr.INT[0].enq_timestamp = (enq_timestamp_v)standard_metadata.enq_timestamp;
        hdr.INT[0].enq_qdepth = (enq_qdepth_v)standard_metadata.enq_qdepth;
        hdr.INT[0].deq_timedelta = (deq_timedelta_v)standard_metadata.deq_timedelta;
        hdr.INT[0].deq_qdepth = (deq_qdepth_v)standard_metadata.deq_qdepth;

        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 32;
    }

    table swtrace {
        actions = {
            add_swtrace;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
        if (hdr.nodeCount.isValid()) {
            swtrace.apply();
        }
    }
}

/*************************************************************************
************* C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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
*********************** D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.nodeCount);
        packet.emit(hdr.INT);
    }
}

/*************************************************************************
*********************** S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
