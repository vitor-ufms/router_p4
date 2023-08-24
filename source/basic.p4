/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x86DD;
const bit<16> TYPE_ARP = 0x806;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

header ipv6_t {
    bit<4>  version;
    bit<8>  traf_class;
    bit<20> flow_lab;
    bit<16> payload_length;
    bit<8>  next_header;
    bit<8>  hop_lim;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

header tcp_t {
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

header time_stamp_t {

    bit<48> ingress_ts; // carimbo de data/hora, em microssegundos, definido quando o pacote aparece na entrada
    bit<48> egress_ts; // um carimbo de data/hora, em microssegundos, definido quando o pacote inicia o processamento de saída,  lido no pipeline de saída
    bit<32> enq_ts; // um carimbo de data/hora, em microssegundos, definido quando o pacote é enfileirado pela primeira vez.
    bit<32> deq_ts; // deq_timedelta: o tempo, em microssegundos, que o pacote ficou na fila.

}

struct metadata {
    /* empty */
    time_stamp_t time;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    ipv6_t       ipv6;
    tcp_t        tcp;
    time_stamp_t time;
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

    state parse_ethernet { // ethernet
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV6: parse_ipv6;
            // arp
            default: accept;
        }
    }

    state parse_ipv4 { // ipv4
        packet.extract(hdr.ipv4);
        //packet.extract(hdr.tcp); // APAGAR ESSA LINHA DEPOIS
        transition accept;
    }
    state parse_ipv6{ // ipv6
        packet.extract(hdr.ipv6);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { 
         verify_checksum(  // adiciona 1 em standard_metadata.checksum_error se estiver erro
            hdr.ipv4.isValid(),
            {   hdr.ipv4.version,
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
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
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
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) { // procedimentos para ipv4
            ipv4_lpm.apply();
            if(hdr.ipv4.ttl == 0) // subtrai e depois verifica, tem qu enviar mensagem de erro?
                drop();
            if (standard_metadata.checksum_error == 1)
                drop(); 
        }
        if(hdr.ipv6.isValid()) // procedimentos ipv6
            //ipv6_table.apply();
            if(hdr.ipv6.hop_lim == 0)
                drop();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { 

        if(!hdr.time.isValid()){ // cria um header no pacote com time

            hdr.time.setValid();

            hdr.time.ingress_ts = standard_metadata.ingress_global_timestamp;
            hdr.time.egress_ts = standard_metadata.egress_global_timestamp;
            hdr.time.enq_ts = standard_metadata.enq_timestamp;
            hdr.time.deq_ts = standard_metadata.deq_timedelta;

        }

        //   meta.time.ingress_ts = standard_metadata.ingress_global_timestamp;
        // meta.time.egress_ts = standard_metadata.egress_global_timestamp;
        // meta.time.enq_ts = standard_metadata.enq_timestamp;
        // meta.time.deq_ts = standard_metadata.deq_timedelta;
    
    
     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
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
        //packet.emit(hdr.tcp);
        //packet.emit(hdr.time);
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


/*************************************************************************
***********************  Comentarios add   *******************************
*************************************************************************/
/* RFC 1812

 Qual topologia?
 erro de checksum descarta o pacote // RFC 1812 item 4.2.2.5

IMPREMENTAR:
 - checksum verify
 - forwarding ipv6
 - Protocolo arp
 - icmp
 - broadcast

TESTAR:
 - ttl
 - checksum
 - forwanding 


*/

// header tcp_t {
//     bit<16> srcPort;
//     bit<16> dstPort;
//     bit<32> seqNo;
//     bit<32> ackNo;
//     bit<4>  dataOffset;
//     bit<3>  res;
//     bit<3>  ecn;
//     bit<6>  ctrl;
//     bit<16> window;
//     bit<16> checksum;
//     bit<16> urgentPtr;
// }