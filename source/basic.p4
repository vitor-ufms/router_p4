/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
//const bit<16> TYPE_IPV6 = 0x86DD;
const bit<16> TYPE_ARP = 0x806;


const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;  
const bit<8>  ARP_PLEN_IPV4      = 4; 
const bit<16> ARP_OPER_REQUEST   = 1; // arp.op operation
const bit<16> ARP_OPER_REPLY     = 2;



const bit<8> TYPE_IPV4_ICMP = 0x01;


const bit<8> ICMP_ECHO_REPLY = 0x00;
const bit<8> ICMP_ECHO_REQUEST = 0x08;
const bit<8> ICMP_TIME_EXCEEDED = 0x0B;




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



header arp_t {
    bit<16> hrd_type; // Hardware Type
    bit<16> prot_type; // Protocol Type
    bit<8> hlen; // Hardware Address Length
    bit<8> plen; // Protocol Address Length
    bit<16> op;  // Opcode
    macAddr_t s_Add; // Sender Hardware Address
    ip4Addr_t s_ip; // Sender Protocol Address
    macAddr_t d_Add; // Target Hardware Address
    ip4Addr_t d_ip; // Target Protocol Address
}



header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
}

struct metadata {
    /* empty */
}
header payload_t{

    varbit<524120> data_ip; // tamanho máximo de um payload ip  2^16-1 = 65535 - 20 = 65515 bytes = 524120 bits
}

struct temp {
    egressSpec_t port;
    macAddr_t     mac;
    ip4Addr_t     ip;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    arp_t        arp;
    icmp_t      icmp;
    payload_t payload;
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
            //TYPE_IPV6: parse_ipv6;
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 { // ipv4
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_IPV4_ICMP: parse_icmp;
            default: parse_payload;
            //default: accept;
        }
    }

    state parse_arp{ // ARP
        packet.extract(hdr.arp);
        transition accept;
    }
    state parse_icmp { // ICMP
        packet.extract(hdr.icmp);
        transition accept;
    }
    state parse_payload{ // capitura o payload do cabeçalho ip 

        //packet.extract(hdr.payload, (bit<32>) ((hdr.ipv4.totalLen - (bit<16>)hdr.ipv4.ihl) * 8));
        //b.extract(headers.ipv4options, (bit<32>)(((bit<16>)headers.ipv4.ihl - 5) * 32));

        packet.extract(hdr.payload, (bit<32>) ((hdr.ipv4.totalLen - 20) * 8));      // considera tamanho fixo de cabeçalho ip  
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

    bit<1> PKT_TO_ROUTER = 0;
    //register<bit<48>>(5) interface_mac; // mac(48) cada index é uma porta
    register<bit<32>>(5) interface_ip; // ip(32)
    macAddr_t aux_mac; ip4Addr_t aux_ip;

    temp forward = {0,0,0};


    action drop() {
        mark_to_drop(standard_metadata);
    }

    //action NoAction() {}



/******************** Action for table  ipv4_lpm  ****************************/

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        forward.port = port;
        forward.mac = dstAddr;

        //hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        //hdr.ethernet.dstAddr = dstAddr;
        //hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
            
    }


    action my_router( ){
        PKT_TO_ROUTER = 1;
    }


    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            my_router;
            drop;
            NoAction;
        }
        size = 1024;
        //default_action = drop();
      //  default_action = NoAction(); // default enviar para rota default
    }

/******************** Procedimentos para ICMP ****************************/

    action icmp_forward(){ // icmp para o roteador corrente

        standard_metadata.egress_spec = standard_metadata.ingress_port;
        macAddr_t dstAddr_ether = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr_ether;

        ip4Addr_t srcAddr_ipv4 = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = srcAddr_ipv4;

    }
    action icmp_ping(){
        //hdr.icmp.type = 0x08; rs loop
        hdr.icmp.type = ICMP_ECHO_REPLY; 
         
    }

/******************** Action for table arp_exact  ****************************/

    action arp_answer(macAddr_t addr) {

        standard_metadata.egress_spec = standard_metadata.ingress_port;

        //Ethernet
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = addr;

        // ARP
        hdr.arp.op = ARP_OPER_REPLY;
       
        ip4Addr_t send_ip = hdr.arp.s_ip;
        hdr.arp.s_ip = hdr.arp.d_ip;
        hdr.arp.d_ip = send_ip;

        hdr.arp.d_Add = hdr.arp.s_Add;
        hdr.arp.s_Add = addr;

    }

    action multicast() {
        standard_metadata.mcast_grp = 1;
    }

    table arp_exact {
        key = {
            hdr.arp.d_ip: lpm;
        }
        actions = {
            arp_answer;
            drop;
            NoAction;
        }

        size = 1024;
        //default_action = NoAction();
    }

/******************** Action da tabela arp_rp  ****************************/

    action arp_forward(egressSpec_t port){

        standard_metadata.egress_spec = port;

    }
    table arp_rp{
        key = {
            hdr.arp.d_ip: lpm;
        }
        actions = {
            arp_forward;
            drop;
            NoAction;
        }

    size = 1024;
    //default_action = NoAction();
    }

/******************** Action internos  ****************************/

    action new_icmp(bit<8> type, bit<8> code){
        hdr.ipv4.protocol = TYPE_IPV4_ICMP;
        hdr.ipv4.ttl = 38;
        hdr.icmp.setValid();
        hdr.icmp.type =  type;
        hdr.icmp.code =  code;

        hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;

        interface_ip.read(aux_ip, (bit<32>)standard_metadata.ingress_port);
        //interface_ip.read(aux_ip, (bit<32>) 1);        
        hdr.ipv4.srcAddr = aux_ip;
        //hdr.ipv4.srcAddr = 0xAABBFF33; // ip da interface de entrada
        
    }

    action subtrai_ttl(){

        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action Addr_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;

        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        //hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
            
    }


 
    apply {
        if (hdr.ipv4.isValid()) { // procedimentos para ipv4

            if (standard_metadata.checksum_error == 1){ 
                drop(); // 4.2.2.5 RFC 1812 
            
            }else if(ipv4_lpm.apply().hit){ // match na tabela ipv4_lpm

                if(PKT_TO_ROUTER == 0){ // 4.2.2.9 ip destino != do roteador
                    subtrai_ttl(); // Precisa verificar se o pkt é para o roteador antes de diminuir ttl
                    if(hdr.ipv4.ttl == 0){ // subtrai e depois verifica
                        new_icmp(11, 0x00); //gerar um icmp code 11 iniciar o ttl
                        forward.mac = hdr.ethernet.srcAddr;
                        forward.port = standard_metadata.ingress_port;
                    }
                    Addr_forward(forward.mac, forward.port);

                }else{ // ip destino é o roteador
                    if(hdr.icmp.isValid())  // icmp para o roteador
                        if(hdr.icmp.type == ICMP_ECHO_REQUEST){
                            icmp_forward();
                            icmp_ping();
                        } // }else if(hdr.icmp.type == ICMP_ECHO_REQUEST ){
                        //     ;
                        // } // continue
                    
                    // 4.3.2.1 icmp Tipos de mensagens desconhecidas  deve descartar o pacote
                }
            }else{   // sem match rota inacessível, devover icmp type 3, verificar  5.2.7.1 Destino Inacessíve

                ;
                
            }

        }else if(hdr.arp.isValid()){ // procedimentos arp
            if(hdr.arp.op == ARP_OPER_REQUEST){
                if(arp_exact.apply().miss){
                    // salva os dados do pacote???
                    multicast();
                }
            } else if(hdr.arp.op == ARP_OPER_REPLY){
               arp_rp.apply(); // pode vir erro e set my router for 1
            }

        }
        
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    

    action drop() {
        mark_to_drop(standard_metadata);
    }

    apply {
        // Não enviar pacote para porta em que o pacote entrou em  Multicast
        if (standard_metadata.egress_port == standard_metadata.ingress_port && standard_metadata.mcast_grp != 0)
            drop();
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
    


        update_checksum_with_payload( // verificar se pacote icmp foi alterado
            hdr.icmp.isValid(),
                { hdr.icmp.type,
                  hdr.icmp.code },
                hdr.icmp.checksum,
                HashAlgorithm.csum16);
     }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.payload);
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

 Fazer maquina de estado do parser no tcc
 Qual topologia?
 erro de checksum descarta o pacote // RFC 1812 item 4.2.2.5

IMPREMENTAR:
 - checksum verify
 - forwarding ipv6
 - Protocolo arp
 - icmp e icmpv6
 - broadcast
 - tamanho variado de pacote ip 

TESTAR:
 - ttl
 - checksum
 - forwanding 

NOTE
considero que o roteador conheçe quem fez o pedido de arp,
preciso implementar algo que salve o mac e ip facil de pesquisar 

*/

/*****************************  retalhos de código ************************************ 
***************************************************************************************/
/*



// header time_stamp_t {

//     bit<48> ingress_ts; // carimbo de data/hora, em microssegundos, definido quando o pacote aparece na entrada
//     bit<48> egress_ts; // um carimbo de data/hora, em microssegundos, definido quando o pacote inicia o processamento de saída,  lido no pipeline de saída
//     bit<32> enq_ts; // um carimbo de data/hora, em microssegundos, definido quando o pacote é enfileirado pela primeira vez.
//     bit<32> deq_ts; // deq_timedelta: o tempo, em microssegundos, que o pacote ficou na fila.

// }


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

        // if(!hdr.time.isValid()){ // cria um header no pacote com time

        //     hdr.time.setValid();

        //     hdr.time.ingress_ts = standard_metadata.ingress_global_timestamp;
        //     hdr.time.egress_ts = standard_metadata.egress_global_timestamp;
        //     hdr.time.enq_ts = standard_metadata.enq_timestamp;
        //     hdr.time.deq_ts = standard_metadata.deq_timedelta;

        // }

        //   meta.time.ingress_ts = standard_metadata.ingress_global_timestamp;
        // meta.time.egress_ts = standard_metadata.egress_global_timestamp;
        // meta.time.enq_ts = standard_metadata.enq_timestamp;
        // meta.time.deq_ts = standard_metadata.deq_timedelta;



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

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;

}


    // testes
    //register <bit<48>>(10) proxy_arp_mac; // para mac
    //register <bit<32>>(10) Proxy_arp_ip; // para ip
    //macAddr_t aux_reg;

    // testes
    //my_register.write(1,2); //index, value
    //my_register.read(aux_reg, 1); // value index

    
    // interface_mac.write(1,0x080000000100);
    // interface_mac.write(2,0x080000000300);
    // interface_mac.write(3,0x080000000400);

    // interface_ip.write(1,0x0A000B0A);
    // interface_ip.write(2,0x0A00210A);
    // interface_ip.write(3,0x0A002C0A);

*/