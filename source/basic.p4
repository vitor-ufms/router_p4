/* -*- P4_16 -*- */

  
#include <core.p4>
#include <v1model.p4>
#define CPU_PORT 510

const bit<32> MAX_INTERFACE = 10;
 
const bit<16> TYPE_IPV4 = 0x800;
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
const bit<8> ICMP_DESTINATION_UNREACHABLE = 0X03;

const bit<8> TYPE_IPV4_UDP   = 0x11;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

@controller_header("packet_out")
header packet_out_header_t {
    bit<8>   opcode;
    bit<32> operand0;
    bit<32> operand1;
    bit<32> operand2;
}

@controller_header("packet_in")
header packet_in_header_t {
    bit<8>   opcode;
    bit<32> operand0;
    bit<48> operand1;
    bit<48> operand2;
}

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

header icmp_un_t{ 
    bit<32> Unused;
}

header header_8_t{
    bit<64> data;
}

header payload_t{

    varbit<524120> data_ip; // tamanho máximo de um payload ip  2^16-1 = 65535 - 20 = 65515 bytes = 524120 bits
}

struct temp_t {
    egressSpec_t  port_dst; // encaminhamento
    ip4Addr_t     ip_dst; // encaminhamento

    macAddr_t     mac_dst; //arp
    macAddr_t     mac_src; // arp

    ip4Addr_t     ip_ingress; // pre
    macAddr_t     mac_ingress; // pre

   // ip4Addr_t     ip_scr;
}

struct metadata {
    //@field_list(1)
    header_8_t   header_8;
    temp_t       forward_temp;
    bit<1>       pkt_to_router;
    bit<4>       encaminhamento;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    arp_t        arp;
    icmp_t       icmp;
    icmp_un_t    icmp_un;
    ipv4_t       icmp_ip_header;
    header_8_t   header_8;
    payload_t    payload;
    packet_in_header_t  packet_in;
    packet_out_header_t packet_out;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    // state start {
    //     transition parse_ethernet;
    // }

    state start {
        transition check_cpu;
    }
    state check_cpu{
        transition select(standard_metadata.ingress_port){
            CPU_PORT : parse_controller;
            default : parse_ethernet;
        }
    }
    
    state parse_controller{
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet { // ethernet
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 { // ipv4
        packet.extract(hdr.ipv4);

        meta.header_8.setValid();
        meta.header_8.data = packet.lookahead<bit<64>>(); // leitura do 8 primeiros bytes do paylod do ipv4

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
        // considera tamanho fixo de cabeçalho ip
        packet.extract(hdr.payload, (bit<32>) ((hdr.ipv4.totalLen - 20) * 8));       
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

    register<bit<64>>(4) controller_op; // registrador que conversa com o plano de controle
    // 0 - flag; 1 - ip; 2 - mac; 3 - port

    action drop() {
        mark_to_drop(standard_metadata);
    }

    //action NoAction() {;}

/******************** Action for table  ipv4_lpm  ****************************/

    action ipv4_forward(egressSpec_t port, ip4Addr_t ip_dst, bit<32> metric) {
        meta.forward_temp.port_dst = port;
        meta.forward_temp.ip_dst = ip_dst;
        //meta.forward_temp.mac_src = scrAddr;
        //meta.forward_temp.mac_dst = dstAddr;
    }

    action my_router( ){
        meta.pkt_to_router = 1;
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
      //  default_action = NoAction(); drop(); // default enviar para rota default
    }


/******************** Action for table arp_exact  ****************************/

    action arp_answer(macAddr_t addr) {

        standard_metadata.egress_spec = standard_metadata.ingress_port;

        //Ethernet
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = addr; // mac do roteador

        // ARP
        hdr.arp.op = ARP_OPER_REPLY;
       
        // troca de ip
        ip4Addr_t send_ip = hdr.arp.s_ip;
        hdr.arp.s_ip = hdr.arp.d_ip; 
        hdr.arp.d_ip = send_ip;

        // mac no arp
        hdr.arp.d_Add = hdr.arp.s_Add;
        hdr.arp.s_Add = addr;
    }

    action arp_query(macAddr_t srcAddr, macAddr_t dstAddr){

        meta.forward_temp.mac_src = srcAddr;
        meta.forward_temp.mac_dst = dstAddr;

        standard_metadata.egress_spec = meta.forward_temp.port_dst;
        hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.dstAddr = dstAddr;
    
    }

    table arp_exact { // ipd => mac
        key = {
            meta.forward_temp.ip_dst: lpm;
        }
        actions = {
            arp_query;
            drop;
            NoAction;
        }
        size = 1024;
        //default_action = NoAction();
    }

/********************** pre proc ************************************/
    action set_temp(macAddr_t mac_ingress,ip4Addr_t ip_ingress ){
        meta.forward_temp.ip_ingress = ip_ingress;
        meta.forward_temp.mac_ingress = mac_ingress;
    }

    table pre_proc {
        key = {
           standard_metadata.ingress_port : exact;
        }
        actions = {
            set_temp;
            drop;
            NoAction;
        }
        size = 10;
        //default_action = NoAction();
    }

/******************** Action internos  ****************************/
/******** Procedimentos para ICMP *****************/

    action icmp_ping(){ // respondendo ping

        hdr.icmp.type = ICMP_ECHO_REPLY;
        ip4Addr_t srcAddr_ipv4 = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = srcAddr_ipv4;         
    }

    action new_icmp(bit<8> type, bit<8> code){
        
       // hdr.header_8.setValid();
        hdr.payload.setInvalid();
        hdr.icmp.setValid();
        hdr.icmp.type =  type;
        hdr.icmp.code =  code;

        hdr.icmp_un.setValid(); // ?
        hdr.icmp_un.Unused = 0x00;

        hdr.icmp_ip_header.setValid();
        hdr.icmp_ip_header = hdr.ipv4; // copia cabeçalho ipv4

        hdr.ipv4.ttl = 64; //4.3.2.2 deve originar um novo ttl
        hdr.ipv4.totalLen = 56; // 20 + 20 + 4 + 4 + 8
        hdr.ipv4.protocol = TYPE_IPV4_ICMP;
        hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;

        hdr.ipv4.srcAddr = meta.forward_temp.ip_ingress;
       
    }

    action subtrai_ttl(){ 
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // action conf_forward(egressSpec_t port, macAddr_t srcAddr, macAddr_t dstAddr) {
    //     standard_metadata.egress_spec = port;

    //     hdr.ethernet.srcAddr = srcAddr;
    //     hdr.ethernet.dstAddr = dstAddr;
    //     //hdr.ipv4.ttl = hdr.ipv4.ttl - 1;            
    // } 

    apply {  

        // verify if pakcet is controller
        // if(standard_metadata.ingress_port == CPU_PORT){
        //     controller_op.write(0, 11); // send a signal for the controller
        // }  
        // if(hdr.packet_out.isValid()){
        //     controller_op.write(0, 11); // send a signal for the controller
        // }     

        pre_proc.apply(); 

        // procedimentos para ipv4
        if (hdr.ipv4.isValid()) { 
            // direcionar a porta para o multicast de envios do rip
            if(standard_metadata.ingress_port == CPU_PORT && hdr.packet_out.opcode == 1){               
                standard_metadata.egress_spec = (bit<9>) hdr.packet_out.operand0;
                meta.encaminhamento = 0;
            }else if (standard_metadata.checksum_error == 1){ 
                drop(); // 4.2.2.5 RFC 1812 
            
            }else if(ipv4_lpm.apply().hit){ // match na tabela ipv4_lpm

                if(meta.pkt_to_router == 0){ // 4.2.2.9 ip destino != do roteador
                   
                    if((hdr.ipv4.ttl -1) == 0){ // subtrai e depois verifica
                        new_icmp(ICMP_TIME_EXCEEDED, 0x00); //gerar um icmp code 11 iniciar o ttl
                        
                        
                        //standard_metadata.egress_spec = standard_metadata.ingress_port;
                        //hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
                        //hdr.ethernet.srcAddr = meta.forward_temp.mac_ingress;                      
                        
                        meta.encaminhamento = 2;
                        hdr.header_8.setValid();
                        hdr.header_8.data = meta.header_8.data;

                       // resubmit_preserving_field_list(1);

                    }else{
                        subtrai_ttl(); // Precisa verificar se o pkt é para o roteador antes de diminuir ttl
                        //conf_forward(meta.forward_temp.port_dst, meta.forward_temp.mac_src, meta.forward_temp.mac_dst); // Forwarding normal
                        meta.encaminhamento = 1;
                        // problema se não tiver mac para o endereço ip
                    }

                }else{ // ip destino é o roteador

                    if(hdr.icmp.isValid()){  // icmp para o roteador
                        if(hdr.icmp.type == ICMP_ECHO_REQUEST){
                            //meta.forward_temp.port_dst = standard_metadata.ingress_port;
                            //meta.forward_temp.mac_dst = hdr.ethernet.srcAddr;
                            //conf_forward(meta.forward_temp.port_dst, meta.forward_temp.mac_src, meta.forward_temp.mac_dst);
                            standard_metadata.egress_spec = standard_metadata.ingress_port;
                            hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
                            hdr.ethernet.srcAddr = meta.forward_temp.mac_ingress;

                            meta.encaminhamento = 0 ;
                            icmp_ping();

                        }else if(hdr.icmp.type == ICMP_ECHO_REPLY ){
                             ;
                        }else{
                            drop(); // ICMP 4.3.2.1 Tipos de mensagens desconhecidas, descarta o pacote 
                        }
                    }
                }
            }else{   

                if(hdr.ipv4.dstAddr == 0xE0000009 && hdr.ipv4.protocol == TYPE_IPV4_UDP  ){ // 224.0.0.9 multicast, pode ser rip

                    standard_metadata.egress_spec = CPU_PORT;
                    meta.pkt_to_router = 1;

                    hdr.packet_in.setValid();
                    hdr.packet_in.opcode = 3;
                    hdr.packet_in.operand0 = (bit<32>) hdr.ipv4.srcAddr; 
                    hdr.packet_in.operand1 =  (bit<48>) meta.forward_temp.ip_ingress;
                    hdr.packet_in.operand2 = (bit<48>) standard_metadata.ingress_port;
                    

                }else{ // sem match rota inacessível, devover icmp type 3, verificar  5.2.7.1 Destino Inacessíve

                    new_icmp(ICMP_DESTINATION_UNREACHABLE, 0x00); //gerar um icmp code 11 iniciar o ttl
                    standard_metadata.egress_spec = standard_metadata.ingress_port;
                    hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
                    hdr.ethernet.srcAddr = meta.forward_temp.mac_ingress;
                    
                    meta.encaminhamento = 0;
                    hdr.header_8.setValid();
                    hdr.header_8.data = meta.header_8.data;
                }
                
            }  
        }

        /// chamar tabela arp 
        if( meta.encaminhamento == 1 && meta.pkt_to_router == 0 ){
            if(arp_exact.apply().miss){// configura o mac 
                // ip sem mac, chamar controlador
                
                controller_op.write(0, 1); // send a signal for the controller
                hdr.packet_in.setValid();
                hdr.packet_in.opcode = 1;
                hdr.packet_in.operand0 = (bit<32>) meta.forward_temp.port_dst; 
                hdr.packet_in.operand1 =  (bit<48>) meta.forward_temp.ip_dst;

                standard_metadata.egress_spec = CPU_PORT; // pacote vai para o controlador para ser salvo
                //drop();
            }
        }

        // procedimentos arp
        if(hdr.arp.isValid()){ 
            if(hdr.arp.op == ARP_OPER_REQUEST){
                if(hdr.arp.d_ip == meta.forward_temp.ip_ingress) // request para o roteador na porta certa
                    arp_answer(meta.forward_temp.mac_ingress); 
                if(standard_metadata.ingress_port == CPU_PORT){   // roteador fez o request no plano de controle
                    // tudo pronto, só mandar na porta certa
                    standard_metadata.egress_spec = (bit<9>) hdr.packet_out.operand0;
                    controller_op.write(0, 12); // send a signal for the controller, só para teste
                }
            } else if(hdr.arp.op == ARP_OPER_REPLY){  
                if(hdr.arp.d_ip == meta.forward_temp.ip_ingress ){ // meu ip, reply para o roteador
                    hdr.packet_in.setValid();
                    hdr.packet_in.opcode = 2;
                    hdr.packet_in.operand0 = (bit<32>) hdr.arp.s_ip; // ip que enviou
                    hdr.packet_in.operand1 = hdr.arp.s_Add; // mac send
                    hdr.packet_in.operand2 = hdr.arp.d_Add; // mac dst
                   
                    controller_op.write(0, 2); // send a signal for the controller
                    standard_metadata.egress_spec = CPU_PORT;
                    //drop();
                }
            }

        }


        // send packet for controller
        // hdr.packet_in.isValid();
        // hdr.packet_in.opcode = 0xFFFF;
        // hdr.packet_in.operand0 = 7;
        // hdr.packet_in.operand1 = 1;

        // send packet for controller
        // hdr.packet_out.isValid();
        // hdr.packet_out.opcode = 0;
        // hdr.packet_out.operand0 = 360;
        // hdr.packet_out.operand1 = 8;
        
        //if(standard_metadata.ingress_port != CPU_PORT)
        //hdr.ethernet.dstAddr = 0xFF00FFFF0000;
       // hdr.ethernet.srcAddr = 0xFF0000FFFFFF;
        //standard_metadata.egress_spec = CPU_PORT;

    }// apply
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

     apply {

        if( meta.encaminhamento == 2){
            recirculate_preserving_field_list(0);
        }

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

            update_checksum_with_payload( // verificar se pacote icmp foi alterado
                hdr.icmp_un.isValid(),
                    { hdr.icmp.type,
                    hdr.icmp.code, hdr.icmp_un, hdr.icmp_ip_header, hdr.header_8 },
                    hdr.icmp.checksum,
                    HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.icmp_un);
        packet.emit(hdr.icmp_ip_header);
        packet.emit(hdr.header_8);
        packet.emit(hdr.payload);
       // packet.emit(hdr.packet_in);
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
