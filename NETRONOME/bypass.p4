#include <core.p4>
#include <v1model.p4>

struct metadata {
}

struct headers {
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
        state start {
                transition accept;
        }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
        apply {

        }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
        action act_forward(bit<16> port) {
                standard_metadata.egress_spec = port;
        }

        table tbl_direction {
                actions = {
                        act_forward;
                }
                key = {
                        standard_metadata.ingress_port : exact;
                }
        }

        apply {
                tbl_direction.apply();
        }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
        apply {

        }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
        apply {

        }
}

control DeparserImpl(packet_out packet, in headers hdr) {
        apply {

        }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
