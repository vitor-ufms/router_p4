/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_HEADERS_H__
#define __PIF_HEADERS_H__

/* Generated C source defining PIF headers, metadata and registers */
/* Warning: your edits to this file may be lost */

/*
 * Packet headers
 */

/*
 * Metadata
 */

/* standard_metadata (16B) */
struct pif_header_standard_metadata {
    unsigned int clone_spec:32;
    unsigned int egress_spec:16;
    unsigned int egress_port:16;
    unsigned int ingress_port:16;
    unsigned int packet_length:14;
    unsigned int checksum_error:1;
    unsigned int _padding_0:1;
    unsigned int egress_instance:10;
    unsigned int parser_error_location:8;
    unsigned int instance_type:4;
    unsigned int parser_status:3;
    unsigned int _padding_1:7;
};

/* standard_metadata field accessor macros */
#define PIF_HEADER_GET_standard_metadata___clone_spec(_hdr_p) (((_hdr_p)->clone_spec)) /* standard_metadata.clone_spec [32;0] */

#define PIF_HEADER_SET_standard_metadata___clone_spec(_hdr_p, _val) \
    do { \
        (_hdr_p)->clone_spec = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.clone_spec[32;0] */

#define PIF_HEADER_GET_standard_metadata___egress_spec(_hdr_p) (((_hdr_p)->egress_spec)) /* standard_metadata.egress_spec [16;0] */

#define PIF_HEADER_SET_standard_metadata___egress_spec(_hdr_p, _val) \
    do { \
        (_hdr_p)->egress_spec = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.egress_spec[16;0] */

#define PIF_HEADER_GET_standard_metadata___egress_port(_hdr_p) (((_hdr_p)->egress_port)) /* standard_metadata.egress_port [16;0] */

#define PIF_HEADER_SET_standard_metadata___egress_port(_hdr_p, _val) \
    do { \
        (_hdr_p)->egress_port = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.egress_port[16;0] */

#define PIF_HEADER_GET_standard_metadata___ingress_port(_hdr_p) (((_hdr_p)->ingress_port)) /* standard_metadata.ingress_port [16;0] */

#define PIF_HEADER_SET_standard_metadata___ingress_port(_hdr_p, _val) \
    do { \
        (_hdr_p)->ingress_port = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.ingress_port[16;0] */

#define PIF_HEADER_GET_standard_metadata___packet_length(_hdr_p) (((_hdr_p)->packet_length)) /* standard_metadata.packet_length [14;0] */

#define PIF_HEADER_SET_standard_metadata___packet_length(_hdr_p, _val) \
    do { \
        (_hdr_p)->packet_length = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.packet_length[14;0] */

#define PIF_HEADER_GET_standard_metadata___checksum_error(_hdr_p) (((_hdr_p)->checksum_error)) /* standard_metadata.checksum_error [1;0] */

#define PIF_HEADER_SET_standard_metadata___checksum_error(_hdr_p, _val) \
    do { \
        (_hdr_p)->checksum_error = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.checksum_error[1;0] */

#define PIF_HEADER_GET_standard_metadata____padding_0(_hdr_p) (((_hdr_p)->_padding_0)) /* standard_metadata._padding_0 [1;0] */

#define PIF_HEADER_SET_standard_metadata____padding_0(_hdr_p, _val) \
    do { \
        (_hdr_p)->_padding_0 = (unsigned)(((_val))); \
    } while (0) /* standard_metadata._padding_0[1;0] */

#define PIF_HEADER_GET_standard_metadata___egress_instance(_hdr_p) (((_hdr_p)->egress_instance)) /* standard_metadata.egress_instance [10;0] */

#define PIF_HEADER_SET_standard_metadata___egress_instance(_hdr_p, _val) \
    do { \
        (_hdr_p)->egress_instance = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.egress_instance[10;0] */

#define PIF_HEADER_GET_standard_metadata___parser_error_location(_hdr_p) (((_hdr_p)->parser_error_location)) /* standard_metadata.parser_error_location [8;0] */

#define PIF_HEADER_SET_standard_metadata___parser_error_location(_hdr_p, _val) \
    do { \
        (_hdr_p)->parser_error_location = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.parser_error_location[8;0] */

#define PIF_HEADER_GET_standard_metadata___instance_type(_hdr_p) (((_hdr_p)->instance_type)) /* standard_metadata.instance_type [4;0] */

#define PIF_HEADER_SET_standard_metadata___instance_type(_hdr_p, _val) \
    do { \
        (_hdr_p)->instance_type = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.instance_type[4;0] */

#define PIF_HEADER_GET_standard_metadata___parser_status(_hdr_p) (((_hdr_p)->parser_status)) /* standard_metadata.parser_status [3;0] */

#define PIF_HEADER_SET_standard_metadata___parser_status(_hdr_p, _val) \
    do { \
        (_hdr_p)->parser_status = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.parser_status[3;0] */

#define PIF_HEADER_GET_standard_metadata____padding_1(_hdr_p) (((_hdr_p)->_padding_1)) /* standard_metadata._padding_1 [7;0] */

#define PIF_HEADER_SET_standard_metadata____padding_1(_hdr_p, _val) \
    do { \
        (_hdr_p)->_padding_1 = (unsigned)(((_val))); \
    } while (0) /* standard_metadata._padding_1[7;0] */



/*
 * Registers
 */

#endif /* __PIF_HEADERS_H__ */
