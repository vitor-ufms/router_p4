/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#include <nfp.h>
#include <nfp/me.h>
#include <pkt/pkt.h>
#include <modscript/modscript.h>
#ifdef PKTIO_GRO_ENABLED
#include <gro.h>
#endif
#include "nfd_user_cfg.h"
#include "pif_common.h"
#include <pif_counters.h>

__forceinline extern int pif_deparse(__lmem uint32_t *parrep, PIF_PKT_INFO_TYPE struct pif_pkt_info *pktinfo)
{
    __gpr uint32_t pkt_byteoff = pif_pkt_info_spec.pkt_pl_off;
    __gpr uint32_t pkt_min_off;
    int ret;

    /* Packet minimum offset depends on packet destination - NBI/PCIe */
    pkt_min_off = PKTIO_MIN_NBI_TX_OFFSET; /* apply the nbi min to nfd too */

    pkt_byteoff = pktinfo->p_offset;

    /* If packet offset more than maximum allowed for NBI, return error */
    if (PKT_PORT_TYPE_of(pif_pkt_info_global.p_dst) == PKT_PTYPE_WIRE) {
        if (pkt_byteoff > PKTIO_MAX_NBI_TX_OFFSET) {
            uint32_t move_len = pkt_byteoff - PKTIO_MAX_NBI_TX_OFFSET;
            pif_pkt_move_pkt_up(pkt_byteoff, move_len);
            pkt_byteoff -= move_len;
            pktinfo->p_offset -= move_len;
            PIF_COUNT(OFFSET_TOO_LARGE_SHIFT);

        }
    } else {
#ifdef PKTIO_GRO_ENABLED
        if (pkt_byteoff > GRO_NFD_MAX_OFFSET) {
            uint32_t move_len = pkt_byteoff - GRO_NFD_MAX_OFFSET;
            pif_pkt_move_pkt_up(pkt_byteoff, move_len);
            pkt_byteoff -= move_len;
            pktinfo->p_offset -= move_len;
            PIF_COUNT(OFFSET_TOO_LARGE_SHIFT);

        }
#endif
    }
    if (pif_pkt_info_spec.trunc_len != 0 && pif_pkt_info_spec.trunc_len < pif_pkt_info_global.p_len)
        pif_pkt_info_global.p_len = pif_pkt_info_spec.trunc_len;

    return pkt_byteoff;
}
