/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PARREP_H__
#define __PIF_PARREP_H__

/* Generated C source defining layout of parsed representation */
/* Warning: your edits to this file may be lost */

/*
 * Parsed representation control data
 */
struct pif_parrep_ctldata {
    unsigned int valid:1;
};

#define PIF_PARREP_CTLDATA_OFF_LW 0
#define PIF_PARREP_CTLDATA_LEN_LW 1

/*
 * Parsed representation layout
 */

/* Parsed represention tier types */

/* Parse state values */
#define PIF_PARREP_STATE_exit -1
#define PIF_PARREP_STATE_start 0
#define PIF_PARREP_MAX_STATE 0

/*
 * Metadata
 */

#define PIF_PARREP_standard_metadata_OFF_LW 1
#define PIF_PARREP_standard_metadata_LEN_LW 4

#define PIF_PARREP_LEN_LW 5

/* Parsing branches to a constant control entry point */
#define PIF_PARREP_NO_VARIABLE_EXIT

/* Control data macros */
#define PIF_PARREP_VALID(_ctl) (_ctl->valid)
#define PIF_PARREP_SET_VALID(_ctl) \
    do { _ctl->valid = 1; } while (0)



void pif_value_set_scan_configs();

#endif /* __PIF_PARREP_H__ */
