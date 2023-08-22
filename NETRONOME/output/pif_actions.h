/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_ACTIONS_H__
#define __PIF_ACTIONS_H__

/* Warning: generated file - your edits to this file may be lost */

/* Action operation IDs */

#define PIF_ACTION_ID_ingress__act_forward 0
#define PIF_ACTION_ID_MAX 0

/* Match action data structure */

__packed struct pif_action_actiondata_ingress__act_forward {
    uint32_t __pif_rule_no;
    uint32_t __pif_table_no;
    uint8_t __pif_padding[2]; /* padding */
    uint16_t port;
};

#endif /* __PIF_ACTIONS_H__ */
