#!/bin/bash

FILE="bypass"

DIR=$(pwd)
NUM_VFS=4
LOG_FILE_RUN=$DIR/out_load #output from this run
LOG_FILE_MAIN=/var/log/nfp-sdk6-rte.log
FIRMWARE_FILE=$DIR/output/firmware.nffw #path to firmware
DESIGN_FILE=$DIR/output/pif_design.json #path to design
CONFIG_FILE=$DIR/$FILE.p4cfg #path to config

#restart services
sudo systemctl stop nfp-sdk6-rte
sudo systemctl stop nfp-hwdbg-srv

#unload old firmware
sudo /opt/netronome/bin/nfp-nffw unload
sudo pkill pif_rte

#load firmware and rules to card
pushd /opt/nfp_pif/bin/ > /dev/null
        sudo NUM_VFS=${NUM_VFS} ./pif_rte -n 0 -p 20206 -I -z \
        -s /opt/nfp_pif/scripts/pif_ctl_nfd.sh \
        -f $FIRMWARE_FILE -d $DESIGN_FILE -c $CONFIG_FILE \
        --log_file $LOG_FILE_MAIN > $LOG_FILE_RUN &
popd > /dev/null
