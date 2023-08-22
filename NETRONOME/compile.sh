#!/bin/bash

FILE="bypass"
#FILE="fw"
#FILE="fwd"

C_FILE="./"$FILE".c"
P4_FILE="./"$FILE".p4"
OUTPUT="output/firmware.nffw"
MODEL="beryllium"
INCLUDE_DIR="/opt/netronome/p4/include/16/p4include/"


### Com C file
#/opt/netronome/p4/bin/nfp4build -o ${OUTPUT} -l ${MODEL} --nfp4c_I ${INCLUDE_DIR} --nfp4c_p4_version 16 -4 ${P4_FILE} -c ${C_FILE}
#/opt/netronome/p4/bin/nfp4build -I /usr/include -o $OUTPUT -l $MODEL -c ${C_FILE} -4 ${P4_FILE}
#/opt/netronome/p4/bin/nfp4build --verbose-generate --verbose-build -o ${OUTPUT} -l ${MODEL} -c ${C_FILE} --nfp4c_I ${INCLUDE_DIR} --nfp4c_p4_version 16 -4 ${P4_FILE}

### Sem C file
/opt/netronome/p4/bin/nfp4build -o ${OUTPUT} -l ${MODEL} --nfp4c_I ${INCLUDE_DIR} --nfp4c_p4_version 16 -4 ${P4_FILE}
#/opt/netronome/p4/bin/nfp4build -I /usr/include -o ${OUTPUT} -l ${MODEL} --nfp4c_I ${INCLUDE_DIR} --nfp4c_p4_version 16 -4 ${P4_FILE}
