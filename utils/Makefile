BUILD_DIR = build
PCAP_DIR = pcaps
LOG_DIR = logs

P4C = p4c-bm2-ss
P4C_ARGS += --p4runtime-files $(BUILD_DIR)/$(basename $@).p4.p4info.txt
# P4C_ARGS += --p4runtime-files build/basic.p4.p4info.txt

RUN_SCRIPT = ../utils/run_exercise.py

ifndef TOPO
TOPO = topology.json
endif

source = $(wildcard *.p4) # basic.p4
compiled_json := $(source:.p4=.json) # basic.p4 > basic.json

ifndef DEFAULT_PROG
DEFAULT_PROG = $(wildcard *.p4) #basic.p4
#basci.p4
endif
DEFAULT_JSON = $(BUILD_DIR)/$(DEFAULT_PROG:.p4=.json)
#build/basic.json

# Define NO_P4 to start BMv2 without a program
ifndef NO_P4
run_args += -j $(DEFAULT_JSON)
# run_args += -j build/basic.json
endif

# Set BMV2_SWITCH_EXE to override the BMv2 target
ifdef BMV2_SWITCH_EXE
run_args += -b $(BMV2_SWITCH_EXE)
# run_args += -b simple_switch_grpc  
endif

all: run

run: build  
	sudo python3 $(RUN_SCRIPT) -t $(TOPO) $(run_args)
#sudo python 3 ../utils/run_exercise.py -t TOPOLOGIAS/s1-h1-h2-h3-h4/topology.json 
# -j build/basic.json -b simple_switch_grpc

stop:
	sudo mn -c

build: dirs $(compiled_json)

%.json: %.p4
	$(P4C) --p4v 16 $(P4C_ARGS) -o $(BUILD_DIR)/$@ $<
# p4c-bm2-ss --p4v 16 --p4runtime-files build/basic.p4.p4info.txt -o build
dirs:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

clean: stop
	rm -f *.pcap
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)
