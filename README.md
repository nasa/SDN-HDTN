# SDN-HDTN
This program is to be deployed on a P4-programmable switch as a middlebox in a DTN network to translate between bundle protocol version 6 and version 7.
This is a proof of concept and is not production ready; it requires significant improvements or must be finetuned for a specific application.

This P4 program was designed for the following environment:
- Intel Tofino Native Architecture (TNA)
- Original Tofino ASIC
- Netberg Aurora 710 Programmable Switch
- Intel P4 Studio SDE version 9.7.0
- Hosts are using Interplanetary Overlay Network (ION) v4.1.1 implementation of DTN, sending messages with bpchat program

## Contents:
- setup.py: Control plane initialization script (sets up physical switch ports, IP match-action tables and debug digests)
- bundle_translator.p4: Main p4 file, creates pipeline and includes the following files
- headers.p4: Declaration of all expected protocol headers
- bundle_headers.p4: Declaration of bundle protocol related headers
- parse_v6.p4: Parser states for parsing BPv6
- parse_v7.p4: Parser states for parsing BPv7
- control_v6.p4: Control logic for ingested BPv6 bundles
- control_v7.p4: Control logic for ingested BPv7 bundles
- host_configs/
  - node1_config.rc: Example configuration file for a DTN host running ION
  - node2_config.rc: Example configuration file for a DTN host running ION
## Ways to debug/test:
- Use tcpdump to capture packets on the end-devices (ex: sudo tcpdump -i any port 4556 -w test1.pcap). Can see if fields were modified correctly.
- Modify p4 program and manipulate what is sent in debug digest messages (messages from data plane to control plane), view output messages for each packet in control plane

## Build process (assuming SDE environment is setup):
cd $SDE
./p4_build.sh [path to bundle_translator.p4]

## To run the program:
Step 1) Open a new shell and start the user-space driver process to interact with the switch:
$SDE/run_switchd.sh -p bundle_translator

Step 2) Open a new shell and run the control-plane initialization scripts, keeping interactive mode up to view the debug digest messages
$SDE/run_bfshell.sh -b [path to setup.py] -i

Step 3) From shell in step 1, check the switch ports to verify all ports are up and enabled
ucli     // Enter micro CLI
pm show  // View ports
        If the setup script fails to initialize the switch ports, use micro CLI to reset the port manually:
pm show                 // View ports 
port-del 1/0            // Delete cage 1/lane 0
port-add 1/0 40g none   // Add cage 1/lane 0, 40G speed, no FEC
port-enb 1/0            // Enable cage 1/lane 0
pm show                 // View ports (may have to wait to see changes)

Step 4) Send packets between hosts connected via the switch. Use CTRL+\ to stop the switch processes.

To get ION working on Linux-based end-hosts:

Step 1) Download tar file from https://sourceforge.net/projects/ion-dtn/files/ion-open-source-4.1.1.tar.gz/download

Step 2) Extract
tar -xzvf ion-open-source-4.1.1.tar.gz

Step 3) Enter extract folder
cd ion-open-source-4.1.1.tar.gz

Step 4) Configure the installation
./configure                   // for BPv7
./configure --enable-bpv6     // for BPv6

Step 5) Compile ION
make

Step 6) Install ION
sudo make install

Step 7) Start ION with an ION configuration file
sudo ionstart -I [path to configuration file]

Step 8) Run BP chat program
sudo bpchat ipn:[??].[??] ipn:[??].[??]

Step 9) Send messages and then terminate bpchat program with CTRL+C

Step 10) Terminate ION processes
sudo killm
killm



