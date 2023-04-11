# This file should be ran to initialize the script.
# Should use interactive mode to view results of debug callbacks
# command: ./run_bfshell.sh -b [path_to_this_file] -i

from ipaddress import ip_address

### Teardown and Setup Aurora Switch 710 Ports ###

# Delete if port open currently
for qsfp_cage in range (1,12):
    for lane in range (0, 1):
        dp = bfrt.port.port_hdl_info.get(CONN_ID=qsfp_cage, CHNL_ID=lane, print_ents=False).data[b'$DEV_PORT']
        bfrt.port.port.delete(DEV_PORT=dp)

# Add ports at 10G
for qsfp_cage in range (1, 4):
    for lane in range (0, 1):
        dp = bfrt.port.port_hdl_info.get(CONN_ID=qsfp_cage, CHNL_ID=lane, print_ents=False).data[b'$DEV_PORT']
        bfrt.port.port.add(DEV_PORT=dp, SPEED="BF_SPEED_40G", FEC="BF_FEC_TYP_NONE", AUTO_NEGOTIATION="PM_AN_FORCE_DISABLE", PORT_ENABLE=True)

### Initialize Match-Action IP Forwarding Table ###
p4 = bfrt.bundle_translator.pipe
ipv4_host = p4.Ingress.ipv4_host

#Eta                                                            (cage#/lane#)
ipv4_host.add_with_send(dst_addr=ip_address('10.10.10.100'), port=132) #1/0
#Rho
ipv4_host.add_with_send(dst_addr=ip_address('10.10.10.1'), port=140) #2/0

# Final programming
print("""******************* PROGRAMMING RESULTS *****************""")
print ("Table ipv4_host:")
ipv4_host.dump(table=True)

### Learning Digest Debugging ###

# Debug callback function
def print_debug(dev_id, pipe_id, direction, parser_id, session, msg):
    from datetime import datetime;

    for digest in msg:
        print("Digest (", datetime.now(), "):")
        for k, v in digest.items():
            print("\t", k, ":", hex(v))
        print()
    
    return 0

# Register the callback function
p4.IngressDeparser.debug_digest.callback_register(print_debug)
