// Dominick Ta, Stephanie Booth, Rachel Dudukovich
// NASA Glenn Research Center, Cleveland, OH
// Note this file has been editted from BAREFOOT's original

#ifndef _HEADERS_
#define _HEADERS_

#include "bundle_headers.p4"

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;

const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const bit<3> DIGEST_TYPE_DEBUG = 0x1;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

// Note: Order of declaration of matters for this struct!
// - Headers are deparsed/emitted in order of declaration
// - Invalid headers are not emitted
struct headers_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    udp_h udp;
    
	// V6 Headers
    bpv6_primary_cbhe_h bpv6_primary_cbhe;
    bpv6_extension_phib_h bpv6_extension_phib;
    bpv6_extension_age_h bpv6_extension_age;
    bpv6_payload_h bpv6_payload;

	// V7 Headers
	bpv7_start_code_h bpv7_start_code;
	bpv7_primary_1_h bpv7_primary_1;
	bpv7_primary_2_1_h bpv7_primary_2_1;
	bpv7_primary_2_2_h bpv7_primary_2_2;
	bpv7_primary_2_4_h bpv7_primary_2_4;
	bpv7_primary_2_8_h bpv7_primary_2_8;
	bpv7_primary_3_h bpv7_primary_3;
	bpv7_extension_prev_node_h bpv7_extension_prev_node;
	bpv7_extension_ecos_h bpv7_extension_ecos;
	bpv7_extension_age_h bpv7_extension_age;
	bpv7_payload_h bpv7_payload;

	// Application Data Unit (ADU) Headers for v6 and v7
	adu_1_h adu_1;
	adu_2_h adu_2;
	adu_3_h adu_3;
	adu_4_h adu_4;
	adu_5_h adu_5;
	adu_6_h adu_6;
	adu_7_h adu_7;
	adu_8_h adu_8;
	adu_9_h adu_9;
	adu_10_h adu_10;
	adu_11_h adu_11;
	adu_12_h adu_12;
	adu_13_h adu_13;

	// Stop Code for V7
	bpv7_stop_code_h bpv7_stop_code;
}

// Can freely change this, only used for capturing information we care about for debugging
// Maximum allowed data in a digest is 47 bytes
struct debug_digest_t {
	bit<8> hdr_version_num;
	
    bit<8> initial_byte;
    bit<8> block_type;
    bit<8> block_num;
    bit<8> block_flags;
    bit<8> crc_type;
    bit<8> block_data_initial_byte;
    bit<8> bundle_age;
}

struct metadata_headers_t {
    bool checksum_upd_ipv4; // True if IPv4 checksum should be updated 
    bool checksum_upd_udp; // True if UDP checksum should be updated
	bool checksum_err_ipv4_igprs; // True if IPv4 checksum was correct

	bool incomingV7; // True if a BPv7 bundle was ingested
	bool incomingV6; // True if a BPv6 bundle was ingested

	debug_digest_t debug_metadata; // Used to bridge debug info from ingress match-action stage to ingress deparser
}

#endif /* _HEADERS_ */
