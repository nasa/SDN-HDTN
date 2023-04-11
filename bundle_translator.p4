//p4_16
// Dominick Ta, Stephanie Booth, Rachel Dudukovich
// NASA Glenn Research Center, Cleveland, OH

// Bundle Protocol Translator
// Translates incoming bundles from BPv6 to BPv7 and vice versa (with limitations)

// Ingress Parser extracts data from bundles into P4 data types
// Ingress Match-action/control logic converts into translated data types (and sets up forwarding logic)
// Ingress Deparser sends out the new version onto the wire
// Egress doesn't do anything special, but can be used in future if needed

#include <core.p4>
#include <tna.p4>

#include "headers.p4"

/***    INGRESS PROCESSING   ***/

/***    Ingress Parser   ***/
parser IngressParser(packet_in                 pkt, 
		     out headers_t                     hdr, 
		     out metadata_headers_t            meta,
		     out ingress_intrinsic_metadata_t  ig_intr_md)
{
	Checksum() ipv4_checksum;
	
	// Required for TNA
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

	// Required for TNA
    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }

	// Required for TNA
    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

	state parse_ethernet {
		pkt.extract(hdr.ethernet);
		transition select(hdr.ethernet.ether_type) {
			ETHERTYPE_IPV4: parse_ipv4;
			// should support more ethertypes
			default: accept;
		}
	}

	state parse_ipv4 {
		pkt.extract(hdr.ipv4);
		ipv4_checksum.add(hdr.ipv4);
		meta.checksum_err_ipv4_igprs = ipv4_checksum.verify(); // Currently not doing anything with this

		transition select(hdr.ipv4.protocol) {
			8w0x11: parse_udp;
			// should support more transport protocols
			default: accept;
		}
	}

	state parse_udp {  
		pkt.extract(hdr.udp);

		transition parse_version;
	}

	state parse_version {
		bit<8> start_byte = pkt.lookahead<bit<8>>();

		transition select(start_byte) {
			0x06: parse_v6;
			0x9f: parse_v7;
			default: accept;
		}
	}
	
	#include "parse_v6.p4"
	#include "parse_v7.p4"
}

/***    Ingress Match-Action   ***/
control Ingress(inout headers_t                          hdr,
		inout metadata_headers_t                         meta,
		in ingress_intrinsic_metadata_t                  ig_intr_md,
		in ingress_intrinsic_metadata_from_parser_t      ig_prsr_md,
		inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
		inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
	action checksum_upd_ipv4(bool update) {
		meta.checksum_upd_ipv4 = update;
	}

	action checksum_upd_udp(bool update) {
		meta.checksum_upd_udp = update;
	}
	
	action send(PortId_t port) {
		ig_tm_md.ucast_egress_port = port; // egress port for unicast packets. must be presented to TM for unicast
		#ifdef BYPASS_EGRESS
			ig_tm_md.bypass_egress = 1; // request flag for the warp mode (egress bypass)
		#endif
	}

	action drop() {
		ig_dprsr_md.drop_ctl = 1; // disable packet replication --bit 1 disables copy-to-cpu
	}

	table ipv4_host {
		key = {
			hdr.ipv4.dst_addr : exact; // Match IP addresses exactly (not LPM)
		}

		actions = { 
			send; 
			drop;
			#ifdef ONE_STAGE
				@defaultonly NoAction;
			#endif
		}

	#ifdef ONE_STAGE
		const default_action = NoAction();
	#endif

		size = 65536;
	}
	
	apply {
		ig_dprsr_md.digest_type = DIGEST_TYPE_DEBUG; // Telling deparser that it will receive debugging digests

		// Note: ttl field is used for debugging purposes. Can determine what headers were parsed correctly by examining output packet's ttl field.
		hdr.ipv4.ttl = 1;
		if (hdr.ipv4.isValid()) {
			hdr.ipv4.ttl = 2;
			if (hdr.udp.isValid()) {
				hdr.ipv4.ttl = 3;
				
				if (meta.incomingV7) {
					#include "control_v7.p4" // Translate v7 to v6
				} else if (meta.incomingV6) {
					#include "control_v6.p4" // Translate v6 to v7
				}

				checksum_upd_udp(true); // Always update udp checksum
			}
			checksum_upd_ipv4(true); // Always update ipv4 checksum
			ipv4_host.apply();
		}
	}
}

/***    Ingress Deparser   ***/
control IngressDeparser(packet_out                        pkt,
			inout headers_t                               hdr,
			in metadata_headers_t                         meta,
			in ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
	Checksum() ipv4_checksum;
	Checksum() udp_checksum;

	Digest<debug_digest_t>() debug_digest;

	apply {
		if (ig_dprsr_md.digest_type == DIGEST_TYPE_DEBUG) { 
			// If statement is required, even though there's currently no other digest types
			debug_digest.pack(meta.debug_metadata);
		}

		if (meta.checksum_upd_ipv4) {
			// Recalculating IP checksum because incremental checksum update didn't work.
			hdr.ipv4.hdr_checksum = ipv4_checksum.update(
				{hdr.ipv4.version,
				 hdr.ipv4.ihl,
				 hdr.ipv4.diffserv,
				 hdr.ipv4.total_len,
				 hdr.ipv4.identification,
				 hdr.ipv4.flags,
				 hdr.ipv4.frag_offset,
				 hdr.ipv4.ttl,
				 hdr.ipv4.protocol,
				 hdr.ipv4.src_addr,
				 hdr.ipv4.dst_addr});
		}
		
		if (meta.checksum_upd_udp) {
			/* 
			   Recalculating UDP checksum because incremental checksum update didn't work
			   Important notes:
			    - UDP checksum requires 16-bit aligned values, which means 8-bit padding needs to be added in certain places.
			    - The ADU padding is very brittle and not the "correct" way of doing this.
			        - Would be better to have separate cases for each ADU (i.e. if we have ADU of length 2, then only add adu_2 to the checksum)
			        - Current hacky version takes advantage of the fact that adu fields that weren't used/parsed/extracted into have all 0 values (not guaranteed behavior)
			            - Unused ADU fields are adding zero-values to the checksum, which doesn't affect the final checksum value
		                - Because of 16-bit alignment requirement, some octets of 0s need to be added to ensure alignment is maintained. (not sure exactly how the math works out)
		            - If we did incremental checksum, adding ADU manually to checksum wouldn't be necessary
			    - For debugging purposes there are comments with # of bits in each field
			*/

			if (meta.incomingV7) {
				// Bundle is now BPv6, need to recalculate checksum
				hdr.udp.checksum = udp_checksum.update(data = {
					hdr.ipv4.src_addr, // 32
					hdr.ipv4.dst_addr, // 32
					8w0, // 8
					hdr.ipv4.protocol, // 8

					hdr.udp.hdr_length, // 16
					hdr.udp.src_port, // 16
					hdr.udp.dst_port, // 16
					hdr.udp.hdr_length, // 16

					hdr.bpv6_primary_cbhe.version, // 8
					hdr.bpv6_primary_cbhe.bundle_flags, // 16
					hdr.bpv6_primary_cbhe.block_length, // 8
					hdr.bpv6_primary_cbhe.dst_node_num, // 8
					hdr.bpv6_primary_cbhe.dst_serv_num, // 8
					hdr.bpv6_primary_cbhe.src_node_num, // 8
					hdr.bpv6_primary_cbhe.src_serv_num, // 8
					hdr.bpv6_primary_cbhe.rep_node_num, // 8
					hdr.bpv6_primary_cbhe.rep_serv_num, // 8
					hdr.bpv6_primary_cbhe.cust_node_num, // 8
					hdr.bpv6_primary_cbhe.cust_serv_num, // 8
					hdr.bpv6_primary_cbhe.creation_ts, // 40
					hdr.bpv6_primary_cbhe.creation_ts_seq_num, // 8
					hdr.bpv6_primary_cbhe.lifetime, // 24
					hdr.bpv6_primary_cbhe.dict_len, // 8
					// Everything above is 16-bit aligned

					// Extension blocks aren't translated so don't need to add them to checksum

					hdr.bpv6_payload.block_type_code, // 8
					hdr.bpv6_payload.block_flags, // 8
					hdr.bpv6_payload.payload_length, // 8

					hdr.adu_1.adu, // 8
					8w0,           // 8
					hdr.adu_2.adu, // 16
					hdr.adu_3.adu, // 24
					8w0,           // 8
					hdr.adu_4.adu, // 32
					hdr.adu_5.adu, // 40
					8w0,           // 8
					hdr.adu_6.adu,
					hdr.adu_7.adu,
					8w0,
					hdr.adu_8.adu,
					hdr.adu_9.adu,
					8w0,
					hdr.adu_10.adu,
					hdr.adu_11.adu,
					8w0,
					hdr.adu_12.adu,
					hdr.adu_13.adu
				}, zeros_as_ones = true);
			} else if (meta.incomingV6) {
				// Bundle is now BPv7, need to recalculate checksum
				hdr.udp.checksum = udp_checksum.update(data = {
					hdr.ipv4.src_addr, // 32
					hdr.ipv4.dst_addr, // 32
					8w0, // 8
					hdr.ipv4.protocol, // 8

					hdr.udp.hdr_length, // 16
					hdr.udp.src_port, // 16
					hdr.udp.dst_port, // 16
					hdr.udp.hdr_length, // 16

					hdr.bpv7_start_code.start_code, // 8
					hdr.bpv7_primary_1.prim_initial_byte, // 8
					hdr.bpv7_primary_1.version_num, // 8
					hdr.bpv7_primary_1.bundle_flags, // 16
					hdr.bpv7_primary_1.crc_type, //8
					hdr.bpv7_primary_1.dest_eid, // 40
					hdr.bpv7_primary_1.src_eid, // 40
					hdr.bpv7_primary_1.report_eid, // 40
					hdr.bpv7_primary_1.creation_timestamp_time_initial_byte, //8
					hdr.bpv7_primary_1.creation_timestamp_time, // 72
					hdr.bpv7_primary_1.creation_timestamp_seq_num_initial_byte, // 8

					// Creation timestamp seq. num is hardcoded to be small in translation so don't need to worry including these in checksum right now: bpv7_primary_2_1, bpv7_primary_2_2, bpv7_primary_2_4, bpv7_primary_2_8

					hdr.bpv7_primary_3.lifetime, // 40
					hdr.bpv7_primary_3.crc_field_integer, // 24
					// Everything above is 16-bit aligned

					// Extension blocks aren't translated so don't need to add them to checksum

					hdr.bpv7_payload.initial_byte, // 8
					hdr.bpv7_payload.block_type, // 8
					hdr.bpv7_payload.block_num, // 8
					hdr.bpv7_payload.block_flags, // 8
					hdr.bpv7_payload.crc_type, // 8
					hdr.bpv7_payload.adu_initial_byte, // 8

					hdr.adu_1.adu, // 8
					8w0,           // 8
					hdr.adu_2.adu, // 16
					hdr.adu_3.adu, // 24
					8w0,           // 8
					hdr.adu_4.adu, // 32
					hdr.adu_5.adu, // 40
					8w0,
					hdr.adu_6.adu,
					hdr.adu_7.adu,
					8w0,
					hdr.adu_8.adu,
					hdr.adu_9.adu,
					8w0,
					hdr.adu_10.adu,
					hdr.adu_11.adu,
					8w0,
					hdr.adu_12.adu,
					hdr.adu_13.adu
				}, zeros_as_ones = true);
				
			}
		}
		
		pkt.emit(hdr);
	}
}

/***    EGRESS PROCESSING   ***/
// Egress processing currently only contains the required boiler plate code

struct egress_headers_t {
}
struct egress_metadata_t {
}

/***    Egress Parser   ***/
parser EgressParser(packet_in                       pkt,
					out egress_headers_t            hdr,
					out egress_metadata_t           meta,
					out egress_intrinsic_metadata_t eg_intr_md)
{	
	state start {
		pkt.extract(eg_intr_md);
		transition accept;
	}
}
/***    Egress Match-Action   ***/
control Egress(
		inout egress_headers_t                            hdr,
		inout egress_metadata_t                           meta,
		in egress_intrinsic_metadata_t                    eg_intr_md,
		in egress_intrinsic_metadata_from_parser_t        eg_prsr_md,
		inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
		inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{
	apply {
	}
} 
/***    Egress Deparser   ***/
control EgressDeparser(packet_out                           pkt,
				inout egress_headers_t                      hdr,
				in egress_metadata_t                        meta,
				in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
	apply {
		pkt.emit(hdr);
	}
}

/***    Final Package   ***/

// Create a Pipeline instance
Pipeline(
	IngressParser(),
	Ingress(),
	IngressDeparser(),
	EgressParser(),
	Egress(),
	EgressDeparser()
) pipe;

// Our switch will use one pipe instance for all pipes (i.e. all pipes do the same thing)
Switch(pipe) main;
