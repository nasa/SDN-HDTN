// Dominick Ta, Stephanie Booth, Rachel Dudukovich
// NASA Glenn Research Center, Cleveland, OH

// Logic for parsing Bundle Protocol version 7 headers.
// Assumes that transport layer headers have been extracted and next byte is start of bundle (i.e. CBOR indefinite-length array start code, 0x9f)

state parse_v7 {
	meta.incomingV7 = true;

	pkt.extract(hdr.bpv7_start_code);
	transition parse_v7_prim_block;
}

state parse_v7_prim_block {
	pkt.extract(hdr.bpv7_primary_1);
	transition select(hdr.bpv7_primary_1.creation_timestamp_seq_num_initial_byte) {
		24 &&& CBOR_MASK_AI: parse_v7_prim_block_2_1; // Requires 1 extra byte to parse creation timestamp seq num
		25 &&& CBOR_MASK_AI: parse_v7_prim_block_2_2; // Requires 2 extra bytes to parse creation timestamp seq num
		26 &&& CBOR_MASK_AI: parse_v7_prim_block_2_4; // Requires 4 extra bytes to parse creation timestamp seq num
		27 &&& CBOR_MASK_AI: parse_v7_prim_block_2_8; // Requires 8 extra bytes to parse creation timestamp seq num
		_ : parse_v7_prim_block_3; // Timestamp Seq. Num data item was only one-byte total
	}
}

state parse_v7_prim_block_2_1 {
	pkt.extract(hdr.bpv7_primary_2_1);
	transition parse_v7_prim_block_3;
}

state parse_v7_prim_block_2_2 {
	pkt.extract(hdr.bpv7_primary_2_2);
	transition parse_v7_prim_block_3;
}

state parse_v7_prim_block_2_4 {
	pkt.extract(hdr.bpv7_primary_2_4);
	transition parse_v7_prim_block_3;
}

state parse_v7_prim_block_2_8 {
	pkt.extract(hdr.bpv7_primary_2_8);
	transition parse_v7_prim_block_3;
}

state parse_v7_prim_block_3 {
	pkt.extract(hdr.bpv7_primary_3);
	transition parse_v7_prev_node_block;
}

state parse_v7_prev_node_block {
	pkt.extract(hdr.bpv7_extension_prev_node);
	transition parse_v7_ecos_block;
}

state parse_v7_ecos_block {
	pkt.extract(hdr.bpv7_extension_ecos);
	transition parse_v7_age_block;
}

state parse_v7_age_block {
	pkt.extract(hdr.bpv7_extension_age);
	transition parse_v7_payload_header;
}

state parse_v7_payload_header {
	pkt.extract(hdr.bpv7_payload);
	transition select(hdr.bpv7_payload.adu_initial_byte) {
		1 &&& CBOR_MASK_AI: parse_v7_adu_1;
		2 &&& CBOR_MASK_AI: parse_v7_adu_2;
		3 &&& CBOR_MASK_AI : parse_v7_adu_3;
		4 &&& CBOR_MASK_AI : parse_v7_adu_4;
		5 &&& CBOR_MASK_AI : parse_v7_adu_5;
		6 &&& CBOR_MASK_AI : parse_v7_adu_6;
		7 &&& CBOR_MASK_AI : parse_v7_adu_7;
		8 &&& CBOR_MASK_AI : parse_v7_adu_8;
		9 &&& CBOR_MASK_AI : parse_v7_adu_9;
		10 &&& CBOR_MASK_AI : parse_v7_adu_10;
		11 &&& CBOR_MASK_AI : parse_v7_adu_11;
		12 &&& CBOR_MASK_AI : parse_v7_adu_12;
		13 &&& CBOR_MASK_AI : parse_v7_adu_13;
		_ : accept;
	}
}

state parse_v7_adu_1 {
	pkt.extract(hdr.adu_1);
	transition parse_v7_stop_code;
}

state parse_v7_adu_2 {
	pkt.extract(hdr.adu_2);
	transition parse_v7_stop_code;
}

state parse_v7_adu_3 {
	pkt.extract(hdr.adu_3);
	transition parse_v7_stop_code;
}

state parse_v7_adu_4 {
	pkt.extract(hdr.adu_4);
	transition parse_v7_stop_code;
}

state parse_v7_adu_5 {
	pkt.extract(hdr.adu_5);
	transition parse_v7_stop_code;
}

state parse_v7_adu_6 {
	pkt.extract(hdr.adu_6);
	transition parse_v7_stop_code;
}

state parse_v7_adu_7 {
	pkt.extract(hdr.adu_7);
	transition parse_v7_stop_code;
}

state parse_v7_adu_8 {
	pkt.extract(hdr.adu_8);
	transition parse_v7_stop_code;
}

state parse_v7_adu_9 {
	pkt.extract(hdr.adu_9);
	transition parse_v7_stop_code;
}

state parse_v7_adu_10 {
	pkt.extract(hdr.adu_10);
	transition parse_v7_stop_code;
}

state parse_v7_adu_11 {
	pkt.extract(hdr.adu_11);
	transition parse_v7_stop_code;
}

state parse_v7_adu_12 {
	pkt.extract(hdr.adu_12);
	transition parse_v7_stop_code;
}

state parse_v7_adu_13 {
	pkt.extract(hdr.adu_13);
	transition parse_v7_stop_code;
}

state parse_v7_stop_code {
	pkt.extract(hdr.bpv7_stop_code);

	transition accept;
}