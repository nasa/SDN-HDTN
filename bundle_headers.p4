// Contains all Bundle Protocol specific headers
// Included in headers.p4 file
// Dominick Ta, Stephanie Booth, Rachel Dudukovich
// NASA Glenn Research Center, Cleveland, OH

/*   BPv6 Headers   */

// Primary Block (CBHE Version)
header bpv6_primary_cbhe_h {
    bit<8> version;
    bit<16> bundle_flags;
    bit<8> block_length;
    bit<8> dst_node_num; // This field should be named differently for a non-CBHE version (e.g. dst_sch_offset)
    bit<8> dst_serv_num; // This field should be named differently for a non-CBHE version (e.g. dst_ssp_offset)
    bit<8> src_node_num;
    bit<8> src_serv_num;
    bit<8> rep_node_num;
    bit<8> rep_serv_num;
    bit<8> cust_node_num;
    bit<8> cust_serv_num;
    bit<40> creation_ts;
    bit<8> creation_ts_seq_num; // Timestamp seq num can cause issues if it gets too big. (ION always increments seq num, only resets if you restart ION)
    bit<24> lifetime;
    bit<8> dict_len; // should be 0 for Compressed Bundle Header Encoding (CBHE) RFC 6260
}

// Previous Hop Insertion Block (RFC 6259)
// A note on RFC 6259 terminology: "Inserting Node" is the Previous Hop Node ('previous hop' from perspective of the receiving node) 
header bpv6_extension_phib_h {
    bit<8> block_type_code;
    bit<8> block_flags;
    bit<8> block_data_len;
    // Inserting Node's EID Scheme Name - 
    //      A null-terminated array of bytes that comprises the scheme name of an M-EID of the node inserting this PHIB.
    //      Example: ["i", "p", "n", "\0"] aka [0x69, 0x70, 0x6e, 0x00]
    bit<32> prev_hop_scheme_name; 
    // Inserting Node's EID SSP - 
    //      A null-terminated array of bytes that comprises the scheme-specific part (SSP) of an M-EID of the node inserting this PHIB.
    //      Example: ["2", ".", "0", "\0"] aka [0x32, 0x2e, 0x30, 0x00]
    bit<32> prev_hop;
}

// Bundle Age Extension Block (https://datatracker.ietf.org/doc/html/draft-irtf-dtnrg-bundle-age-block-01)
header bpv6_extension_age_h {
    bit<8> block_type_code; // should be 20 (0x14) in ION implementation
    bit<8> block_flags;
    bit<8> block_data_len;
    bit<8> bundle_age;
}

// Payload Block
header bpv6_payload_h {
    bit<8> block_type_code; // should be 1
    bit<8> block_flags;
    bit<8> payload_length;
}

/*   BPv7 Headers   */

const bit<8> CBOR_INDEF_LEN_ARRAY_START_CODE = 8w0x9f;
const bit<8> CBOR_INDEF_LEN_ARRAY_STOP_CODE = 8w0xff;

const bit<8> CBOR_MASK_MT = 8w0b11100000; // CBOR Major Type Mask
const bit<8> CBOR_MASK_AI = 8w0b00011111; // CBOR Additional Info Mask

// Start of Bundle Code (0x9f)
header bpv7_start_code_h {
    bit<8> start_code;
}

// Primary Block (Part 1)
header bpv7_primary_1_h {
    bit<8> prim_initial_byte;
    bit<8> version_num;
    bit<16> bundle_flags;
    bit<8> crc_type;
    bit<40> dest_eid;
    bit<40> src_eid;
    bit<40> report_eid;
    bit<8> creation_timestamp_time_initial_byte;
    bit<72> creation_timestamp_time;
    // The ION implementation currently ALWAYS increments the creation timestamp sequence number. (This number is only reset when ION is reset on a node)
    // This means that the seq. number can become very large, causing problems if the P4 program isn't designed to handle the various CBOR cases correctly.
    // This is an example of the code required to properly parse a CBOR unsigned integer field (although not fully tested). See BPv7 parser to see how these headers are handled in parser.
    bit<8> creation_timestamp_seq_num_initial_byte;
}

// Primary Block (Part 2, may or may not be needed)
// Case: Timestamp Seq. Number requires 1 additional byte to create the CBOR argument
header bpv7_primary_2_1_h {
    bit<8> creation_timestamp_seq_num;
}
    
// Case: Timestamp Seq. Number requires 2 additional bytes to create the CBOR argument
header bpv7_primary_2_2_h {
    bit<16> creation_timestamp_seq_num;
}

// Case: Timestamp Seq. Number requires 4 additional bytes to create the CBOR argument
header bpv7_primary_2_4_h {
    bit<32> creation_timestamp_seq_num;
}

// Case: Timestamp Seq. Number requires 8 additional bytes to create the CBOR argument
header bpv7_primary_2_8_h {
    bit<64> creation_timestamp_seq_num;
}

// Primary Block (Part 3, always used)
// These are the fields that come after the creation timestamp
header bpv7_primary_3_h {
    bit<40> lifetime;
    bit<24> crc_field_integer;
}

// Previous Node Extension Block
header bpv7_extension_prev_node_h {
    bit<8> initial_byte;
    bit<8> block_type;
    bit<8> block_num;
    bit<8> block_flags;
    bit<8> crc_type;
    bit<8> block_data_initial_byte;
    bit<8> prev_node_array_initial_byte;
    bit<8> uri_scheme;
    bit<8> prev_node_eid_initial_byte;
    bit<8> node_num;
    bit<8> serv_num;
}

// Extended Class of Service Extension Block (https://datatracker.ietf.org/doc/draft-burleigh-dtn-ecos/00/)
// This is assuming that block type 193 is ION's type code for an extended class of service block.
// After peeking at ION's source code (.../bpv7/test/bpchat), 80% sure that this is an extended class of service block.
// However, the format of the pcap doesn't match up with the internet draft... 
header bpv7_extension_ecos_h {
    bit<8> initial_byte;
    bit<16> block_type;
    bit<8> block_num;
    bit<8> block_flags;
    bit<8> crc_type;
    bit<8> block_data_initial_byte;
    bit<8> ecos_array_start;
    bit<32> ecos_data;
}

// Bundle Age Extension Block
header bpv7_extension_age_h {
    bit<8> initial_byte;
    bit<8> block_type;
    bit<8> block_num;
    bit<8> block_flags;
    bit<8> crc_type;
    bit<8> block_data_initial_byte;
    bit<8> bundle_age;
}

// Payload Block
header bpv7_payload_h {
    bit<8> initial_byte;
	bit<8> block_type;
	bit<8> block_num;
	bit<8> block_flags;
	bit<8> crc_type;
    bit<8> adu_initial_byte; // This makes the strong assumption that ADU length is less than 24. If ADU len >= 24, then there's additional bytes (to determine the ADU length) before reaching the actual ADU/payload
}

// End of Bundle
header bpv7_stop_code_h {
	bit<8> stop_code;
}

/*   Payload (Application Data Unit) Headers (Used for both BPv6 and BPv7)   */
header adu_1_h {
	bit<8> adu;
}

header adu_2_h {
	bit<16> adu;
}

header adu_3_h {
	bit<24> adu;
}

header adu_4_h {
	bit<32> adu;
}

header adu_5_h {
	bit<40> adu;
}

header adu_6_h {
	bit<48> adu;
}

header adu_7_h {
	bit<56> adu;
}

header adu_8_h {
	bit<64> adu;
}

header adu_9_h {
	bit<72> adu;
}

header adu_10_h {
	bit<80> adu;
}

header adu_11_h {
	bit<88> adu;
}

header adu_12_h {
	bit<96> adu;
}

header adu_13_h {
	bit<104> adu;
}
