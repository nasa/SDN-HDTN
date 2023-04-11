// Dominick Ta, Stephanie Booth, Rachel Dudukovich
// NASA Glenn Research Center, Cleveland, OH

// Control block logic for incoming BPv6 bundles
// Contains logic for translating BPv6 bundles to BPv7

hdr.ipv4.ttl = 32;
if (hdr.bpv6_primary_cbhe.isValid()) {
    hdr.ipv4.ttl = 33;
    meta.debug_metadata.hdr_version_num = hdr.bpv6_primary_cbhe.version; // debug
    if (hdr.bpv6_extension_phib.isValid()) {
        hdr.ipv4.ttl = 34;
        if (hdr.bpv6_extension_age.isValid()) {
            hdr.ipv4.ttl = 35;
            if (hdr.bpv6_payload.isValid()) {
                if (hdr.adu_1.isValid()) {
                    hdr.ipv4.ttl = 36;
                } else if (hdr.adu_2.isValid()) {
                    hdr.ipv4.ttl = 37;
                } else if (hdr.adu_3.isValid()) {
                    hdr.ipv4.ttl = 38;
                } else if (hdr.adu_4.isValid()) {
                    hdr.ipv4.ttl = 39;
                } else if (hdr.adu_5.isValid()) {
                    hdr.ipv4.ttl = 40;
                } else if (hdr.adu_6.isValid()) {
                    hdr.ipv4.ttl = 41;
                } else if (hdr.adu_7.isValid()) {
                    hdr.ipv4.ttl = 42;
                } else if (hdr.adu_8.isValid()) {
                    hdr.ipv4.ttl = 43;
                } else if (hdr.adu_9.isValid()) {
                    hdr.ipv4.ttl = 44;
                } else if (hdr.adu_10.isValid()) {
                    hdr.ipv4.ttl = 45;
                } else if (hdr.adu_11.isValid()) {
                    hdr.ipv4.ttl = 46;
                } else if (hdr.adu_12.isValid()) {
                    hdr.ipv4.ttl = 47;
                } else if (hdr.adu_13.isValid()) {
                    hdr.ipv4.ttl = 48;
                }

                /*   Translate v6 to v7   */

                // Create start code
                hdr.bpv7_start_code.start_code = CBOR_INDEF_LEN_ARRAY_START_CODE;
                hdr.bpv7_start_code.setValid();

                // Create primary block
                hdr.bpv7_primary_1.prim_initial_byte = 0x89; 
                hdr.bpv7_primary_1.version_num = 0x07;
                hdr.bpv7_primary_1.bundle_flags = 0x1840; // Hardcoded b/c requires careful thinking about how to translate flags
                hdr.bpv7_primary_1.crc_type = 0x01; // might have issues with crc (could just avoid having CRC by setting crc-type to 0)
                hdr.bpv7_primary_1.dest_eid = 24w0x82_02_82 ++ hdr.bpv6_primary_cbhe.dst_node_num ++ hdr.bpv6_primary_cbhe.dst_serv_num; // IPN Uri Scheme # is 2
                hdr.bpv7_primary_1.src_eid = 24w0x82_02_82 ++ hdr.bpv6_primary_cbhe.src_node_num ++ hdr.bpv6_primary_cbhe.src_serv_num; // IPN Uri Scheme # is 2
                hdr.bpv7_primary_1.report_eid = 24w0x82_02_82 ++ hdr.bpv6_primary_cbhe.rep_node_num ++ hdr.bpv6_primary_cbhe.rep_serv_num; // IPN Uri Scheme # is 2
                hdr.bpv7_primary_1.creation_timestamp_time_initial_byte = 0x82;
                hdr.bpv7_primary_1.creation_timestamp_time = 0x1b000000a56f9117c4; // Hardcoded b/c requires SDNV decoding capability
                hdr.bpv7_primary_1.creation_timestamp_seq_num_initial_byte = 0x01; // Hardcoded b/c requires SDNV decoding capability
                hdr.bpv7_primary_1.setValid();
                
                hdr.bpv7_primary_3.lifetime = 0x1a05265c00; // Hardcoded b/c requires SDNV decoding capability
                hdr.bpv7_primary_3.crc_field_integer = 24w0x42_0d79; // Hardcoded b/c Tofino hash extern had issues with a big constant (bit<72> timestamp), need to refactor to get it to work
                hdr.bpv7_primary_3.setValid();
                
                // Skip emitting extension blocks (Can add extension block translation later)

                // Create payload block headers
                hdr.bpv7_payload.initial_byte = 0x85;
                hdr.bpv7_payload.block_type = 0x01;
                hdr.bpv7_payload.block_num = 0x01;
                hdr.bpv7_payload.block_flags = 0x01;
                hdr.bpv7_payload.crc_type = 0x00;
                hdr.bpv7_payload.adu_initial_byte =  4w0x4 ++ hdr.bpv6_payload.payload_length[3:0]; // fix later, this is limited
                hdr.bpv7_payload.setValid();
                
                // No need to create new adu headers because adu is already parsed/valid and is being reused

                // Create stop code
                hdr.bpv7_stop_code.stop_code = CBOR_INDEF_LEN_ARRAY_STOP_CODE;
                hdr.bpv7_stop_code.setValid();
                
                /*   Recalculate Header Lengths   */

                // udp length = udp header + bundle primary block + payload header + adu length + stop code
                // 8: udp header
                // 39: v7 primary block
                // 6: v7 payload header
                // x: adu length
                // 1: v7 stopcode
                // total length = 8 + 39 + 6 + 1 + x = 54 + x
                // ^^^ needed to do the math manually because compiler complained about running out of space while adding constants together
                bit<8> udp_len = 54 + hdr.bpv6_payload.payload_length; 
                hdr.udp.hdr_length = (bit<16>) udp_len;
                hdr.ipv4.total_len = (bit<16>) (20 + 54 + hdr.bpv6_payload.payload_length);

                /*   Invalidate v6 headers   */
                hdr.bpv6_primary_cbhe.setInvalid();
                hdr.bpv6_extension_phib.setInvalid();
                hdr.bpv6_extension_age.setInvalid();
                hdr.bpv6_payload.setInvalid();
                // Skip invalidating adu headers
            }
        }
    }

}