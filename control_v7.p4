// Dominick Ta, Stephanie Booth, Rachel Dudukovich
// NASA Glenn Research Center, Cleveland, OH

// Control block logic for incoming BPv7 bundles
// Contains logic for translating BPv7 bundles to BPv6

// TODO: better header validation checks
if (hdr.bpv7_start_code.isValid()) {
    hdr.ipv4.ttl = 4;
    if (hdr.bpv7_primary_1.isValid()) {
        hdr.ipv4.ttl = 5;
        meta.debug_metadata.hdr_version_num = hdr.bpv7_primary_1.version_num; // debug
        
        if (hdr.bpv7_primary_2_1.isValid()) {
            hdr.ipv4.ttl = 6;
        } else if (hdr.bpv7_primary_2_2.isValid()) {
            hdr.ipv4.ttl = 7;
        } else if (hdr.bpv7_primary_2_4.isValid()) {
            hdr.ipv4.ttl = 8;
        } else if (hdr.bpv7_primary_2_8.isValid()) {
            hdr.ipv4.ttl = 9;
        }
        
        // The following code was initially wrapped in these if statements, but it led to a compiler error from running out of space: error: tofino supports up to 12 stages, using 13
        // if (hdr.bpv7_primary_3.isValid()) {
        //     hdr.ipv4.ttl = 10;
        //     if (hdr.bpv7_extension_prev_node.isValid()) {
        //         hdr.ipv4.ttl = 11;
        //         if (hdr.bpv7_extension_ecos.isValid()) {
        //             hdr.ipv4.ttl = 12;
        //             if (hdr.bpv7_extension_age.isValid()) {
        //                 hdr.ipv4.ttl = 13;
        //                 
        //             }
        //         }
        //     }
        // }

        if (hdr.bpv7_payload.isValid()) {
            hdr.ipv4.ttl = 14;

            hdr.ipv4.identification = hdr.bpv7_extension_ecos.block_data_initial_byte ++ hdr.bpv7_extension_ecos.ecos_array_start; // debugging
            // Debug digest stuff
            meta.debug_metadata.initial_byte = hdr.bpv7_extension_age.initial_byte;
            meta.debug_metadata.block_type = hdr.bpv7_extension_age.block_type;
            meta.debug_metadata.block_num = hdr.bpv7_extension_age.block_num;
            meta.debug_metadata.block_flags = hdr.bpv7_extension_age.block_flags;
            meta.debug_metadata.crc_type = hdr.bpv7_extension_age.crc_type;
            meta.debug_metadata.block_data_initial_byte = hdr.bpv7_extension_age.block_data_initial_byte;
            meta.debug_metadata.bundle_age = hdr.bpv7_extension_age.bundle_age;

            // Commented out below is some code that works to change the payload message.
            // We could probably use match-action tables to let the control plane operators change what these payload messages get changed to on the fly. (which could be extended to other bundle fields)
            if (hdr.adu_1.isValid()) {
                hdr.ipv4.ttl = 15;
            } else if (hdr.adu_2.isValid()) {
                hdr.ipv4.ttl = 16;
                // hdr.adu_2.adu = 0x680A; // "h\n"
            } else if (hdr.adu_3.isValid()) {
                hdr.ipv4.ttl = 17;
                // hdr.adu_3.adu = 0x68690A; // "hi\n"
            } else if (hdr.adu_4.isValid()) {
                hdr.ipv4.ttl = 18;
                // hdr.adu_4.adu = 0x6865790A; // "hey\n"
            } else if (hdr.adu_5.isValid()) {
                hdr.ipv4.ttl = 19;
                // hdr.adu_5.adu = 0x6E6173610A; // "nasa\n"
            } else if (hdr.adu_6.isValid()) {
                hdr.ipv4.ttl = 20;
                // hdr.adu_6.adu = 0x68656C6C6F0A; // "hello\n"
            } else if (hdr.adu_7.isValid()) {
                hdr.ipv4.ttl = 21;
                // hdr.adu_7.adu = 0x726F636B65740A; // "rocket\n"
            } else if (hdr.adu_8.isValid()) {
                hdr.ipv4.ttl = 22;
                // hdr.adu_8.adu = 0x726F636B6574730A; // "rockets\n"
            } else if (hdr.adu_9.isValid()) {
                hdr.ipv4.ttl = 23;
            } else if (hdr.adu_10.isValid()) {
                hdr.ipv4.ttl = 24;
            } else if (hdr.adu_11.isValid()) {
                hdr.ipv4.ttl = 25;
            } else if (hdr.adu_12.isValid()) {
                hdr.ipv4.ttl = 26;
            } else if (hdr.adu_13.isValid()) {
                hdr.ipv4.ttl = 27;
            }

            /*   Translate v7 to v6   */

            // Create primary block
            hdr.bpv6_primary_cbhe.version = 6;
            hdr.bpv6_primary_cbhe.bundle_flags = 0x8110; // Hardcoded b/c requires SDNV encoding capability
            hdr.bpv6_primary_cbhe.block_length = 18;
            hdr.bpv6_primary_cbhe.dst_node_num = hdr.bpv7_primary_1.dest_eid[15:8];
            hdr.bpv6_primary_cbhe.dst_serv_num = hdr.bpv7_primary_1.dest_eid[7:0];
            hdr.bpv6_primary_cbhe.src_node_num = hdr.bpv7_primary_1.src_eid[15:8];
            hdr.bpv6_primary_cbhe.src_serv_num = hdr.bpv7_primary_1.src_eid[7:0];
            hdr.bpv6_primary_cbhe.rep_node_num = hdr.bpv7_primary_1.report_eid[15:8];
            hdr.bpv6_primary_cbhe.rep_serv_num = hdr.bpv7_primary_1.report_eid[7:0];
            hdr.bpv6_primary_cbhe.cust_node_num = 0; // v7 has no custodian EID, so this is just 0 for now
            hdr.bpv6_primary_cbhe.cust_serv_num = 0; // v7 has no custodian EID, so this is just 0 for now
            hdr.bpv6_primary_cbhe.creation_ts = 0x82d2e2cc6e; // Hardcoded b/c requires SDNV encoding capability
            hdr.bpv6_primary_cbhe.creation_ts_seq_num = 1; // Hardcoded b/c requires SDNV encoding capability
            hdr.bpv6_primary_cbhe.lifetime = 0x85a300; // (value: 86400ms)  Hardcoded b/c requires SDNV encoding capability
            hdr.bpv6_primary_cbhe.dict_len = 0; // Using CBHE-encoding
            hdr.bpv6_primary_cbhe.setValid();

            // Skip emitting extension blocks (Can add extension block translation later)

            // Create payload header
            hdr.bpv6_payload.block_type_code = 1;
            hdr.bpv6_payload.block_flags = 0x09;
            // The following contains a chain of inefficient if statements, but it works
            // It would be better if we could use hdr.bpv7_payload.adu_initial_byte && CBOR_MASK_AI to extract the payload length directly into hdr.bpv6_payload.payload_length
            // ^^ This didn't work though...
            // Alternatively, could try splitting the definition of hdr.bpv7_payload.adu_initial_byte into two fields: adu_major_type and adu_additional_info
            // ^^ Not sure if this works but worth a shot
            if (hdr.adu_1.isValid()) {
                hdr.bpv6_payload.payload_length = 1;
            } else if (hdr.adu_2.isValid()) {
                hdr.bpv6_payload.payload_length = 2;
            } else if (hdr.adu_3.isValid()) {
                hdr.bpv6_payload.payload_length = 3;
            } else if (hdr.adu_4.isValid()) {
                hdr.bpv6_payload.payload_length = 4;
            } else if (hdr.adu_5.isValid()) {
                hdr.bpv6_payload.payload_length = 5;
            } else if (hdr.adu_6.isValid()) {
                hdr.bpv6_payload.payload_length = 6;
            } else if (hdr.adu_7.isValid()) {
                hdr.bpv6_payload.payload_length = 7;
            } else if (hdr.adu_8.isValid()) {
                hdr.bpv6_payload.payload_length = 8;
            } else if (hdr.adu_9.isValid()) {
                hdr.bpv6_payload.payload_length = 9;
            } else if (hdr.adu_10.isValid()) {
                hdr.bpv6_payload.payload_length = 10;
            } else if (hdr.adu_11.isValid()) {
                hdr.bpv6_payload.payload_length = 11;
            } else if (hdr.adu_12.isValid()) {
                hdr.bpv6_payload.payload_length = 12;
            } else if (hdr.adu_13.isValid()) {
                hdr.bpv6_payload.payload_length = 13;
            }
            hdr.bpv6_payload.setValid();
            
            // No need to create adu headers because adu is already parsed/valid and is being reused
            
            /*   Recalculate Header Lengths   */
            // udp length = udp header + bundle primary block + payload header + adu length
            bit<8> udp_len = 8 + 22 + 3 + hdr.bpv6_payload.payload_length;
            hdr.udp.hdr_length = (bit<16>) udp_len;
            hdr.ipv4.total_len = (bit<16>) (20 + 8 + 22 + 3 + hdr.bpv6_payload.payload_length);

            /*   Invalidate v7 headers   */
            hdr.bpv7_start_code.setInvalid();
            hdr.bpv7_primary_1.setInvalid();
            hdr.bpv7_primary_2_1.setInvalid();
            hdr.bpv7_primary_2_2.setInvalid();
            hdr.bpv7_primary_2_4.setInvalid();
            hdr.bpv7_primary_2_8.setInvalid();
            hdr.bpv7_primary_3.setInvalid();
            hdr.bpv7_extension_prev_node.setInvalid();
            hdr.bpv7_extension_ecos.setInvalid();
            hdr.bpv7_extension_age.setInvalid();
            // Skip invalidating adu headers
            hdr.bpv7_payload.setInvalid();
            hdr.bpv7_stop_code.setInvalid();
        }
    }
}