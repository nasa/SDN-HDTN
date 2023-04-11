// Dominick Ta, Stephanie Booth, Rachel Dudukovich
// NASA Glenn Research Center, Cleveland, OH

// Logic for parsing Bundle Protocol version 6 headers.
// Assumes that transport layer headers have been extracted and next byte is start of bundle (i.e. Bundle protocol version number 6, 0x06)

state parse_v6 {
    meta.incomingV6 = true;
    pkt.extract(hdr.bpv6_primary_cbhe);
    pkt.extract(hdr.bpv6_extension_phib);
    pkt.extract(hdr.bpv6_extension_age);
    pkt.extract(hdr.bpv6_payload);
    transition select(hdr.bpv6_payload.payload_length) {
        1 : parse_v6_adu_1;
        2 : parse_v6_adu_2;
        3 : parse_v6_adu_3;
        4 : parse_v6_adu_4;
        5 : parse_v6_adu_5;
        6 : parse_v6_adu_6;
        7 : parse_v6_adu_7;
        8 : parse_v6_adu_8;
        9 : parse_v6_adu_9;
        10 : parse_v6_adu_10;
        11 : parse_v6_adu_11;
        12 : parse_v6_adu_12;
        13 : parse_v6_adu_13;
        _ : accept;
    }
}

state parse_v6_adu_1 {
    pkt.extract(hdr.adu_1);
    transition accept;
}

state parse_v6_adu_2 {
    pkt.extract(hdr.adu_2);
    transition accept;
}

state parse_v6_adu_3 {
    pkt.extract(hdr.adu_3);
    transition accept;
}

state parse_v6_adu_4 {
    pkt.extract(hdr.adu_4);
    transition accept;
}

state parse_v6_adu_5 {
    pkt.extract(hdr.adu_5);
    transition accept;
}

state parse_v6_adu_6 {
    pkt.extract(hdr.adu_6);
    transition accept;
}

state parse_v6_adu_7 {
    pkt.extract(hdr.adu_7);
    transition accept;
}

state parse_v6_adu_8 {
    pkt.extract(hdr.adu_8);
    transition accept;
}

state parse_v6_adu_9 {
    pkt.extract(hdr.adu_9);
    transition accept;
}

state parse_v6_adu_10 {
    pkt.extract(hdr.adu_10);
    transition accept;
}

state parse_v6_adu_11 {
    pkt.extract(hdr.adu_11);
    transition accept;
}

state parse_v6_adu_12 {
    pkt.extract(hdr.adu_12);
    transition accept;
}

state parse_v6_adu_13 {
    pkt.extract(hdr.adu_13);
    transition accept;
}