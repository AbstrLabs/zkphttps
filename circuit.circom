pragma circom 2.0.0;

include "gates.circom";

template CertValid(N) {
    signal input cert_chain[N];
    // if certificate is valid, return it's valid until this timestamp.
    // which is cbor encoded timestamp: 1 byte tag, 1 byte type, 8 bytes int
    // Otherwise, first byte is bool false
    signal output out[10];
    signal cert_chain_format_correct;
    cert_chain_format_correct <== cert_chain[0] == 0x83;

    out[0] <== cert_chain_format_correct ? 0xf4 : 0xc1;
    // if (cert_chain_format_correct) {
    //     out[0] <== 0xf4; // false
    //     for (var i = 1; i < 10; i++) {
    //         out[i] <== 0;
    //     }
    // } else {
    //     out[0] <== 0xc1;
    //     out[1] <== 0x1b;
    //     out[2] <== 0x00;
    //     out[3] <== 0x00;
    //     out[4] <== 0x01;
    //     out[5] <== 0x7c;
    //     out[6] <== 0xe0;
    //     out[7] <== 0xe1;
    //     out[8] <== 0x07;
    //     out[9] <== 0x53;
    // }
}

component main = CertValid(1000);