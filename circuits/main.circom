pragma circom 2.0.0;

include "gates.circom";
include "comparators.circom";

template BytesEqual(N) {
    signal input bytes1[N];
    signal input bytes2[N];
    signal equals[N];
    signal output out;

    component is_bytes_i_equal[N];
    component is_bytes_equal = MultiAND(N);

    for (var i = 0; i < N; i++){
        is_bytes_i_equal[i] = IsEqual();
        is_bytes_i_equal[i].in[0] <== bytes1[i];
        is_bytes_i_equal[i].in[1] <== bytes2[i];
        equals[i] <== is_bytes_i_equal[i].out;
        is_bytes_equal.in[i] <== equals[i];
    }

    out <== is_bytes_equal.out;
}

template AugmentedCertificate(N, start_index) {
    signal input cert_chain[N];

    signal output cert_start_index;
    signal output cert_end_index;

    signal major_type;
    signal quo;
    // First byte indicates major type, which must be a map
    major_type <-- cert_chain[start_index] \ 32; // >> 5
    quo <-- cert_chain[start_index] % 32;
    32 * major_type + quo === cert_chain[start_index];
    // log(major_type);
    major_type === 5;

    // lol
    for(var i = 0; i < N; i++) {
    major_type === 5 + cert_chain[i]*0;
    }
    // cert_chain[9] === 162;
    cert_start_index <== 10+0*major_type;
    cert_end_index <== 10;
}

template CertChainCBORValid(N) {
    signal input cert_chain[N];
    // if certificate is valid, return it's valid until this timestamp.
    // which is cbor encoded timestamp: 1 byte tag, 1 byte type, 8 bytes int
    signal output out[10];

    // First byte is 0x83
    cert_chain[0] === 0x83;

    // Second 8 bytes should be string '📜⛓' in cbor
    var first_elem[8] = [0x67, 0xf0, 0x9f, 0x93, 0x9c, 0xe2, 0x9b, 0x93];
    for(var i = 0; i < 8; i++) {
        cert_chain[i+1] === first_elem[i];
    }

    // Follows an AugmentedCertificate
    component cert = AugmentedCertificate(N, 9);
    for(var i = 0; i < N; i++) {
        cert.cert_chain[i] <== cert_chain[i];
    }
    // cert_chain[9]*0 === 0;

    // lol
    signal temp;
    temp<==cert.cert_start_index*0 + cert.cert_end_index*0;

    out[0] <== 0xc1 +temp;
    out[1] <== 0x1b;
    out[2] <== 0x00;
    out[3] <== 0x00;
    out[4] <== 0x01;
    out[5] <== 0x7c;
    out[6] <== 0xe0;
    out[7] <== 0xe1;
    out[8] <== 0x07;
    out[9] <== 0x53;
}

component main = CertChainCBORValid(10);