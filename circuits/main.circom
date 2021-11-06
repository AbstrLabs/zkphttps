pragma circom 2.0.0;

include "gates.circom";
include "comparators.circom";

// template BytesEqual(N) {
//     signal input bytes1[N];
//     signal input bytes2[N];

//     for (var i = 0; i < N; i++){
//         component is_bytes_i_equal = IsEqual();
//         is_bytes_i_equal.input[0] <== bytes1[i];
//         is_bytes_i_equal.input[1] <== bytes2[i];
        
//     }
// }

template CertChainCBORValid(N) {
    signal input cert_chain[N];
    // if certificate is valid, return it's valid until this timestamp.
    // which is cbor encoded timestamp: 1 byte tag, 1 byte type, 8 bytes int
    signal output out[10];

    component cert_chain_is_array3 = IsEqual();
    cert_chain_is_array3.in[0] <== 0x83;
    cert_chain_is_array3.in[1] <== cert_chain[0];
    assert(cert_chain_is_array3.out == 1);
    
    out[0] <== 0xc1;
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

component main = CertChainCBORValid(1);