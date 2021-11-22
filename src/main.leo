


// The 'zkphttps' main function.
function main(cert_chain: [u8; 10]) -> bool {
    let c = cert_chain_valid(cert_chain);
    return c;
}

function cert_chain_valid(cert_chain: [u8; 10]) -> bool {
    if cert_chain[0..9] != [131, 103, 240, 159, 147, 156, 226, 155, 147] {
        return false;
    } else {
        if (cert_chain[9] / 32u8) != 5 {
            return false;
        } else {
            return true;
        }
    }
}