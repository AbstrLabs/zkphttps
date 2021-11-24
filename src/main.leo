


// The 'zkphttps' main function.
function main(cert_chain_bytes: [u8; 10]) -> bool {
    let cert_chain = CertChain::new(cert_chain_bytes[0..8], cert_chain_bytes[8..]);
    return cert_chain.is_valid();
}

circuit AugmentedCertificate {
    cert: [u8; 1];
    // oscp: [u8; 100];
    // sct: [u8; 100];

    function new(cert: [u8; 1]) -> Self {
        return Self { cert: cert };
    }

    function default() -> Self {
        return Self { cert: [0u8] };
    }
}

circuit AugmentedCertificateRaw {
    bytes: [u8; 2];
    function new(bytes: [u8; 2]) -> Self {
        return Self { bytes: bytes };
    }

    function parse(self, start_index: u32) -> (bool, AugmentedCertificate, u32) {
        if self.bytes[0] / 32u8 != 5 {
            return (false, AugmentedCertificate::default(), 1);
        } else {
            return (true, AugmentedCertificate::new(self.bytes[1..]), 0);
        }
    }
}

circuit CertChain {
    magic: [u8; 8];
    aug_certs_valid: bool;
    augmented_certificates: [AugmentedCertificate; 2];

    function new(magic: [u8; 8], aug_cert_bytes: [u8; 2]) -> Self {
        let aug_certs_valid = true;
        let augmented_certificates: [AugmentedCertificate; 2] = [AugmentedCertificate::default(), AugmentedCertificate::default()];
        let start_index: u32 = 0;
        for i in 0..2 {
            let aug_cert_raw = AugmentedCertificateRaw::new(aug_cert_bytes);
            let (aug_cert_valid, aug_cert, new_start_index) = aug_cert_raw.parse(start_index);
            start_index = new_start_index;
            augmented_certificates[i] = aug_cert;
            aug_certs_valid = aug_certs_valid && aug_cert_valid;
        }

        return Self {
            magic: magic, 
            aug_certs_valid: aug_certs_valid,
            augmented_certificates: augmented_certificates,
        };
    }

    function is_valid(self) -> bool {
        if !self.aug_certs_valid {
            return false;
        } else {
            let magic: [u8; 8] = [131, 103, 240, 159, 147, 156, 226, 155];
            if self.magic != magic {
                return false;
            } else {
                return true;
            }
        }
    }
}

