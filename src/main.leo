


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

    function new_invalid() -> Self {
        return Self { cert: [0u8] };
    }
}

circuit AugmentedCertificateRaw {
    bytes: [u8; 2];
    function new(bytes: [u8; 2]) -> Self {
        return Self { bytes: bytes };
    }

    function parse(self) -> (bool, AugmentedCertificate) {
        if self.bytes[0] / 32u8 != 5 {
            return (false, AugmentedCertificate::new_invalid());
        } else {
            return (true, AugmentedCertificate::new(self.bytes[1..]));
        }
    }
}

circuit CertChain {
    magic: [u8; 8];
    aug_cert_valid: bool;
    augmented_certificate: AugmentedCertificate;

    function new(magic: [u8; 8], aug_cert_bytes: [u8; 2]) -> Self {
        let aug_cert_raw = AugmentedCertificateRaw::new(aug_cert_bytes);
        let (aug_cert_valid, aug_cert) = aug_cert_raw.parse();
        return Self {
            magic: magic, 
            aug_cert_valid: aug_cert_valid,
            augmented_certificate: aug_cert,
        };
    }

    function is_valid(self) -> bool {
        if !self.aug_cert_valid {
            return false;
        } else {
            let magic: [u8; 8] = [131, 103, 240, 159, 147, 156, 226, 155];
            if self.magic != magic {
                return false;
            } else {
                return true;
                // if (cert_chain_bytes[9] / 32u8) != 5 {
                //     return false;
                // } else {
                //     return true;
                // }
            }
        }
    }
}

