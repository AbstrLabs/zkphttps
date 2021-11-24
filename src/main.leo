// The 'zkphttps' main function.
function main(cert_chain_bytes: [u8; 11]) -> bool {
    let cert_chain = CertChain::new(cert_chain_bytes[0..9], cert_chain_bytes[9..]);
    let is_valid = cert_chain.is_valid();
    return is_valid;
}

circuit AugmentedCertificate {
    bytes: [u8; 2];
    cert_start: u32;
    // oscp_start: u32;
    // sct_start: u32;

    function new(bytes: [u8; 2], cert_start: u32) -> Self {
        return Self { bytes: bytes, cert_start: cert_start };
    }

    function default() -> Self {
        return Self { bytes: [0u8, 0u8], cert_start: 0 };
    }
}

circuit AugmentedCertificateRaw {
    bytes: [u8; 2];
    function new(bytes: [u8; 2]) -> Self {
        return Self { bytes: bytes };
    }

    function parse(self, start_index: u32) -> (bool, AugmentedCertificate, u32) {
        if self.bytes[start_index] / 32u8 != 5 {
            return (false, AugmentedCertificate::default(), 0);
        } else {
            return (true, AugmentedCertificate::new(self.bytes, start_index), start_index+1);
        }
    }
}

circuit CertChain {
    magic: [u8; 9];
    aug_certs_valid: bool;
    augmented_certificates: [AugmentedCertificate; 2];

    function new(magic: [u8; 9], aug_cert_bytes: [u8; 2]) -> Self {
        let aug_certs_valid = true;
        let augmented_certificates: [AugmentedCertificate; 2] = [AugmentedCertificate::default(), AugmentedCertificate::default()];
        let start_index: u32 = 0;
        for i in 0..2 {
            let aug_cert_raw = AugmentedCertificateRaw::new(aug_cert_bytes);
            let (aug_cert_valid, aug_cert, new_start_index) = aug_cert_raw.parse(start_index);
            start_index = new_start_index;
            console.log("start_index {} aug_cert_valid {}", start_index, aug_cert_valid);
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
            let magic: [u8; 9] = [131, 103, 240, 159, 147, 156, 226, 155, 147];
            if self.magic != magic {
                return false;
            } else {
                return true;
            }
        }
    }
}

