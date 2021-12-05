import u8u32.main.u8_u32;

// The 'zkphttps' main function.
function main(main_cert_bytes: [u8; 4000], tbs: u32, algo: u32, sig: u32, tbs_serial_number: u32, tbs_signature: u32, tbs_issuer: u32, tbs_validity: u32, tbs_subject: u32, issuer_pub_key: [u8; 200]) -> bool {
    let main_cert = Cert::new(main_cert_bytes, tbs, algo, sig, tbs_serial_number, tbs_signature, tbs_issuer, tbs_validity, tbs_subject);
    return main_cert.is_valid();
}

function len_bytes(byte: u8) -> u32 {
    return byte < 128u8 ? 0 : u8_u32(byte - 128u8);
}

circuit Cert {
    bytes: [u8; 4000];
    tbs: u32;
    algo: u32;
    sig: u32;
    tbs_serial_number: u32;
    tbs_signature: u32;
    tbs_issuer: u32;
    tbs_validity: u32;
    tbs_subject: u32;
    
    function new(bytes: [u8; 4000], tbs: u32, algo: u32, sig: u32, tbs_serialNumber: u32, tbs_signature: u32, tbs_issuer: u32, tbs_validity: u32, tbs_subject: u32) -> Self {
        return Self { bytes: bytes, tbs: tbs, algo: algo, sig: sig, tbs_serial_number: tbs_serialNumber, tbs_signature: tbs_signature, tbs_issuer: tbs_issuer, tbs_validity: tbs_validity, tbs_subject: tbs_subject };        
    }

    function is_valid(self) -> bool {
        return self.tbs_serial_number_valid() && self.tbs_signature_valid();
    }

    function tbs_serial_number_valid(self) -> bool {
        return self.bytes[self.tbs_serial_number] == 2u8 // integer
            && len_bytes(self.bytes[self.tbs_serial_number+1]) == 0
            && (self.tbs_signature - self.tbs_serial_number) == (2 + u8_u32(self.bytes[self.tbs_serial_number+1]));
    }
        
    function seq_valid(self, start: u32) -> (bool, u32) {
        let lb = len_bytes(self.bytes[start+1]);
        let len:u32 = lb == 0 ? 2+u8_u32(self.bytes[start+1]) : 2;
        for i in 0..4 {
            len += (i < lb) ? u8_u32(self.bytes[start+2+i]) : 0;
            len *= (i < lb) ? 128 : 1;
        }
        let valid = self.bytes[start] == 48 && lb <= 4;
        return (valid, len);
    }

    function tbs_signature_valid(self) -> bool {
        let (valid, len) = self.seq_valid(self.tbs_signature);
        return valid && self.tbs_signature + len == self.tbs_issuer;
    }
}
