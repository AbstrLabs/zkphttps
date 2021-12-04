// The 'zkphttps' main function.
function main(main_cert_bytes: [u8; 4000]) -> bool {
    let main_cert_raw = CertRaw::new(main_cert_bytes);
    let main_cert = main_cert_raw.parse();
    return main_cert.is_valid();
}

circuit CertRaw {
    bytes: [u8; 4000];

    function new(bytes: [u8;  4000]) -> Self {
        return Self { bytes: bytes };
    }

    function parse(self) -> Cert {
        console.assert(self.bytes[0] == 48u8);
        let len: u32 = 0;
        let nextChild: u32 = 0;
        let nextSibling: u32 = 0;

        if (self.bytes[1] / 128u8 == 1) {
            let lenBytes = self.bytes[1] - (self.bytes[1] / 128u8) * 128u8;
            console.assert(lenBytes <= 4); // impossible to be more than 4G
            len = 0;
            nextChild = 2+lenBytes as u32;
            for i in 0..4 {
                if i < lenBytes as u32 {
                    len *= 256;
                    len += self.bytes[2+i] as u32;
                } else {
                    len = len;
                }
            }
        } else {
            nextChild = 2;
            len = self.bytes[1] as u32;
        }
        let tbs = self.bytes;
        let algo: [u8; 10] = tbs[0..10];
        let sig: [u8; 200] = tbs[0..200];
        return Cert::new(tbs, algo, sig);
    }
}

circuit Cert {
    tbs: [u8; 4000];
    algo: [u8; 10];
    sig: [u8; 200];

    function new(tbs: [u8; 4000], algo: [u8; 10], sig: [u8; 200]) -> Self {
        return Self { tbs: tbs, algo: algo, sig: sig };        
    }

    function is_valid(self) -> bool {
        return true;
    }
}


