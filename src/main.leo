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


