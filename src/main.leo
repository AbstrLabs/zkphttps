// The 'zkphttps' main function.
// aleo doesn't support u8 -> u32 cast or u8 calculation with u32. have to make it full u32 for now
function main(main_cert_bytes: [u32; 4000]) -> bool {
    let main_cert_raw = CertRaw::new(main_cert_bytes);
    let main_cert = main_cert_raw.parse();
    return main_cert.is_valid();
}

circuit CertRaw {
    bytes: [u32; 4000];

    function new(bytes: [u32;  4000]) -> Self {
        return Self { bytes: bytes };
    }

    function parse(self) -> Cert {
        if self.bytes[0] == 48u32 {
            let len: u32 = 0;
            let nextChild: u32 = 0;
            let nextSibling: u32 = 0;
            let lenBytes:u32 = 0;

            if (self.bytes[1] / 128u32 == 1) {
                lenBytes = self.bytes[1] - (self.bytes[1] / 128u32) * 128u32;
                for i in 0..4 {
                    if i < lenBytes  {
                        // cannot write i in 0..lenBytes because aleo require loop constants
                        len *= 256;
                        len += self.bytes[2+i] ;
                    } else {
                        len = len;
                    }
                }
            } else {
                len = self.bytes[1] ;
            }
            nextChild = 2+lenBytes ;
            if lenBytes <= 4 {
                // we do not check lenBytes in the first place because if so number of constraints increased a lot. Also aleo limitation :(
                let tbs = [0u32; 4000];
                for i in 0..3900 {
                    if i < len {
                        tbs[i] = self.bytes[nextChild+i];
                    } else {
                        tbs[i] = 0;
                    }
                }
                let algo: [u32; 10] = tbs[0..10];
                let sig: [u32; 200] = tbs[0..200];
                return Cert::new(tbs, algo, sig);
            } else {
                return Cert::default();
            }
        } else {
            // must write in else, not a flat return because aleo limitation
            return Cert::default();
        }
    }
}

circuit Cert {
    tbs: [u32; 4000];
    algo: [u32; 10];
    sig: [u32; 200];

    function new(tbs: [u32; 4000], algo: [u32; 10], sig: [u32; 200]) -> Self {
        return Self { tbs: tbs, algo: algo, sig: sig };        
    }

    function default() -> Self {
        return Self { tbs: [0; 4000], algo: [0; 10], sig: [0; 200] };
    }

    function is_valid(self) -> bool {
        return true;
    }
}
