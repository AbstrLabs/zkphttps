import u8u32.main.u8_u32; // convert u8 to u32

// The 'zkphttps' main function. We do a sub part of entire verify https: verify the cert is valid.
// On a high level, the cert valid means a few thing:
// 1. The cert is for a whitelisted domain name, such as "finance.yahoo.com", or "signed-exchange-testing.dev" (for testing)
// 2. The cert is signed by a a whitelisted cert issuer, such as Digicert. This can be verified by verify the sig with Digicert's known public key
// 3. Provided public key bytes matches one of known hard coded one
// To reduce the calculation in circuit, the cert (in DER format) is preparsed and important offset of elements in cert is parsed as input
// It's equivalent to parse the DER cert in circuit and verify the parsing result (offset, bytes from offsets are correct). but verify the parse
// generate much less constraints.
// Also, we don't need to verify the entire parsing, we only care the above three facts. 2 and 3 don't require a parse of bytes, they act on entire
// bytes. 1 does require parsing: cannot just check the domain name bytes is a subarray in cert bytes, because attacker can construct valid cert that
// contains the domain name bytes and get it signed by whitelist cert issuer. Therefore need to verify the domain name layouts in the correct location
// Other parts of parsing do not need to be verified. It can get signed by whitelist cert guarantees all parts of parsing are valid.
// To verify the domain name layouts in correct location, only need to check the fields before domain name (named tbs_subject in the RFC) have correct
// length
function main(main_cert_bytes: [u8; 4000], tbs: u32, algo: u32, sig: u32, tbs_serial_number: u32, tbs_signature: u32, tbs_issuer: u32, tbs_validity: u32, tbs_subject: u32, issuer_pub_key: [u8; 200]) -> bool {
    let main_cert = Cert::new(main_cert_bytes, tbs, algo, sig, tbs_serial_number, tbs_signature, tbs_issuer, tbs_validity, tbs_subject);
    return main_cert.is_valid();
    // It should be main_cert.is_valid(issuer_pub_key), I only finishes "check domain name layouts in correct location" part
}

// In DER, any object, including sequence and primitive integers, is encoded as:
// Tag Len Data
// Tag part fits in one byte. The Len part is encoded as following:
// - Short form. One octet. Bit 8 has value "0" and bits 7-1 give the length.
// - Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits 7-1 give the number of additional length octets. Second and following octets give the length, base 256, most significant digit first.
// This function returns the number of additional length octets. For short form it is 0.
function len_bytes(byte: u8) -> u32 {
    return byte < 128u8 ? 0 : u8_u32(byte - 128u8);
}

circuit Cert {
    // Cert bytes. 4000 should be more than sufficient, unused bytes are 0s.
    bytes: [u8; 4000];
    // starting offset of the tbs, algo and sig part of the cert, defined as following:
    //    Certificate  ::=  SEQUENCE  {
    //    tbsCertificate       TBSCertificate,
    //    signatureAlgorithm   AlgorithmIdentifier,
    //    signatureValue       BIT STRING  }
    tbs: u32;
    algo: u32;
    sig: u32;
    // starting offset of the fields of the tbs before domain name, defined as following:
    //    TBSCertificate  ::=  SEQUENCE  {
    //    version         [0]  EXPLICIT Version DEFAULT v1,
    //    serialNumber         CertificateSerialNumber,
    //    signature            AlgorithmIdentifier,
    //    issuer               Name,
    //    validity             Validity,
    tbs_serial_number: u32;
    tbs_signature: u32;
    tbs_issuer: u32;
    tbs_validity: u32;
    // starting offset of the tbs subject field, equals to the domain name
    //        subject              Name,
    tbs_subject: u32;
    // Definition of above fields can be find in https://datatracker.ietf.org/doc/html/rfc5280#section-4
    // Most of them are just DER SEQUENCE
    
    function new(bytes: [u8; 4000], tbs: u32, algo: u32, sig: u32, tbs_serialNumber: u32, tbs_signature: u32, tbs_issuer: u32, tbs_validity: u32, tbs_subject: u32) -> Self {
        return Self { bytes: bytes, tbs: tbs, algo: algo, sig: sig, tbs_serial_number: tbs_serialNumber, tbs_signature: tbs_signature, tbs_issuer: tbs_issuer, tbs_validity: tbs_validity, tbs_subject: tbs_subject };        
    }

    function is_valid(self) -> bool {
        return self.tbs_serial_number_valid() && self.tbs_signature_valid() && self.tbs_issuer_valid() && self.tbs_validity_valid() && self.tbs_subject_valid();
    }

    function tbs_serial_number_valid(self) -> bool {
        return self.bytes[self.tbs_serial_number] == 2u8 // DER INTEGER
            && len_bytes(self.bytes[self.tbs_serial_number+1]) == 0 // Len is short form 
            && (self.tbs_signature - self.tbs_serial_number) == (2 + u8_u32(self.bytes[self.tbs_serial_number+1])); // INTEGER takes Len + 2 bytes. 2 bytes for tag and short form len.
    }
    
    // Returns (true, length, seq_content_start) DER SEQUENCE start from self.bytes[start] is valid, (false, *, *) otherwise.
    function seq_valid(self, start: u32) -> (bool, u32, u32) {
        let lb = len_bytes(self.bytes[start+1]);
        let len:u32 = lb == 0 ? 2+u8_u32(self.bytes[start+1]) : 2;
        // Aleo loop must be constant, cannot write for i in 0..lb. cannot `break` from loop too. we assume lb <= 4 here.
        for i in 0..4 {
            len += (i < lb) ? u8_u32(self.bytes[start+2+i]) : 0;
            len *= (i < lb) ? 128 : 1;
        }
        // 48 (0x30) is the tag for DER SEQUENCE
        // if lb actually > 4, seq is also considered invalid, it's also practically impossible (lb > 4 means >4G length)
        let valid = self.bytes[start] == 48 && lb <= 4;
        return (valid, len, start+2u32+lb);
    }

    // tbs_signature is a valid sequence and takes correct number of bytes
    function tbs_signature_valid(self) -> bool {
        let (valid, len, content_start) = self.seq_valid(self.tbs_signature);
        return valid && self.tbs_signature + len == self.tbs_issuer;
    }

    // similar for tbs_issuer
    function tbs_issuer_valid(self) -> bool {
        let (valid, len, content_start) = self.seq_valid(self.tbs_issuer);
        return valid && self.tbs_issuer + len == self.tbs_validity;
    }

    // similar for tbs_validity.
    // TODO: also actually check the validity (cert doesn't expire)
    function tbs_validity_valid(self) -> bool {
        let (valid, len, content_start) = self.seq_valid(self.tbs_validity);
        return valid && self.tbs_validity + len == self.tbs_subject;
    }

    function tbs_subject_valid(self) -> bool {
        let (valid, len, content_start) = self.seq_valid(self.tbs_subject);
        // TODO
        return true;
    }
}
