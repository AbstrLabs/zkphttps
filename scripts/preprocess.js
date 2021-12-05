#!/usr/bin/env node

const cbor = require('cbor')
const fs = require('fs')
const asn1js = require('asn1js')
const pkijs = require('pkijs')
const assert = require('assert')

let certChain = cbor.decode(fs.readFileSync(process.argv[2]))

fs.writeFileSync('main-cert.der', certChain[1].cert)
fs.writeFileSync('main-ocsp.der', certChain[1].ocsp)
fs.writeFileSync('next-cert.der', certChain[2].cert)

function toArrayBuffer(b) {
    return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
}
const certAsn1 = asn1js.fromBER(toArrayBuffer(certChain[1].cert))
// console.log(asn1)
const cert = new pkijs.Certificate({schema: certAsn1.result})
console.log(cert)
process.exit(0)
let tbs = cert.tbs
let algo = cert.signatureAlgorithm
let sig = cert.signatureValue
console.log(tbs)
console.log(algo)
console.log(sig)

let c = certChain[1].cert
console.log(c)
assert(c[0] == 0x30)
let len
let nextChild
let nextSibling
if (c[1] & 1<<7) {
    let lenBytes = c[1] & ((1<<7) - 1)
    assert(lenBytes <= 4) // impossible to be more than 4G
    len = 0
    nextChild = 2+lenBytes
    for (i = 0; i < lenBytes; i++) {
        len *= 256
        len += c[2+i]
    }
} else {
    nextChild = 2
    len = c[1]
}
console.log(nextChild)

assert(c[nextChild] == 0x30)
if (c[nextChild+1] & 1 << 7) {
    let lenBytes = c[nextChild+1] & ((1<<7) - 1)
    assert(lenBytes <= 4) // impossible to be more than 4G
    len = 0
    for (i = 0; i < lenBytes; i++) {
        len *= 256
        len += c[nextChild+2+i]
    }
    nextChild = nextChild+2+lenBytes
    nextSibling = nextChild + len
} else {
    nextChild = nextChild+2
    len = c[nextChild+1]
    nextSibling = nextChild+len
}

console.log(nextSibling)
assert(c[nextSibling] == 0x30)
console.log((c[nextSibling+1] & 1 << 7) == 0)
len=c[nextSibling+1]
console.log(c.slice(nextSibling+2, nextSibling+2+len))

// const ocspAsn1 = asn1js.fromBER(toArrayBuffer(certChain[1].ocsp))
// console.log(ocspAsn1)
// const ocsp = new pkijs.OCSPResponse({schema: ocspAsn1})
// console.log(ocsp)