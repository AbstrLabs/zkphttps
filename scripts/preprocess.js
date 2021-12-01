#!/usr/bin/env node

const cbor = require('cbor')
const fs = require('fs')
const asn1js = require('asn1js')
const pkijs = require('pkijs')

let certChain = cbor.decode(fs.readFileSync(process.argv[2]))

fs.writeFileSync('main-cert.der', certChain[1].cert)
fs.writeFileSync('main-ocsp.der', certChain[1].ocsp)
fs.writeFileSync('next-cert.der', certChain[2].cert)