const cbor = require('cbor')
const fs = require('fs')

let a = fs.readFileSync('res/cert.cbor')
console.log(a)
console.log(cbor.decode(a)[1])
console.log(cbor.encode(cbor.decode(a)[1]))
console.log(cbor.encode('cert'))

// console.log(cbor.encode([1,2,3]))
// console.log(Buffer.from(cbor.decode(a)[0]))
// console.log(cbor.encode(1635860416339))
// console.log(cbor.encode(false))
// console.log(cbor.encode(0))