import cbor
import pprint

data = cbor.load(open('cert2.cbor'))
pprint.pprint(data)