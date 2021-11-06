#!/bin/bash
make circuit
cd main_js
node generate_witness.js main.wasm ../tests/input.json ../tests/witness.wtns
cd ..
snarkjs plonk setup main.r1cs pot12_final.ptau circuit_final.zkey
