#!/bin/bash
set -euo pipefail
dir=$(cd $(dirname $0)/..; pwd)

echo 'Build circuit ...'
cd ${dir}
make circuit
cd -

echo 'Generate witness ...'
cd ${dir}/build/main_js
mkdir -p ${dir}/test_output
node generate_witness.js main.wasm ${dir}/tests/input.json ${dir}/test_output/witness.wtns
cd -

echo 'Generate keys ...'
cd ${dir}/build/
snarkjs plonk setup main.r1cs ${dir}/res/powersOfTau28_hez_final_16.ptau ${dir}/test_output/main_final.zkey
# snarkjs zkey verify main.r1cs ${dir}/res/powersOfTau28_hez_final_16.ptau ${dir}/test_output/main_final.zkey
snarkjs zkey export verificationkey ${dir}/test_output/main_final.zkey ${dir}/test_output/verification_key.json
cd -

echo 'Create the proof ...'
cd ${dir}/test_output/
snarkjs plonk prove ${dir}/test_output/main_final.zkey witness.wtns proof.json public.json
cd -

echo 'Verify the proof ...'
cd ${dir}/test_output/
snarkjs plonk verify verification_key.json public.json proof.json
cd -
