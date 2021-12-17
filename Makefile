circuit:
	mkdir -p build
	cd circuits && circom main.circom --inspect --r1cs --wasm --sym --c -o ../build

test:
	tests/test_valid_proof.sh
	