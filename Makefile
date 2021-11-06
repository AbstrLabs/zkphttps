circuit:
	mkdir -p build
	cd circuits && circom main.circom --r1cs --wasm --sym --c -o ../build
	