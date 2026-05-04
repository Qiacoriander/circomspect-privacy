include "../node_modules/circomlib/circuits/poseidon.circom";
include "./utils/SHA256.circom";
include "./utils/ECDH.circom"

// verify if hash = SHA256(message) && key = ECDH-Derive(x1, y2) && cipherText = MiMCEncrypt(message, iv, key)
template VerifiableEncrypt(N) {
  signal private input message[N]; //N must be multiple of 3
  signal private input privateKey; // ECDH private key of data owner
  signal input publicKey[2]; // ECDH public key of user
  signal input ciphertext[N+1];
  signal input nonce; 
  signal input hash; 

  // verify hash
  component sha256 = SHA256(N);
  for(var i=0; i<N; i++) {
    sha256.in[i] <== message[i];
  }
  sha256.out === hash;

  // derive shared key
  component ecdh = ECDH();
  ecdh.privateKey <== privateKey;
  ecdh.publicKey[0] <== publicKey[0]; 
  ecdh.publicKey[1] <== publicKey[1]; 

  // verify encryption of the message
  component poseidonDecrypt = PoseidonDecrypt(N);
  poseidonDecrypt.nonce <== nonce;
  poseidonDecrypt.key[0] <== ecdh.sharedKey[0];
  poseidonDecrypt.key[1] <== ecdh.sharedKey[1];

  for(var i=0; i<=N; i++) {
    poseidonDecrypt.ciphertext[i] <== ciphertext[i];
  }
  for(var i=0; i<N; i++) {
    message[i] === poseidonDecrypt.decrypted[i];
  }

}

component main = VerifiableEncrypt(10);