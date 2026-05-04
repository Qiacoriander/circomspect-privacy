pragma circom 2.2.2;

include "./utils/verify.circom";

template Main() {
  signal input message[32];
  signal input pubkey[64];
  signal input sig[6254];
  signal input message_bytes; // actual length of the message without the padding
  
  component VerifySig = VerifySignature(32);
  VerifySig.message <== message;
  VerifySig.pubkey <== pubkey;
  VerifySig.sig <== sig;
  VerifySig.message_bytes <== message_bytes;

  signal output o;

  o <== 1;
}
