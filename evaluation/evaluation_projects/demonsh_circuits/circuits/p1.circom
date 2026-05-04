pragma circom 2.0.0;
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";


template P1 (levels) {

   // Declaration of signals.  
   signal input amount;
   signal input receiver;
   signal input nonce;

   signal input signatureS;
   signal input signatureR8X;
   signal input signatureR8Y;

   signal input paymentID;
   signal input paymentPrivateKey;

   signal input root;
   signal input tree[levels];

   signal output nullifier;


   component pub = BabyPbk();
   pub.in <== paymentPrivateKey;

    // key hash
   component keyHash = Poseidon(2);
   keyHash.inputs[0] <== pub.Ax;
   keyHash.inputs[1] <== pub.Ay;

   // key included in tree root
   component smtVerifier = SMTVerifier(levels);
   smtVerifier.enabled <== 1;
   smtVerifier.fnc <== 0; // Inclusion
   smtVerifier.root <== root;
   for (var i=0; i<levels; i++) { smtVerifier.siblings[i] <== tree[i]; }
   smtVerifier.oldKey <== 0;
   smtVerifier.oldValue <== 0;
   smtVerifier.isOld0 <== 0;
   smtVerifier.key <== paymentID;
   smtVerifier.value <== keyHash.out;

   // Constraints.
   component pos = Poseidon(4);
   pos.inputs[0] <== amount;
   pos.inputs[1] <== receiver;
   pos.inputs[2] <== nonce;
   pos.inputs[3] <== paymentID;

    // Signature verification
   component sigVerifier = EdDSAPoseidonVerifier();
   sigVerifier.enabled <== 1;
   sigVerifier.Ax <== pub.Ax;
   sigVerifier.Ay <== pub.Ay;
   sigVerifier.S <== signatureS;
   sigVerifier.R8x <== signatureR8X;
   sigVerifier.R8y <== signatureR8Y;
   sigVerifier.M <== pos.out;


   component hNull = Poseidon(2);
   hNull.inputs[0] <== paymentPrivateKey;
   hNull.inputs[1] <== paymentID;

    // [TODO] Nullifier calculation
   nullifier <== hNull.out;
}