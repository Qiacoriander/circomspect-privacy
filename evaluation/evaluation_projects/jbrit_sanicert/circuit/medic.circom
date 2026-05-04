pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";

/*This circuit template gives interface of ideal input, verification and public output.*/  
template Medic () {  

   // Declaration of signals.  
   signal input timestamp;  
   signal input user_id;  
   signal input age;  
   signal input has_tb_vaccine;
   signal input has_yellow_fever_vaccine;

   // No one (user/verifier) knows this. The common knowledge is the data above is signed.
   signal input S;
   signal input R8x;
   signal input R8y;

   // signature of the combination of all with a known standard
   component p = Poseidon(5);
   p.inputs[0] <== timestamp;
   p.inputs[1] <== user_id;
   p.inputs[2] <== age;
   p.inputs[3] <== has_tb_vaccine;
   p.inputs[4] <== has_yellow_fever_vaccine;

   // EdDSAPoseidonVerifier
   component verifier = EdDSAPoseidonVerifier();
   verifier.enabled <== 1;
   // constrain Ax and Ay to already known publickey values
   verifier.Ax <== 13694923463182674830929626955487473476537691995474024808322408111996017798513;
   verifier.Ay <== 20467476669097489032688929523593938883946441376977100367560944785029750314310;
   verifier.S <== S;
   verifier.R8x <== R8x;
   verifier.R8y <== R8y;
   verifier.M <== p.out;

   // NOTE: Add Custom Constraints Here

   // NOTE: Output must be user_id
   signal output out <== user_id;
}

// NOTE: Timestamp is the only public input
component main { public [timestamp] } = Medic();