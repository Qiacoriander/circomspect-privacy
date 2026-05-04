//circom multiplier2.circom --r1cs --wasm --sym --c
//https://docs.circom.io/getting-started/compiling-circuits/
pragma circom 2.0.0;

/*This circuit template checks that c is the multiplication of a and b.*/  

template Multiplier2 () {  

   // Declaration of signals.  
   signal input a;  
   signal input b;  
   signal output c;  

   // Constraints.  
   c <== a * b;  
}

 component main {public [a]} = Multiplier2();