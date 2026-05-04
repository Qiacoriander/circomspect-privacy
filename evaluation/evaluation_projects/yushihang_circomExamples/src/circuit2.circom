//circom multiplier2.circom --r1cs --wasm --sym --c
//https://docs.circom.io/getting-started/compiling-circuits/
pragma circom 2.0.0;

/*This circuit template checks that c is the multiplication of a and b.*/  

template Multiplier2 () {  

   // Declaration of signals.  
   signal input x;  
   signal input y;  
   signal output z;


   // Constraints.  
   z <== x * (y+1);  
}

 component main {public [x]} = Multiplier2();