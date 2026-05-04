//circom multiplier2.circom --r1cs --wasm --sym --c
//https://docs.circom.io/getting-started/compiling-circuits/
pragma circom 2.0.0;

/*This circuit template checks that c is the multiplication of a and b.*/  

template Multiplier2 () {  

   // Declaration of signals.  
   signal temp;
   signal input y;  
   signal output z;
   signal input a;  
   signal input x; 



   // Constraints.  
   temp <== (a + x) * (x + y + 3);
   z <== (x + y + a) * (temp + x + 1);  
}

 component main {public [x, a]} = Multiplier2();