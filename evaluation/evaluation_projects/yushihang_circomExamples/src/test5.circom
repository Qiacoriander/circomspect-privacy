
pragma circom 2.0.0;

template calc () {  

   // Declaration of signals.  
   signal T2;
   signal T1;
   signal z;

   signal output y;

   signal input x;  

   //y = x ** 3 + 2x + 5
   // Constraints.  
   T1 <== x * x;
   z <== T1 * x;
   T2 <== z + 2 * x;
   y <== T2 + 5;  
}

component main  = calc();