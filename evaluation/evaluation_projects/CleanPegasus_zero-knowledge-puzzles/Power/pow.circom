pragma circom 2.1.4;

// Create a circuit which takes an input 'a',(array of length 2 ) , then  implement power modulo 
// and return it using output 'c'.

// HINT: Non Quadratic constraints are not allowed. 

include "../QuinSelector/QuinSelector.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template Pow(n) {
   
   // Your Code here.. 
   signal input a[2];
   signal output c;
  
   // lte range check
   component lte = LessThan(n);
   lte.in <== [a[1], n];
   lte.out === 1;


   signal possiblePowers[n];
   signal temp[n][n];
   for(var i; i<n; i++) {
      temp[i][0] <== 1;
      for(var j = 1; j<=i; j++) {
         temp[i][j] <== temp[i][j - 1] * a[0];
      }
      possiblePowers[i] <== temp[i][i];

   }

   log(possiblePowers[a[1]]);

   component quinSelector = QuinSelector(n);
   quinSelector.in <== possiblePowers;
   quinSelector.selector <== a[1];

   c <== quinSelector.out;

}

component main = Pow(33);

