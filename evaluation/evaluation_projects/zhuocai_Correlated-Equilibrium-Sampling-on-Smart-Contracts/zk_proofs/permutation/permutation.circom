pragma circom 2.0.0;
// include "../exp_elliptic/circom-ecdsa/node_modules/circomlib/circuits/comparators.circom";
include "../circomlib/circuits/comparators.circom";
/*This circuit template checks that array B is the permutation of array A.*/  


template Permutation(N) {  

   // Declaration of signals.  
   signal input A[N];  // A = 0 1 2 3
   signal input B[N];  // B = 2 3 1 0
   signal input P[N][N]; 
   signal input PA[N][N]; // 
   // B = perm_matrix * A
   // each element of permutation matrix is binary value

   for (var i=0; i<N; i++) {
    var row_sum = 0;
    var col_sum = 0;
    var mult_sum = 0;
    
    for (var j=0; j<N; j++) {
        // check if P[i][j] is binary
        P[i][j] * (1 - P[i][j]) === 0;

        // check row and column sum
        row_sum += P[i][j];
        col_sum += P[j][i];

        // check calculation
        PA[i][j] === P[i][j]*A[j];
        mult_sum += PA[i][j];
    }
    row_sum === 1;
    col_sum === 1;

    mult_sum === B[i];
   }

}

//  component main= Permutation(2);