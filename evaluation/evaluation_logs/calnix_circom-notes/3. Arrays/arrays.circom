pragma circom 2.1.6;

template Powers(n) {
    signal input a;
    signal output powers[n];
    
    powers[0] <== a;

    for (var i = 1; i < n; i++) {
        powers[i] <==  powers[i - 1] * a;
    }
}


component main = Powers(6);

/*

template is parameterized with n, i.e. Powers(n).

A Rank 1 Constraint System must be fixed and immutable, this means we cannot change the number of rows or columns once defined, and we cannot change the values of the matrices or the witness.
That is why the final line has hard-coded argument Powers(6), this size must be fixed.


However, if we wanted to re-use this code later to support a different size circuit, then it is more ergonomic to have the template be able to change its size on the fly. 
Therefore, components can take arguments to parameterize control flows and data structures, but this must be fixed per circuit.

On compilation the circit below is equal teh one above:
*/

template Powers() {
    signal input a;
    signal output powers[6];
   
    powers[0] <== a;
    powers[1] <== powers[0] * a;
    powers[2] <== powers[1] * a;
    powers[3] <== powers[2] * a;
    powers[4] <== powers[3] * a;
    powers[5] <== powers[4] * a;
    
}
component main = Powers();

/* 
This example usefully illustrates that any circuit that uses variables in its computation can be rewritten to not include variables.

Variables build helper code that exists outside the R1CS. They help define the circuit, but they are not part of the circuit.

The variable var i was simply bookkeeping to track the loop iteration while constructing the circuit, it isn’t part of the constraints.
*/



