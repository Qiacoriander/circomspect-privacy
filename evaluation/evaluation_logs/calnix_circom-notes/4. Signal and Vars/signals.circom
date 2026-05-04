pragma circom 2.1.6;

template Multiply() {
    signal input a;
    signal input b;
    signal input c;

    c === a * b;
}

component main {public [c]} = Multiply();


/*
# Signal vs variable

A signal is immutable and intended to be one of the columns of the R1CS. 
A variable is not part of the R1CS. It is intended for computing values outside the R1CS to help define the R1CS.

The reason signals are immutable is because the witness entries in an R1CS have a fixed value.
 solution vector in an R1CS that changes value does not make sense, as you cannot create a proof for it.
 The R1CS wtiness vector cannot be changing at a whim.
 <--, <==, and === operators are used with signals

 <== operator computes, then assigns, then adds a constraint.
 === operator only defines a constraint

*/

/*
Circom does not require an output signal to exist, as that is merely syntatic sugar for a public input. 
    `signal output out` does not have to exist.

Remember, an “input” is merely an entry to the witness vector, so everything is an input from a zero knowledge proof perspective. 
In the above example, there is no output signal, but this is a perfectly valid circuit with proper constraints.


*/