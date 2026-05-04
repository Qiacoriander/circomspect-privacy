pragma circom 2.1.6;

template Square() {

    signal input in;
    signal output out;

    out <== in * in;
}

template SumOfSquares() {
    signal input a;
    signal input b;
    signal output out;

    component sq1 = Square();
    component sq2 = Square();

    // wiring the components together
    sq1.in <== a;
    sq2.in <== b;

    out <== sq1.out + sq2.out;
}
//If we want to input multiple values then we can use these template
template Mul {

    signal input in[2]; // takes two inputs
    signal output out; // single output
    
    out <== in[0] * in[1];
}
    
template IsZero() {
  signal input in;
  signal output out;

  signal inv;

  inv <-- in!=0 ? 1/in : 0; // This '<--' is used which means it first computes the value and then assigns to inv .This is a conditional statement. If in is not equal to zero, then inv is assigned the value 1/in. Otherwise, inv is assigned the value 0.

  out <== -in*inv +1; //The arrow creates a constraint and also assigns a value. In the code above, out is constrained to be equal -in*inv + 1.
  in*out === 0; // It is not assigning zero to in*out. Rather, it is enforcing that in*out does in fact equal zero.
} 

component main = SumOfSquares();