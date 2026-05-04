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

component main = SumOfSquares();


// Circom templates are reusable and composeable 
// Here, Square is a template used by SumOfSquares. 
// Note how inputs a and b are “wired” to the component Square().
// You can think of the <== operator as “wiring” the components together by referencing their inputs or outputs.

// Multiple inputs to a component

/*
The example Square above takes a single signal as an input, but if a component takes multiple inputs, it is conventional to specify this as an array in[n]. 
The following component takes two numbers and returns their product:
*/
template Mul {

    signal input in[2]; // takes two inputs
    signal output out; // single output
    
    out <== in[0] * in[1];
}


/*
It is conventional to name the input signals in or as an array in[] and output signal(s) to be out or out[].
*/