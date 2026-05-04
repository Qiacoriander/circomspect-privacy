pragma circom 2.0.3;

template Multiplier2(){
   signal input in1; // declare an input signal in1
   signal input in2; // declare an input signal in2
   signal output out; // declare an output signal out
   out <== in1 * in2; // initialize out with in1*in2
   log(out); // print `out`
}

component main {public [in1,in2]} = Multiplier2(); // call the main component with in1 and in2 as public signals

/* INPUT = {
    "in1": "10",
    "in2": "77"
} */