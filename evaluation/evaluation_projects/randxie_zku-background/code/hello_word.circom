pragma circom 2.0.3;

// Define the multiplication function.
template Multiplier2(){
   // specify the first input.
   signal input in1;
   // specify the second input.
   signal input in2;
   // specify a variable to store output.
   signal output out;
   // Multiply the first and the second input.
   out <== in1 * in2;
   // Print the output.
   log(out);
}

component main {public [in1,in2]} = Multiplier2();

/* INPUT = {
    "in1": "5",
    "in2": "77"
} */