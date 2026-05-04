pragma circom 2.1.4;
include "../node_modules/circomlib/circuits/comparators.circom";

// Input 3 values using 'a' (array of length 3) and check if they all are equal.
// Return the result using the signal 'c'.

template Equality() {
   // Define input signal array 'a' with 3 elements
   signal input a[3];

   // Define output signal 'c' which will store the result
   signal output c;

   // Instantiate the first IsEqual component to compare the first two values
   component eq1 = IsEqual();

   // Instantiate the second IsEqual component to compare the second and third values
   component eq2 = IsEqual();

   // Check if a[0] == a[1] by assigning a[0] and a[1] to eq1's input
   eq1.in[0] <== a[0];
   eq1.in[1] <== a[1];

   // Check if a[1] == a[2] by assigning a[1] and a[2] to eq2's input
   eq2.in[0] <== a[1];
   eq2.in[1] <== a[2];

   // The output 'c' will be 1 (true) only if both comparisons are true (i.e., all three values are equal)
   // Multiply the outputs of eq1 and eq2. If both are 1, the result will be 1; otherwise, it will be 0.
   c <== eq1.out * eq2.out;
}

// Instantiate the main component that will execute the Equality template
component main = Equality();
