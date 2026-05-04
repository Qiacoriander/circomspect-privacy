pragma circom 2.1.4;

// The template 'ForLoop' takes an array 'a' of length 2 as input.
// It adds the elements of the array 'a[0]' and 'a[1]' four times in a loop and outputs the result in 'c'.

template ForLoop() {
    // Define input signals 'a', an array with 2 elements.
    signal input a[2];
    
    // Define the output signal 'c' which will store the result of the addition.
    signal output c;

    // Initialize a variable 'sum' to store the cumulative result of the additions.
    // NOTE: This is a regular JavaScript variable, not a Circom signal.
    var sum = 0;

    // A for loop that runs 4 times to perform the addition.
    for (var i = 0; i < 4; i++) {
        // In each iteration, add 'a[0]' and 'a[1]' to 'sum'.
        sum += a[0] + a[1];
    }

    // Assign the final value of 'sum' to the output signal 'c'.
    // This will output the result of adding 'a[0]' and 'a[1]' four times.
    c <== sum;

}  

// Instantiate the main component that will execute the 'ForLoop' template.
component main = ForLoop();
