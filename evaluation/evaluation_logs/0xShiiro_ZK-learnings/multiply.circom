// pragma circom 2.1.6;

// template Multiply() {
//   signal input a;
//   signal input b;
//   signal input c;
//   signal output out;

//   out <== a * b;
//   // out <== a * b * c; // THis will lead to an error as we can multiply only two numbers at a time and not three
// }

// component main = Multiply();

// for multiplying three inputs we can follow this steps 
pragma circom 2.1.6;

template Multiply() {
  signal input a;
  signal input b;
  signal input c;
  signal s1;
  signal output out;
  
  s1 <== a * b;
  out <== s1 * c;
  // These are the other two ways to multiply two numbers in circom 
  // c <-- a * b;
  //   c === a * b; 
}

component main = Multiply();
// component main {public [a, c]} = SomePublic(); // In this function we are making the inputs a and c public and b remains hidden as it is not mentioned in the public array
