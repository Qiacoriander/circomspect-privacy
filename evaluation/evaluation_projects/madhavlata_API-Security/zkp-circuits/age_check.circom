pragma circom 2.0.0;

// Import the comparators library from node_modules
include "node_modules/circomlib/circuits/comparators.circom";

/*
  This is the final, correct circuit for the age check.
  It uses a LessThan component from circomlib to safely perform comparisons.
*/
template IsOver18() {
   // Private input
   signal input birthYear;
   
   // Public input
   signal input currentYear;
   
   // Public output
   signal output isOver18;

   // Calculate the age
   signal age <== currentYear - birthYear;

   // To check if age >= 18, we can check that age is NOT less than 18.
   // We use a 32-bit comparator, which is safe for realistic ages.
   component isLessThan18 = LessThan(32);
   isLessThan18.in[0] <== age;
   isLessThan18.in[1] <== 18;

   // isLessThan18.out will be 1 if age < 18, and 0 otherwise.
   // We want the opposite for isOver18.
   isOver18 <== 1 - isLessThan18.out;
}

// Instantiate the main component and declare the public input.
component main {public [currentYear]} = IsOver18();