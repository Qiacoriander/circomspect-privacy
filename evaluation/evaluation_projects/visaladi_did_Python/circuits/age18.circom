pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";

template Age18() {
    signal input birthYear;     // PRIVATE
    signal input currentYear;   // PUBLIC
    signal output ok;

    // 1) Prove birthYear <= currentYear  (prevent wrap-around on subtraction)
    // LessThan(n).out = 1 if in[0] < in[1]
    component byLt = LessThan(32);
    signal currentPlus1;
    currentPlus1 <== currentYear + 1;

    byLt.in[0] <== birthYear;
    byLt.in[1] <== currentPlus1;
    byLt.out === 1;  // birthYear < currentYear+1  => birthYear <= currentYear

    // 2) Compute age
    signal age;
    age <== currentYear - birthYear;

    // 3) Prove age >= 18
    // age >= 18  <=>  NOT(age < 18)
    component ageLt18 = LessThan(32);
    ageLt18.in[0] <== age;
    ageLt18.in[1] <== 18;
    ageLt18.out === 0; // ensures age is NOT < 18 => age >= 18

    ok <== 1;
}

component main { public [currentYear] } = Age18();
