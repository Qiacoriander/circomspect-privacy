pragma circom 2.0.0;

// Comparator: ถ้า in[0] < in[1] → out = 1, ไม่งั้น out = 0
template LessThan(n) {
    signal input in[2];
    signal output out;

    signal bits[n];
    var sum = (1 << n) + in[1] - in[0];
    
    for (var i = 0; i < n; i++) {
        bits[i] <-- (sum >> i) & 1;
        bits[i] * (bits[i] - 1) === 0;
    }
    
    out <== 1 - bits[n-1];
}

// GreaterEqThan: ถ้า in[0] >= in[1] → out = 1
template GreaterEqThan(n) {
    signal input in[2];
    signal output out;

    component lt = LessThan(n);
    lt.in[0] <== in[0];
    lt.in[1] <== in[1];
    out <== 1 - lt.out;
}

template AgeCheck() {
    // Public inputs (Verifier เห็น)
    signal input minAge;
    signal input currentYear;

    // Private inputs (ซ่อนใน Knox Vault)
    signal input birthYear;

    // Output
    signal output isOldEnough;

    // คำนวณอายุ
    signal age;
    age <== currentYear - birthYear;

    // เช็คว่า age >= minAge
    component gte = GreaterEqThan(8);  // รองรับค่า 0-255
    gte.in[0] <== age;
    gte.in[1] <== minAge;
    
    isOldEnough <== gte.out;
}

component main {public [minAge, currentYear]} = AgeCheck();