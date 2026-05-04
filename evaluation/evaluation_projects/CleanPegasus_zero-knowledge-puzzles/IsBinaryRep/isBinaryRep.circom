pragma circom 2.1.6;

// Create a circuit that takes an array of signals `in[n]` and
// a signal v. The circuit should check if `v` is the decimal 
// representation of the signal in[n] in binary.

template IsBinaryRep(n) {
    signal input in[n];
    signal input v;

    var acc = 0;
    var exp = 1;
    for(var i = 0; i < n; i++) {
      in[i] * (in[i] - 1) === 0;
      acc += in[i] * exp;
      exp = 2 * exp;
    }

    acc === v;

}

component main{public [v]} = IsBinaryRep(4);

