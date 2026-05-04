pragma circom 2.1.6;

// If input is 0 return 1, else return 0

template IsZero() {
  signal input in;
  signal output out;

  signal inv;
  inv <-- in == 0 ? 1 : 1/in;
  out <== 1 - in * inv;

  in * out === 0;
}

component main = IsZero();
