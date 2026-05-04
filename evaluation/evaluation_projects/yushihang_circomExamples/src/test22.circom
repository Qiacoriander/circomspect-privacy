pragma circom 2.2.0;

template B() {
  signal input in;
  signal output out;
  out <== in + 1;
}

template A(n) {
  signal out;
  if(n == 2) {
    signal aux <== 2;
    out <== B()(aux);
  } else {
    out <== 5;
  }
}

component main = A(3);