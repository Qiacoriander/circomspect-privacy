pragma circom 2.1.2;

template isliteral() {
  signal input term[128];
  signal output out[128];

  out[0] <-- 4;
  out[1] <-- (term[0] != 0) && (term[0] != 1);

  for (var i = 2; i < 128; i++) {
    out[i] <-- 0;
  }
}

template lang() {
  signal input in[128];
  signal output out[128];

  in[0] === 2;
  out[0] <== 3;

  for (var i = 1; i < 8; i++) {
    out[i] <== in[i];
  }
}

template all(numBits) {
  signal input in[numBits];
  signal interim[numBits];
  signal output out;

  interim[0] <-- in[0];
  for (var i = 1; i < numBits; i++) {
    interim[i] <-- in[i] && interim[i - 1];
  }

  out <-- interim[numBits - 1];
}

template eq(numBits) {
  signal input l[numBits];
  signal input r[numBits];
  signal interim[numBits];
  signal output out;

  for (var i = 0; i < numBits; i++) {
    interim[i] <-- l[i] == r[i];
  }

  out <-- all(numBits)(interim);
}

template equal() {
  signal input l[128];
  signal input r[128];
  signal output out[128];

  out[0] <-- 4;
  out[1] <-- eq(128)(l, r);

  for (var i = 2; i < 128; i++) {
    out[i] <-- 0;
  }
}
