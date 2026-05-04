pragma circom 2.0.0;

template Lang() {
  signal input in[128];
  signal output out[127];

  in[0] === 2;

  for (var i = 1; i < 128; i++) {
    out[i - 1] <== in[i];
  }
}

template StringEquals() {
  signal input in[2][127];

  for (var i = 0; i < 8; i++) {
    in[0][i] === in[1][i];
  }
}
