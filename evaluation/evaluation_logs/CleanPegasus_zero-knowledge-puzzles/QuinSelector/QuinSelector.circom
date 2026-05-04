pragma circom 2.1.6;

// Dot product
template EscalarProduct(w) {
  signal input in_1[w];
  signal input in_2[w];
  signal output out;

  var lc = 0;

  signal temp[w];
  for(var i; i < w; i++) {
    temp[i] <== in_1[i] * in_2[i];
    lc += temp[i];
  }
  out <== lc;

}

template Decoder(n) {
  signal input in;
  signal output out[n];

  signal success;

  var acc;

  for(var i; i<n; i++) {
    out[i] <-- i == in ? 1 : 0;
    out[i] * (in - i) === 0;
    acc += out[i];
  }

  success <== acc;
  success * (success - 1) === 0;
}

template QuinSelector(n) {
  signal input in[n];
  signal input selector;
  signal output out;

  component decoder = Decoder(n);
  decoder.in <== selector;

  component scalar_product = EscalarProduct(n);
  scalar_product.in_1 <== in;
  scalar_product.in_2 <== decoder.out;

  out <== scalar_product.out;
}

// component main = QuinSelector(6);
