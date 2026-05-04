pragma circom 2.1.8;

include "../node_modules/circomlib/circuits/comparators.circom";

template MaxOfArray(n) {
  signal input in[n];
  signal output out;

  assert(n > 0);

  component gts[n - 1];
  signal maxs[n];
  signal branches1[n - 1];
  signal branches2[n - 1];

  maxs[0] <== in[0];

  for (var i = 1; i < n; i++) {
    gts[i - 1] = GreaterThan(252);
    gts[i - 1].in[0] <== in[i];
    gts[i - 1].in[1] <== maxs[i - 1];

    // gts[i-1].out returns 1 if in[i] > maxs[i-1], otherwise 0.
    //
    // case 1: in[i] > maxs[i-1]
    //          maxs[i] <== 1 * in[i] + (1 - 1) * maxs[i-1]
    //
    // case 2: in[i] <= maxs[i-1]
    //          maxs[i] <== 0 * in[i] + (1 - 0) * maxs[i-1]
    branches1[i - 1] <== gts[i - 1].out * in[i];
    branches2[i - 1] <== (1 - gts[i - 1].out) * maxs[i - 1];

    maxs[i] <== branches1[i - 1] + branches2[i - 1];
    // maxs[i] <== gts[i - 1].out * in[i] + (1 - gts[i - 1].out) * maxs[i - 1];
  }

  out <== maxs[n - 1];
}

component main = MaxOfArray(4);