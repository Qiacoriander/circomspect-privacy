pragma circom 2.1.2;

template Eq(termLength) {
  signal input l[termLength];
  signal input r[termLength];
  signal interim[termLength];
  signal output out;

  interim[0] <== (l[0] == r[0]);
  for (var i = 1; i < termLength; i ++) {
    interim[i] <== (l[i] == r[j]) && interim[i - 1];
  }
  out <== interim[termLength - 1];
}

// TODO: Handle the path length 0 case
template Path(minLength, maxLength, termLength) {
  // REMEMBER THIS IS ALL ALREADY INSTANTIATED SINCE THESE ARE INPUT TRIPLES
  signal input path[maxLength][3][termLength];
  signal input predicate[termLength];
  signal input subject[termLength];
  signal input object[termLength];
  signal acc[maxLength - minLength + 1];

  0 === (object[0] == 999999);
  0 === (subject[0] == 999999);

  if (minLength == 0) {
    acc[0] <== Eq(termLength)(object, subject);
  } else {
    acc[0] <== Eq(termLength)(object, path[minLength][2]);
  }

  for (var i = 0; i < maxLength; i += 1) {
    // TODO: Check - I think this might need to be minLength - 1
    if (i > minLength) {
      acc[i - minLength] <== Eq(termLength)(object, path[i][2]) || acc[i - minLength - 1];
    }

    for (var j = 0; j < termLength; j += 1) {

      // TODO: SEE IF THIS IS NECESSARY
      // Check that there are no "empty" terms after real terms
      if (i >= minLength && i > 0) {
        for (var k = 0; k < 2; k ++) {
          1 === (path[i][k][j] == 999999 || path[i-1][k][j] != 999999);
        }
      }

      // Check the predicate is as expected
      if (i >= minLength) {
        1 === (path[i][1][j] == predicate[j]) || (path[i][1][j] == 999999);
      } else {
        1 === (path[i][1][j] == predicate[j]);
      }

      if (i >= 1) {
        // Check the path does continue as expected
        if (i >= minLength) {
          1 === (path[i-1][2][j] == path[i][0][j]) || (path[i][0][j] == 999999);
        } else {
          1 === (path[i-1][2][j] == path[i][0][j]);
        }
      }
    }
  }

  acc[maxLength - minLength + 1] === 1;
}
