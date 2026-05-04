template BadMultiOR(n) {

		signal input in[n];
		signal output out;
		
		var sum;
		for (var i = 0; i < n; i++) {
				sum += in[i];
		}
		
		out <== GreaterThan(sum, 0);
}

template GoodMultiOR(n) {
  signal input in[n];
	signal output out;
		
  signal sum[n];
  sum[0] <== in[0];
  for (var i = 1; i < n; i++) {
      sum[i] <== sum[i - 1] + in[i];
  }
  
  out <== GreaterThan(sum, 0);
}

// component main = GoodMultiOR(5);