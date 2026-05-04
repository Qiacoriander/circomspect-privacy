pragma circom 2.0.0;

function F(a, b){
	var c = a + b;
	return c;
}

template M() {
    signal input in;
    signal output out;
    out <== in * in;
}


template T() {
    signal input a;
    signal output out1;
    signal output out2;
    signal output out3;
    component m1 = M();
    component m2 = M();
    m1.in <== a;
    m2.in <== a;
    out1 <== m1.out;
    out2 <== m2.out;
    out3 <-- F(out1, out2);
}

component main = T();
    