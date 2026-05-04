pragma circom 2.0.0;

function F(a, b){
	var c[2][3];
    c[0][0] = a + b[0];
    c[0][1] = a + b[1];
    c[0][2] = a + b[0] + b[1];
	return c[0];
}

template T() {
    signal input a;
    signal input b[2];
    signal output out1;
    signal output out2;
    signal output out3;
    var temp[3] = F(a, b);
    out1 <== temp[0];
    out2 <== temp[1];
    out3 <== temp[2];
}

component main = T();
    