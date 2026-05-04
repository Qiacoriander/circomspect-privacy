pragma circom 2.1.6;

bus A(){
    signal x;
    signal y;
}


template B(){
	A() input in;
	output A() {tag} out;
	out.tag = 2;
	out <== in;
	 
}

component main = B();
