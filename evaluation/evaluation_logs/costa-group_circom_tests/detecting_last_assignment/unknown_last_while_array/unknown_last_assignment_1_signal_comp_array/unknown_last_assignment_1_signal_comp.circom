
template C(){
    signal input in[3];
    signal output out[3];
    
    out <== in;
}


template B(n){
    signal input in1[n][3];
    signal input in2[n][3];
    signal output out;

    out <== in1[0][1] * in2[n-1][2];
}


template A(n){

   signal input in[3];
   
   signal output out;
   
   component a = B(n);
   component a1 = C();
   
   a1.in <== in;
   
   for (var i = 0; i < n; i++){
         
	a.in1[i] <== a1.out;
        a.in2[i] <== a1.out;
   }
   
   out <== a.out;
    
}


component main = A(3);
