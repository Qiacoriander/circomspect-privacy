

template B(n){
    signal input in1[n];
    signal input in2[n][2];
    signal output out;

    out <== in1[0] * in2[n-1][1];
}


template A(n){

   signal input in1;
   signal input in2;
   
   signal output out;
   
   component a = B(n);
   
   for (var i = 0; i < n; i++){
         
	a.in1[i] <== in1;
        a.in2[i] <== [in2, in2];
   }

   
   out <== a.out;
    
}


component main = A(7);
