template B(n){
    signal input in1[n][3];
    signal input in2[n][2][3];
    signal output out;

    out <== in1[0][2] * in2[n-1][1][0];
}



template A(n){

   signal input in1[3];
   signal input in2[3];
   
   signal output out;
   
   component a = B(n);
   
   for (var i = 0; i < n; i++){
         
	a.in1[i] <== in1;
        a.in2[i] <== [in2, in2];
   }

   
   out <== a.out;
    
}


component main = A(7);
