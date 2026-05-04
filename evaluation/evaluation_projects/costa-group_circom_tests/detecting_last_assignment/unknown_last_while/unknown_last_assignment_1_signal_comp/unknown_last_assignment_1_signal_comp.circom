
template C(){
    signal input in;
    signal output out;
    
    out <== in * in;
}


template B(n){
    signal input in1[n];
    signal input in2[n];
    signal output out;

    out <== in1[0] * in2[n-1];
}


template A(n){

   signal input in;
   
   signal output out;
   
   component a = B(n);
   component a1 = C();
   
   a1.in <== in;
   
   for (var i = 0; i < n; i++){
         
	a.in1[i] <== a1.out;
        a.in2[i] <== a1.out + 6;
   }
   
   out <== a.out;
    
}


component main = A(3);
