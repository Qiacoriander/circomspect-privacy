
template C(){
    signal input in;
    signal output out;
    
    out <== in * in;
}


template B(n){
    signal input in1[n];
    signal input in2[n][2];
    signal output out;

    out <== in1[0] * in2[n-1][1];
}


template A(n){

   signal input in;
   
   signal output out;
   
   component a = B(n);
   component a1 = C();
   
   var mivar = in;
   a1.in <== in;
   
   for (var i = 0; i < n; i++){
         
       a.in1[i] <== a1.out;
       a.in2[i][1] <== mivar;
       a.in2[i][0] <== a1.out;   
   }

   out <== a.out;
    
}


component main = A(5);
