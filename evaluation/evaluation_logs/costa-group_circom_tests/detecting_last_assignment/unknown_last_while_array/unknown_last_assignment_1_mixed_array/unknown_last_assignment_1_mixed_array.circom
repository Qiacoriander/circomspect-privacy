
template C(){
    signal input in[3];
    signal output out[3];
    
    out <== in;
}


template B(n){
    signal input in1[n][3];
    signal input in2[n][2][3];
    signal output out;

    out <== in1[0][2] * in2[n-1][1][0];
}


template A(n){

   signal input in[3];
   
   signal output out;
   
   component a = B(n);
   component a1 = C();
   
   var mivar[3] = in;
   a1.in <== in;
   
   for (var i = 0; i < n; i++){
         
       a.in1[i] <== a1.out;
       a.in2[i][1] <== mivar;
       a.in2[i][0] <== a1.out;   
   }

   out <== a.out;
    
}


component main = A(5);
