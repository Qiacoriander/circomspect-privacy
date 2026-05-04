


template A(){
   signal input in;
   signal output out[10];
   var i = 0;
   
   
   while (in > i){
       out[i] <-- in;
       i = i + 1;
   }
}

component main = A();
