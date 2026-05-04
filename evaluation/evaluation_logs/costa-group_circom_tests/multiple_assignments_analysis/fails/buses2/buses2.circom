bus MiBusPeque{
    signal a[2];
}


bus MiBus{
   signal b;
   MiBusPeque a[2];
}



template A(){
   MiBus input in;
   MiBus output out;
   
   if (in.b > 10){
       out.b <-- 4;
   } else{
       out.b <-- 0;

   }
   out <== in;

}

component main = A();
