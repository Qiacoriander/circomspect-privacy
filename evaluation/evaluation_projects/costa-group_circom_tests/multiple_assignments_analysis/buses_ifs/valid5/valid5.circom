bus MiBusPeque{
    signal a[2];
}


bus MiBus{
   signal b;
   MiBusPeque a[2];
}



template A(){
   MiBus input in;
   signal input in1;
   MiBus output out;
   
   if (in.b > 10){
       out.b <-- 2;
   } else{
       out <-- in;
   }

}

component main = A();
