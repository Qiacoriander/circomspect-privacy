bus MiBusPeque{
    signal a[2];
}


bus MiBus{
   signal b;
   MiBusPeque a[2];
}



template A(){
   MiBus input in;
   MiBusPeque output out[2];
   
   if (in.b > 10){
       out <-- in.a;
   } else{
       if (in.b > 20){
           out[0] <-- in.a[1];
           out[1] <-- in.a[0];
       } else{
           out <-- in.a;
       }
   }

}

component main = A();


