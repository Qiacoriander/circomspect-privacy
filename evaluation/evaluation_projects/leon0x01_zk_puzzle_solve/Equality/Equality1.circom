pragma circom 2.1.4;

// Input 3 values using 'a'(array of length 3) and check if they all are equal.
// Return using signal 'c'.

template IsZero() {
    signal input in;
    signal output out;

    signal inv;

    inv <-- in!=0 ? 1/in : 0;

    out <== -in*inv +1;
    in*out === 0;
}

template Equality() {
   // Your Code Here..
   signal input a[3];
   signal ans;
   signal ans1;
   signal ans2;
   signal ans3;
   signal ans4;
   signal output c;

   component isz = IsZero();
   a[2] - a[1] ==> ans;
   a[1] - a[0] ==> ans1;
   a[2] - a[1] ==> ans2;
   ans + ans1 ==> ans3;
   ans2 + ans3 ==> ans4;
   ans4 ==> isz.in;
   isz.out ==> c;
   
}

component main = Equality();