pragma circom 2.1.4;

// Input : 'a',array of length 2 .
// Output : 'c 
// Using a forLoop , add a[0] and a[1] , 4 times in a row .

template ForLoop() {
    signal input a[2];
    signal output c;
    var sum;
    var ans;
    for(var i=0; i<4; i++){
        sum = a[0] + a[1];
        ans += sum;
    }
    c <== ans;

}  

component main = ForLoop();
