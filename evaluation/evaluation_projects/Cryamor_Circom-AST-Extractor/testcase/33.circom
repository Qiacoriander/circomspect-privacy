// dot

pragma circom 2.1.0;

template A() {
    signal input a;
    signal output b;
    b <== a;
}

template B() {
    signal input a;
    signal output b;
    a++;
    b--;
    for(var j=1;j<10;j++){
    j--;
    }
    for(var i=2;i<10;i--){
    i++;
    }
    b <== a;
}

component main = B();