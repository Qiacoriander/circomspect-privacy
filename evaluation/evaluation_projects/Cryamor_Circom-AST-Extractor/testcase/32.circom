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
    component c = A();
    b <== c.out;
    b.in ==> c.aaa;
    b.out === c.in;
    c --> s.a;
}

component main = B();