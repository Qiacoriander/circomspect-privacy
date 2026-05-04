pragma circom 2.0.0;

function foo(x) {
  var bar[1+1];       // this is the problematic line. `var bar[2];` works
  bar[0] = x;
  bar[1] = x;
  return bar;
}

template Main() {
  signal input  inp;
  signal output out;

  var baz[2] = foo(5);

  out <== inp + baz[0];
}

component main {public [inp]} = Main();
