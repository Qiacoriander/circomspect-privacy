pragma circom 2.0.0;

function foo(x) {
  var n = 1;
  var bar[n+1 * n][n + 1];       // this is the problematic line. `var bar[2];` works
  bar[0][0] = x;
  bar[0][1] = x;
  return bar[1][1];
}

template Main() {
  signal input  inp;
  signal output out;

  var baz = foo(inp);

  out <== inp + baz;
}

component main {public [inp]} = Main();
