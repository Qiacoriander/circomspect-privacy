pragma circom 2.0.0;

include "math_lib.circom";

/*
 * 高级数学模板，使用math_lib.circom中的函数
 */

// 计算多项式的值：a*x^2 + b*x + c
template Polynomial() {
    signal input x;
    signal input a;
    signal input b;
    signal input c;
    signal output y;
    
    // 使用pow函数计算x的平方
    var x_squared = pow(x, 2);
    
    // 计算多项式的值
    y <== a * x_squared + b * x + c;
}

// 计算n!/(k!(n-k)!)，即组合数C(n,k)
template Combination() {
    signal input n;
    signal input k;
    signal output result;
    
    // 使用阶乘函数计算组合数
    var n_factorial = factorial(n);
    var k_factorial = factorial(k);
    var n_minus_k_factorial = factorial(n - k);
    
    result <== n_factorial / (k_factorial * n_minus_k_factorial);
}

// 计算斐波那契数列的前n项和
template FibonacciSum() {
    signal input n;
    signal output sum;
    
    var total = 0;
    for (var i = 1; i <= n; i++) {
        total += fibonacci(i);
    }
    
    sum <== total;
}

// 计算两个数的最大值和最小值
template MinMax() {
    signal input a;
    signal input b;
    signal output maximum;
    signal output minimum;
    
    // 使用max和min函数
    maximum <== max(a, b);
    minimum <== min(a, b);
}