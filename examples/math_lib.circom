pragma circom 2.0.0;

/*
 * 数学函数库，包含一些基本的数学运算函数
 */

// 计算两个数的最大值
function max(a, b) {
    if (a > b) {
        return a;
    } else {
        return b;
    }
}

// 计算两个数的最小值
function min(a, b) {
    if (a < b) {
        return a;
    } else {
        return b;
    }
}

// 计算绝对值
function abs(x) {
    if (x < 0) {
        return -x;
    } else {
        return x;
    }
}

// 计算幂
function pow(base, exponent) {
    if (exponent == 0) {
        return 1;
    }
    
    var result = 1;
    for (var i = 0; i < exponent; i++) {
        result = result * base;
    }
    return result;
}

// 计算阶乘
function factorial(n) {
    if (n <= 1) {
        return 1;
    }
    
    var result = 1;
    for (var i = 2; i <= n; i++) {
        result = result * i;
    }
    return result;
}

// 计算斐波那契数列的第n项
function fibonacci(n) {
    if (n <= 0) {
        return 0;
    }
    if (n == 1) {
        return 1;
    }
    
    var a = 0;
    var b = 1;
    var result = 0;
    
    for (var i = 2; i <= n; i++) {
        result = a + b;
        a = b;
        b = result;
    }
    
    return result;
}