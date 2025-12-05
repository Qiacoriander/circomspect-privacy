pragma circom 2.0.0;

include "math_lib.circom";
include "basic_components.circom";
include "advanced_math.circom";

/*
 * 测试include语句的文件
 * 这个文件包含了对多个文件的include，并使用了这些文件中的函数和模板
 */

// 使用math_lib.circom中的函数
template MathFunctions() {
    signal input x;
    signal input y;
    signal output maxResult;
    signal output minResult;
    signal output absResult;
    signal output powResult;
    signal output factorialResult;
    signal output fibonacciResult;
    
    // 使用max函数
    maxResult <== max(x, y);
    
    // 使用min函数
    minResult <== min(x, y);
    
    // 使用abs函数
    absResult <== abs(x - y);
    
    // 使用pow函数
    powResult <== pow(x, 2);
    
    // 使用factorial函数
    factorialResult <== factorial(5);
    
    // 使用fibonacci函数
    fibonacciResult <== fibonacci(10);
}

// 使用basic_components.circom中的模板
template BasicCircuits(n) {
    signal input a[n];
    signal input b[n];
    signal output adderResult[n];
    signal output multiplierResult[n];
    
    // 实例化Adder模板
    component adder = Adder(n);
    for (var i = 0; i < n; i++) {
        adder.a[i] <== a[i];
        adder.b[i] <== b[i];
        adderResult[i] <== adder.out[i];
    }
    
    // 实例化Multiplier模板
    component multiplier = Multiplier(n);
    for (var i = 0; i < n; i++) {
        multiplier.a[i] <== a[i];
        multiplier.b[i] <== b[i];
        multiplierResult[i] <== multiplier.out[i];
    }
}

// 使用advanced_math.circom中的模板
template AdvancedCircuits() {
    signal input x;
    signal input a;
    signal input b;
    signal input c;
    signal input n;
    signal input k;
    signal output polyResult;
    signal output combResult;
    signal output fibSumResult;
    signal output maxResult;
    signal output minResult;
    
    // 实例化Polynomial模板
    component poly = Polynomial();
    poly.x <== x;
    poly.a <== a;
    poly.b <== b;
    poly.c <== c;
    polyResult <== poly.y;
    
    // 实例化Combination模板
    component comb = Combination();
    comb.n <== n;
    comb.k <== k;
    combResult <== comb.result;
    
    // 实例化FibonacciSum模板
    component fibSum = FibonacciSum();
    fibSum.n <== n;
    fibSumResult <== fibSum.sum;
    
    // 实例化MinMax模板
    component minMax = MinMax();
    minMax.a <== a;
    minMax.b <== b;
    maxResult <== minMax.maximum;
    minResult <== minMax.minimum;
}

// 主模板，组合使用多个文件中的函数和模板
template IncludeMain(n) {
    signal input x;
    signal input y;
    signal input a[n];
    signal input b[n];
    signal input coeffs[3]; // a, b, c for polynomial
    signal input combinationParams[2]; // n, k for combination
    
    signal output mathResults[6]; // max, min, abs, pow, factorial, fibonacci
    signal output circuitResults[2][n]; // adder, multiplier
    signal output advancedResults[5]; // poly, comb, fibSum, max, min
    
    // 使用MathFunctions模板
    component mathFuncs = MathFunctions();
    mathFuncs.x <== x;
    mathFuncs.y <== y;
    mathResults[0] <== mathFuncs.maxResult;
    mathResults[1] <== mathFuncs.minResult;
    mathResults[2] <== mathFuncs.absResult;
    mathResults[3] <== mathFuncs.powResult;
    mathResults[4] <== mathFuncs.factorialResult;
    mathResults[5] <== mathFuncs.fibonacciResult;
    
    // 使用BasicCircuits模板
    component basicCircs = BasicCircuits(n);
    for (var i = 0; i < n; i++) {
        basicCircs.a[i] <== a[i];
        basicCircs.b[i] <== b[i];
        circuitResults[0][i] <== basicCircs.adderResult[i];
        circuitResults[1][i] <== basicCircs.multiplierResult[i];
    }
    
    // 使用AdvancedCircuits模板
    component advCircs = AdvancedCircuits();
    advCircs.x <== x;
    advCircs.a <== coeffs[0];
    advCircs.b <== coeffs[1];
    advCircs.c <== coeffs[2];
    advCircs.n <== combinationParams[0];
    advCircs.k <== combinationParams[1];
    advancedResults[0] <== advCircs.polyResult;
    advancedResults[1] <== advCircs.combResult;
    advancedResults[2] <== advCircs.fibSumResult;
    advancedResults[3] <== advCircs.maxResult;
    advancedResults[4] <== advCircs.minResult;
}