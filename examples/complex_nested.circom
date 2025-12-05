pragma circom 2.0.0;

include "math_lib.circom";
include "basic_components.circom";
include "advanced_math.circom";
include "instantiation_test.circom";
include "include_test.circom";

/*
 * 复杂嵌套调用的测试文件
 * 这个文件包含了深层次的模板嵌套和函数调用
 */

// 递归调用的斐波那契模板
template RecursiveFibonacci(n) {
    signal output out;
    
    // 基本情况
    if (n <= 1) {
        out <== n;
    } else {
        // 递归调用
        component fib1 = RecursiveFibonacci(n-1);
        component fib2 = RecursiveFibonacci(n-2);
        out <== fib1.out + fib2.out;
    }
}

// 多层嵌套的计算模板
template NestedCalculation(depth, width) {
    signal input x;
    signal output result;
    
    // 基本情况
    if (depth <= 0) {
        result <== x;
    } else {
        // 创建多个子计算
        component subCalcs[width];
        for (var i = 0; i < width; i++) {
            subCalcs[i] = NestedCalculation(depth-1, width);
            subCalcs[i].x <== x + i;
        }
        
        // 合并结果
        var sum = 0;
        for (var i = 0; i < width; i++) {
            sum += subCalcs[i].result;
        }
        result <== sum / width;
    }
}

// 使用多个文件中的模板和函数的复杂电路
template ComplexCircuit(n) {
    signal input values[n];
    signal input coeffs[3]; // a, b, c for polynomial
    signal output results[5];
    
    // 使用math_lib.circom中的函数
    var maxVal = 0;
    for (var i = 0; i < n; i++) {
        maxVal = max(maxVal, values[i]);
    }
    
    // 使用advanced_math.circom中的模板
    component poly = Polynomial();
    poly.x <== maxVal;
    poly.a <== coeffs[0];
    poly.b <== coeffs[1];
    poly.c <== coeffs[2];
    
    // 使用basic_components.circom中的模板
    component comparator = Comparator();
    comparator.a <== maxVal;
    comparator.b <== poly.y;
    
    // 使用instantiation_test.circom中的模板
    component simpleAdder = SimpleAdder();
    simpleAdder.a <== maxVal;
    simpleAdder.b <== poly.y;
    
    // 使用include_test.circom中的模板
    component mathFuncs = MathFunctions();
    mathFuncs.x <== maxVal;
    mathFuncs.y <== poly.y;
    
    // 使用本文件中的递归模板
    component fib = RecursiveFibonacci(5);
    
    // 使用本文件中的嵌套模板
    component nested = NestedCalculation(3, 2);
    nested.x <== maxVal;
    
    // 输出结果
    results[0] <== poly.y;
    results[1] <== comparator.lt;
    results[2] <== simpleAdder.sum;
    results[3] <== fib.out;
    results[4] <== nested.result;
}

// 循环依赖测试
template CircularDependencyA(n) {
    signal input x;
    signal output y;
    
    if (n <= 0) {
        y <== x;
    } else {
        component b = CircularDependencyB(n-1);
        b.x <== x;
        y <== b.y;
    }
}

template CircularDependencyB(n) {
    signal input x;
    signal output y;
    
    if (n <= 0) {
        y <== x;
    } else {
        component a = CircularDependencyA(n-1);
        a.x <== x;
        y <== a.y;
    }
}

// 主模板，组合使用多个复杂组件
template ComplexMain(n) {
    signal input values[n];
    signal input coeffs[3];
    signal output finalResults[7];
    
    // 使用ComplexCircuit模板
    component complex = ComplexCircuit(n);
    for (var i = 0; i < n; i++) {
        complex.values[i] <== values[i];
    }
    for (var i = 0; i < 3; i++) {
        complex.coeffs[i] <== coeffs[i];
    }
    
    // 使用CircularDependency模板
    component circularA = CircularDependencyA(3);
    circularA.x <== values[0];
    
    // 使用instantiation_test.circom中的Main模板
    component instMain = Main(n);
    for (var i = 0; i < n; i++) {
        instMain.a[i] <== values[i];
        instMain.b[i] <== values[(i+1) % n];
    }
    
    // 输出结果
    for (var i = 0; i < 5; i++) {
        finalResults[i] <== complex.results[i];
    }
    finalResults[5] <== circularA.y;
    finalResults[6] <== instMain.addResult[0];
}