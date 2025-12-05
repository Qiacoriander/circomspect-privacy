pragma circom 2.0.0;

include "basic_components.circom";

/*
 * 测试模板实例化的文件
 * 这个文件包含了对basic_components.circom中模板的实例化
 */

// 简单的加法器实例化
template SimpleAdder() {
    signal input a;
    signal input b;
    signal output sum;
    
    sum <== a + b;
}

// 使用Adder模板的复合加法器
template CompositeAdder(n) {
    signal input a[n];
    signal input b[n];
    signal output sum[n];
    
    // 实例化Adder模板
    component adder = Adder(n);
    
    // 连接输入和输出
    for (var i = 0; i < n; i++) {
        adder.a[i] <== a[i];
        adder.b[i] <== b[i];
        sum[i] <== adder.out[i];
    }
}

// 使用Multiplier模板的复合乘法器
template CompositeMultiplier(n) {
    signal input a[n];
    signal input b[n];
    signal output product[n];
    
    // 实例化Multiplier模板
    component multiplier = Multiplier(n);
    
    // 连接输入和输出
    for (var i = 0; i < n; i++) {
        multiplier.a[i] <== a[i];
        multiplier.b[i] <== b[i];
        product[i] <== multiplier.out[i];
    }
}

// 使用Comparator模板的比较器
template NumberComparator() {
    signal input a;
    signal input b;
    signal output isLess;
    signal output isEqual;
    signal output isGreater;
    
    // 实例化Comparator模板
    component comparator = Comparator();
    
    // 连接输入和输出
    comparator.a <== a;
    comparator.b <== b;
    isLess <== comparator.lt;
    isEqual <== comparator.eq;
    isGreater <== comparator.gt;
}

// 使用Selector模板的多路选择器
template MultiSelector(n) {
    signal input values[n];
    signal input selector[n];
    signal output selected;
    
    // 确保只有一个选择器为1
    var sum = 0;
    for (var i = 0; i < n; i++) {
        selector[i] * (1 - selector[i]) === 0; // 确保是0或1
        sum += selector[i];
    }
    sum === 1;
    
    // 使用多个Selector模板实现多路选择
    component selectors[n-1];
    
    // 第一个选择器
    selectors[0] = Selector();
    selectors[0].in0 <== values[0];
    selectors[0].in1 <== values[1];
    selectors[0].sel <== selector[1];
    
    // 其余选择器
    for (var i = 1; i < n-1; i++) {
        selectors[i] = Selector();
        selectors[i].in0 <== selectors[i-1].out;
        selectors[i].in1 <== values[i+1];
        selectors[i].sel <== selector[i+1];
    }
    
    // 最终输出
    selected <== selectors[n-2].out;
}

// 使用BitwiseOps模板的位运算器
template BitOperator(n) {
    signal input a[n];
    signal input b[n];
    signal output andResult[n];
    signal output orResult[n];
    signal output xorResult[n];
    
    // 实例化BitwiseOps模板
    component bitwise = BitwiseOps(n);
    
    // 连接输入和输出
    for (var i = 0; i < n; i++) {
        bitwise.a[i] <== a[i];
        bitwise.b[i] <== b[i];
        andResult[i] <== bitwise.and[i];
        orResult[i] <== bitwise.or[i];
        xorResult[i] <== bitwise.xor[i];
    }
}

// 主模板，组合使用多个组件
template Main(n) {
    signal input a[n];
    signal input b[n];
    signal output addResult[n];
    signal output mulResult[n];
    signal output bitResults[3][n];
    
    // 实例化加法器
    component adder = CompositeAdder(n);
    for (var i = 0; i < n; i++) {
        adder.a[i] <== a[i];
        adder.b[i] <== b[i];
        addResult[i] <== adder.sum[i];
    }
    
    // 实例化乘法器
    component multiplier = CompositeMultiplier(n);
    for (var i = 0; i < n; i++) {
        multiplier.a[i] <== a[i];
        multiplier.b[i] <== b[i];
        mulResult[i] <== multiplier.product[i];
    }
    
    // 实例化位运算器
    component bitOps = BitOperator(n);
    for (var i = 0; i < n; i++) {
        bitOps.a[i] <== a[i];
        bitOps.b[i] <== b[i];
        bitResults[0][i] <== bitOps.andResult[i];
        bitResults[1][i] <== bitOps.orResult[i];
        bitResults[2][i] <== bitOps.xorResult[i];
    }
}