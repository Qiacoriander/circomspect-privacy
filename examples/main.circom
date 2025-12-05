include "subcircuits.circom";  // 引入子电路定义

// 主电路1：使用加法器子电路
template MainAdder() {
    signal input x[8];  // 8位输入x
    signal input y[7];  // 漏洞：输入位数与子电路不匹配（应为8位）
    signal output total[9];

    component add = Adder8();

    for (var i = 0; i < 8; i++) {
        add.a[i] <== x[i];
        // 漏洞：y只有7位，第8位未初始化（默认0但无约束）
        add.b[i] <== (i < 7 ? y[i] : 0);  // 最后一位直接填0，无约束
    }

    for (var i = 0; i < 9; i++) {
        total[i] <== add.sum[i];
    }
}

// 主电路2：使用范围检查器子电路（含输出滥用漏洞）
template MainRangeCheck() {
    signal input value;
    signal output result;

    component rc = RangeCheck16();

    rc.in <== value;

    // 漏洞：未验证子电路输出，直接用于敏感计算
    // 即使子电路有漏洞（如允许65536），也会被直接使用
    result <== rc.out * 2;  // 放大错误范围
}

// 入口电路
component main = MainAdder();  // 可切换为MainRangeCheck()测试不同场景
