// 子电路1：8位加法器（无漏洞）
template Adder8() {
    signal input a[8];  // 8位输入a
    signal input b[8];  // 8位输入b
    signal output sum[9];  // 9位输出（含进位）

    // 内部信号：进位
    signal carry;
    carry <== 0;

    // 逐位加法（含进位）
    for (var i = 0; i < 8; i++) {
        sum[i] <== a[i] + b[i] + carry - 2*a[i]*b[i] - 2*a[i]*carry - 2*b[i]*carry + 3*a[i]*b[i]*carry;
        carry <== a[i] * b[i] + a[i] * carry + b[i] * carry - 2*a[i] * b[i] * carry;
    }
    sum[8] <== carry;  // 最终进位
}

// 子电路2：范围检查器（含潜在漏洞）
template RangeCheck16() {
    signal input in;  // 输入整数
    signal output out;  // 输出（透传）

    // 漏洞1：错误的范围计算（应为2^16-1=65535，写成了65536）
    in * (65536 - in) >= 0;  // 实际允许in=65536，超出16位范围
    out <== in;
}
