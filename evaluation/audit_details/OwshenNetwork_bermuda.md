# 隐私泄露审计报告：OwshenNetwork/bermuda

## 1. 项目与漏洞概述
- **项目名**: `OwshenNetwork_bermuda`
- **文件路径**: `contracts\circuits\coin_withdraw.circom`
- **泄露类型**: **Full Leak (完全泄露)**
- **涉及信号**: `user_checkpoint_head`, `user_latest_values_commitment_head`

## 2. 漏洞发生链路分析
和 `huyphamcs` 的逻辑错误如出一辙，OwshenNetwork 的这个代币提款电路同样犯了将底层私有状态直接通过 public output 抛出的致命错误。

分析其代码：
```circom
    signal input user_checkpoint_head;
    signal input user_latest_values_commitment_head;

    signal output checkpoint_head;
    signal output latest_values_commitment_head;

    // 各种检查与默克尔树/哈希运算...
    // ...

    checkpoint_head <== user_checkpoint_head;
    latest_values_commitment_head <== user_latest_values_commitment_head;
```

不仅代码中做出了毫无遮掩的赋值裸奔：`output = input`，而且整个电路的声明也是：
```circom
 component main = CoinWithdraw(2, 2, 1024);
```
没有使用 `{public [xxx]}` 声明白名单，这意味着 `user_checkpoint_head` 和 `user_latest_values_commitment_head` 被视作私密输入。然而它们被原原本本地装载进了公开可见的 Output 中，致使所谓的隐私状态暴露无遗。

## 3. 审计结论：确认为有效泄露 (True Positive)
**真实有效**的全量侧漏。Circomspect 的常量级传播与相等追踪约束直接一针见血地指出了用户的私密记录头被明文发送了。完全丧失零知识隐私性。
