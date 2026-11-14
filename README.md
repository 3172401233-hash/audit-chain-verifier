# audit-chain-verifier

面向审计场景的 Node.js 不可篡改日志索引库。日志按“段（segment）”落盘，段内用 Merkle 树支持单条记录证明，段与段之间通过根摘要串联，能发现缺段、乱序、重复序号、尾部删除和中间记录替换。

只依赖 Node.js 内置模块（`node:crypto`、`node:fs`），无第三方依赖，要求 Node.js >= 20。

## 为什么需要它

只靠“逐行解析 + 人工核对行数”的审计日志有两个盲区：

- 文件尾部少几条记录时，只要剩余内容仍能解析，序号也连续，就不会暴露问题。
- 旧日志被整段替换后，读取方没有参照物，无法判断看到的是不是原始数据。

本库用两层密码学结构解决这两个问题：

1. **段内 Merkle 树**：每条业务记录编码成带域分离标签的叶子哈希，段内构建 Merkle 树，任何一条记录的删除、插入、交换、替换都会改变 Merkle 根。
2. **跨段根链**：每个段的提交尾保存前一段的根摘要，并把“段序号 + 前一段根 + 记录数 + Merkle 根”再次哈希成当前段根。段被替换、重排或缺段都会让链断裂。

## 数据模型

每条业务记录包含四个字段：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `seq` | 非负安全整数 | 全局严格递增序号 |
| `timestamp` | 非负安全整数 | 业务时间（毫秒） |
| `source` | 字符串 | 记录来源，UTF-8 编码 |
| `data` | `Buffer` / `Uint8Array` | 原始字节，按字节参与哈希 |

段文件命名为 `segment-0000000000.log`、`segment-0000000001.log`……段序号必须从 0 开始连续，目录中出现其他文件会报 `UNEXPECTED_FILE`。

段文件二进制布局：

```text
段头   魔数 AULG(4) | 版本(1) | 段序号(4)
记录帧 魔数 AULR(4) | 负载长度(4) | seq(8) | timestamp(8) | 负载
       负载 = seq(8) | timestamp(8) | source 长度(4) | source(UTF-8) | data(原始字节)
提交尾 魔数 AULT(4) | 段序号(4) | 记录数(4) | prevRoot(32) | merkleRoot(32) | segmentRoot(32) | 校验字(4)
```

哈希算法固定为 SHA-256，叶子、Merkle 内部节点、段根分别使用不同的域分离标签，防止跨层伪造。

## 提交语义：未提交的数据不可验证

`append()` 只把记录帧写进当前段，记录此时**不是**可验证记录：

- 段尾还没有提交尾，读取侧会把它识别为“未提交尾段”，不纳入索引。
- 只有 `commit()`（或写满触发的自动封段，或正常 `close()`）写入提交尾并 `fsync` 后，段才被密封，其中的记录才会出现在索引里、才能生成 proof。
- 进程在 `commit()` 前崩溃，磁盘上只会留下没有提交尾的尾段。重新打开写入器会直接清理这个尾段，从最后一个已密封段的根继续写。
- 写入过程中发生 I/O 错误会让写入器“中毒”，后续 `append` / `commit` 一律拒绝，必须重新打开，避免半帧污染后续数据。

## 快速上手

```js
import { AuditWriter, openIndex } from 'audit-chain-verifier';

const directory = './audit-data';

const writer = await AuditWriter.open(directory, { maxRecordsPerSegment: 1000 });
await writer.append({
  seq: 0,
  timestamp: Date.now(),
  source: 'billing',
  data: Buffer.from(JSON.stringify({ orderId: 'A-1', amount: 100 }))
});
const checkpoint = await writer.commit();
// checkpoint.root 就是此刻的可信 root，必须保存到日志目录之外
await writer.close();

const index = await openIndex(directory);
const proof = index.getProof(0);
index.verifyProof(proof, { trustedRoot: checkpoint.root }); // => true
```

## 可信 root 从哪里来

日志文件本身无法自证清白：能改日志的人理论上也能重算所有哈希。因此验证必须依赖一个**来自带外通道的可信 root**，它不能和日志存放在同一个信任域里。常见来源：

- 每次 `commit()` 返回的 `checkpoint.root` 写入只追加的外部账本、独立数据库或 KMS。
- 把 root 发布到另一套系统（配置中心、区块链、公证服务、独立对象存储的锁定桶）。
- 多方互备：每个副本各自保存 root，审计时交叉比对。

可信 root 的最小单位是“某次提交后的 head root”。空日志的可信 root 是 64 个 `0`（`ZERO_HASH`）。

验证单条记录时把可信 root 传给 `verifyProof`：

```js
const proof = index.getProof(42);
index.verifyProof(proof, { trustedRoot: externallyStoredRoot });
```

如果不传 `trustedRoot`，只证明“该记录属于当前磁盘上这条链的 head”，无法发现整条链的尾部被整体删除。

## 轮转之后怎么验证

轮转只是密封当前段并新建下一个段，链不会断：

- 段 `N` 的提交尾保存段 `N-1` 的根（第一段的 `prevRoot` 是全零）。
- `getProof(seq)` 返回的 proof 自带一条 `anchors` 锚点链，从记录所在段一直延伸到当前 head，每个锚点都包含该段的 `prevRoot`、记录数、Merkle 根和段根。
- `verifyProof` 会先重算叶子和 Merkle 证明，再逐段重算段根、核对 `prevRoot` 链接，最后比对 `headRoot`；传入 `trustedRoot` 时再做一次带外锚定。

因此旧段不需要重新扫描：一条记录的 proof 可以脱离原进程，用 `serializeProof` / `parseProof` 做 JSON 序列化后离线验证。

```js
import { parseProof, serializeProof, verifyProof } from 'audit-chain-verifier';

const text = serializeProof(index.getProof(42));
const restored = parseProof(text);
verifyProof(restored, { trustedRoot });
```

## API

### 写入

- `AuditWriter.open(directory, options?)`：打开或创建日志，自动清理未提交尾段。
- `writer.append(record)`：追加一条记录，返回 `{ seq, committed: false, segmentIndex, position }`。
- `writer.commit()`：密封当前段并 `fsync`，返回 `{ committed, segmentIndex, count, merkleRoot, prevRoot, root }`。
- `writer.close({ discardUncommitted }?)`：正常关闭；默认密封未提交数据，传 `discardUncommitted: true` 可丢弃。
- `writer.simulateCrash()`：测试用，直接关闭文件描述符且不写提交尾，模拟进程崩溃。
- 选项：`maxRecordsPerSegment`（默认 1000）、`allowGaps`（默认 false，序号必须连续）。

### 读取与证明

- `openIndex(directory, options?)`：加载并验证全部已密封段，返回 `AuditIndex`。
- `index.getProof(seq)`：生成含锚点链的 Merkle proof。
- `index.verifyProof(proof, { trustedRoot }?)`：验证 proof，失败抛 `AuditError`。
- `index.locate(seq)` / `index.list()`：定位或列出已提交记录，附带段序号、帧偏移等定位信息。
- `auditLog(directory, options?)`：容错审计，返回 `{ ok, headRoot, issues, warnings, hasUncommittedTail, ... }`，验证途中遇到损坏段也会继续收集问题而不是只抛一个异常。
- `serializeProof` / `parseProof` / 独立函数 `verifyProof`：支持跨进程离线验证。

### 错误码

`CORRUPT_SEGMENT`、`MISSING_SEGMENT`、`UNEXPECTED_FILE`、`ROOT_MISMATCH`、`INVALID_PROOF`、`PROOF_MISMATCH`、`SEQ_DUPLICATE`、`SEQ_OUT_OF_ORDER`、`SEQ_GAP`、`INVALID_RECORD`、`NOT_FOUND`、`WRITER_CLOSED`。

## 各类篡改的检测方式

| 攻击 | 检测点 |
| --- | --- |
| 删除段内中间记录 | 帧数与提交尾记录数不一致，或 Merkle 根不匹配 |
| 交换两条记录 | 叶子顺序变化导致 Merkle 根不匹配 |
| 插入伪造记录 | 记录数校验失败，或 Merkle 根不匹配 |
| 替换记录内容 | 叶子哈希变化导致 Merkle 根不匹配 |
| 删除整个段 | 文件名不连续报 `MISSING_SEGMENT`，或 `prevRoot` 链断裂 |
| 整段替换 | 段头序号 / `prevRoot` 与链上的根不一致 |
| 尾部删除 | 磁盘 headRoot 与带外可信 root 不一致 |
| 伪造提交尾 | 重算的段根与提交尾中的摘要不一致 |
| 伪造 proof | 叶子、Merkle 兄弟、锚点链或可信 root 任一重算失败 |

注意：如果攻击者把**最后一个已密封段连同提交尾一起截掉**，磁盘内容与“写入中断”在字节层面无法区分。此时本地结构校验只会提示未提交尾段，最终判定依赖带外可信 root——这正是可信 root 必须独立保存的原因。

## 测试

```bash
npm test
# 等价于
node --test
```

测试覆盖：空日志、单记录、轮转边界、隐式轮转、写入中断与崩溃恢复、写入失败中毒、伪造 proof、损坏段审计，以及删除 / 交换 / 插入 / 替换记录和缺段、整段替换、尾部删除等攻击注入。
