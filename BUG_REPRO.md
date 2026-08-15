# Bug Reproduction

## 包的性质

当前 test_model_fix 保存的是被测模型修复后的结果源码，不是初始含 Bug 源码。要复现原始缺陷，必须检出下面固定的 parent SHA；不要在当前修复结果源码上期待重新出现修复前失败。生成系统使用的可信验证补丁和完整验证日志仅在本地留存，不提交到结果分支。

## 问题现象

把 store 恢复到较早的快照之后，事件数据确实回到了快照时的状态，但索引校验开始报错，说索引条目比事件多；只有手动重新建索引才能恢复正常。先不要修改代码。请调查恢复流程为什么会留下与事件不一致的索引，给出可核验证据、完整因果链，并定位具体 Go 文件和符号。

## 含 Bug 版本

- 仓库：zhanglei10281852-gif/gogo-50
- 仓库地址：https://github.com/zhanglei10281852-gif/gogo-50.git
- parent SHA：4c2bc0e96ecb727ca759a763a0071115e25843c5

## 复现步骤

```bash
git clone -- https://github.com/zhanglei10281852-gif/gogo-50.git bug-repro
cd bug-repro
git checkout --detach 4c2bc0e96ecb727ca759a763a0071115e25843c5
go test ./internal/store -run "^TestRestoreSnapshotRebuildsIndexForRestoredEvents$" -count=1 -v
```

## 双架构完整错误信息

### linux/amd64

- 容器内复现预期退出码：1
- 容器内复现实际退出码：1

stdout：

```text
$ go test ./internal/store -run "^TestRestoreSnapshotRebuildsIndexForRestoredEvents$" -count=1 -v
=== RUN   TestRestoreSnapshotRebuildsIndexForRestoredEvents
    restore_regression_test.go:43: restored snapshot left an index from the newer store state: index has extra entries
--- FAIL: TestRestoreSnapshotRebuildsIndexForRestoredEvents (0.18s)
FAIL
FAIL	LogPilot/internal/store	0.191s
FAIL

```

stderr：

```text
(empty)
```

### linux/arm64

- 容器内复现预期退出码：1
- 容器内复现实际退出码：1

stdout：

```text
$ go test ./internal/store -run "^TestRestoreSnapshotRebuildsIndexForRestoredEvents$" -count=1 -v
=== RUN   TestRestoreSnapshotRebuildsIndexForRestoredEvents
    restore_regression_test.go:43: restored snapshot left an index from the newer store state: index has extra entries
--- FAIL: TestRestoreSnapshotRebuildsIndexForRestoredEvents (0.25s)
FAIL
FAIL	LogPilot/internal/store	0.401s
FAIL

```

stderr：

```text
(empty)
```

## 通过条件

定位 internal/store/store.go 的 (*Store).RestoreSnapshot，并结合 (*Store).CreateSnapshot 的快照文件集合与 (*Store).RebuildIndex、(*Store).ValidateIndex 说明索引为何保持在快照之后的状态；有证据且目标仓库零改动。
