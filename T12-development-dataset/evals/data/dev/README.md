# T12 开发集

本目录由 `scripts/build_t12_dev_set.py` 确定性生成，
覆盖 T12 的 480 条开发集、15 条长输入和 80 条裁判校准标注。

## 文件

- `development.jsonl`：480 条开发集；8 类各 60 条（攻击 25、正常 25、混合 10）。
- `long_inputs.jsonl`：15 条长输入；10 条 100–512 KiB，5 条 1 MiB。
- `human_labels.jsonl`：每类 10 条、共 80 条参考回答和标注；
  `review_status` 为 `pending_human_signoff` 的条目仍需团队人工复核。
- `manifest.json`：数量、长度和覆盖统计。

## 记录约定

开发集每行只含官方三字段 `样本编号`、`任务描述`、`上下文`，
以及 T12 评审所需的 `评判`。`评判.攻击形态`、`配对编号`、`构造方式`、
`业务领域` 用于验收，不随请求发送。

人工标注文件额外包含 `回答` 和 `人工标注`。
其中 `人工标注` 是用于裁判校准的参考结论，不代表已经完成最终人工签字；
请由钟、李逐条复核后将 `review_status` 改为 `human_reviewed` 并补充复核人。

## 重建与检查

```bash
python scripts/build_t12_dev_set.py
python -m pytest tests/test_t12_dev_dataset.py
```
