## 变更说明

<!-- 简要说明这个 PR 解决什么问题、为什么这样实现。 -->

关联 Issue：<!-- 例如 Closes #12 -->

## 变更类型

- [ ] 修复缺陷
- [ ] 新增检测规则或功能
- [ ] 文档更新
- [ ] 测试或 CI 改进
- [ ] 重构（不改变行为）

## 验证方式

```bash
python -m unittest discover -s tests -v
python -m compileall -q loghawk tests
```

<!-- 补充你实际执行的命令、合成日志片段或 JSON 输出。 -->

## 检查清单

- [ ] 保持 Python 3.9 兼容
- [ ] 未新增运行时第三方依赖
- [ ] 新增/修改行为有对应测试
- [ ] 未包含真实日志、凭据或个人信息
- [ ] 已同步 README / CHANGELOG（如适用）
- [ ] 变更范围聚焦，未混入无关修改
