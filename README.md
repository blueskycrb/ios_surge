# ios_surge

面向 Loon 的国内外分流规则，每天由 GitHub Actions 自动合并和更新。

## 生成规则

| 文件 | 用途 | 建议策略 |
| --- | --- | --- |
| `ai.list` | OpenAI、Claude、Gemini、Copilot 等 AI 服务 | `AI` |
| `proxy.list` | 国外服务，生成时排除已归入 AI 的规则 | `Proxy` |
| `china.list` | 国内域名、中国 ASN 和 IP 段 | `DIRECT` |

规则按 `AI > Proxy > China` 处理。低优先级中已被高优先级完整覆盖的域名或 CIDR 会在生成阶段删除。

## Loon 配置顺序

在 `[Remote Rule]` 中必须保持以下顺序：

```ini
https://raw.githubusercontent.com/blueskycrb/ios_surge/main/ai.list, policy=AI, tag=AI, enabled=true
https://raw.githubusercontent.com/blueskycrb/ios_surge/main/proxy.list, policy=Proxy, tag=Proxy, enabled=true
https://raw.githubusercontent.com/blueskycrb/ios_surge/main/china.list, policy=DIRECT, tag=China, enabled=true
```

本地规则末尾建议保留：

```ini
GEOIP,CN,DIRECT
FINAL,Proxy
```

`cn.list`、`us.list` 和 `openai.list` 是对应分类的自定义输入源。修改这些文件后，工作流会重新生成三份规则。

## 本地验证

```bash
python -m unittest discover -s tests -v
python scripts/merge_rules.py
```
