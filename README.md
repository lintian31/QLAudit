# QLAudit

利用 AI 对 CodeQL 扫描结果进行自动化研判的工具。采用 ReAct（Reasoning + Acting）范式，Agent 会逐步读取源码、追踪数据流、分析过滤逻辑，最终判断每条告警是**真实漏洞**还是**误报**。

> 项目仍在持续调优中，欢迎反馈。

## 工作流程

```
CodeQL 扫描 -> SARIF 结果 -> parser.py 转 JSON -> main.py 分组过滤 -> Agent 逐条研判
```

1. **SARIF 转换**：`parser.py` 将 CodeQL 原始 SARIF 文件转为简化 JSON，保留规则、位置、数据流等关键信息
2. **分组过滤**：`main.py` 按 `ruleId` 分组，根据 `config.py` 中的白名单决定哪些规则需要研判
3. **逐条研判**：每条结果单独交给 ReAct Agent，Agent 通过工具读取源码、搜索符号，沿数据流逐步分析
4. **输出结论**：每条给出 真实漏洞 / 误报 / 风险不明 的判定，附带原因和关键链路

## 项目结构

```
QLAudit/
├── Agent/
│   ├── AuditAgent.py          # ReAct 循环主逻辑（Thought -> Action -> Observation）
│   ├── AuditLLM.py            # LLM 客户端封装（兼容 OpenAI 接口）
│   └── prompt.py              # Agent 系统提示词
├── Tool/
│   ├── Tool.py                # 工具注册与管理
│   └── source_snippet_tool.py # Agent 可用的工具集（代码提取、文件搜索、符号搜索）
├── config.py                  # 全局配置（研判规则白名单、Agent 步数等）
├── main.py                    # 入口：加载数据 -> 分组 -> 过滤 -> 驱动 Agent
└── parser.py                  # SARIF -> 简化 JSON 转换器
```

## 快速开始

### 1. 安装依赖

```bash
pip install openai
```

### 2. 配置环境变量

```bash
export AUDIT_LLM_API_KEY="sk-你的密钥"

# 以下为可选配置，有默认值
# export AUDIT_LLM_MODEL="kimi-k2.5"
# export AUDIT_LLM_BASE_URL="https://api.moonshot.cn/v1"
```

默认使用 Kimi/Moonshot 的 `kimi-k2.5` 模型。如需更换，可自行设置 `AUDIT_LLM_MODEL` 和 `AUDIT_LLM_BASE_URL`，兼容所有 OpenAI 接口格式的服务。

给k2.5打广告，用起来还不错，价格也可以。

### 3. 创建 CodeQL 数据库并扫描

```bash
# 创建数据库（以 Java 项目为例）
codeql database create /path/to/codeql-db --language=java --source-root=/path/to/project

# 运行查询，输出 SARIF 格式结果
codeql database analyze /path/to/codeql-db codeql/java-queries:codeql-suites/java-security-extended.qls --format=sarif-latest --output=result.sarif
```

### 4. 转换 SARIF 为简化 JSON

```bash
python parser.py result.sarif output.json /path/to/project
```

参数说明：
- `result.sarif` — CodeQL 输出的 SARIF 文件
- `output.json` — 转换后的简化 JSON 文件
- `/path/to/project` — 被扫描项目的根目录路径（用于拼接文件绝对路径）
- `codeql/java-queries:codeql-suites/java-security-extended.qls` — 官方规则集，选用深度扫描的那个

### 5. 配置研判规则

编辑 `config.py`，在 `AUDIT_RULES` 白名单中填入你关心的规则（子串匹配，不区分大小写）：

```python
AUDIT_RULES = [
    "unsafe-deserialization",
    "path-injection",
    "xss",
]
```

白名单为空 `[]` 时，所有规则都会被研判。

### 6. 运行研判

```bash
# 查看规则概览（不触发研判）
python main.py output.json --project-root /path/to/project --list

# 研判所有白名单规则
python main.py output.json --project-root /path/to/project

# 只研判指定规则
python main.py output.json --project-root /path/to/project --rule java/xss
```

## Agent 可用工具

| 工具 | 用途 |
|------|------|
| `get_source_snippet` | 根据文件路径和行列信息提取代码片段及上下文 |
| `search_code_in_file` | 在单个文件中按关键字搜索代码片段 |
| `search_project_files` | 在项目目录下按关键词查找文件 |
| `search_symbol_in_project` | 在项目中按符号名搜索定义和使用位置 |

## 研判输出示例

```
结论：真实漏洞
原因：用户输入通过 request.getParameter() 获取后，未经任何过滤直接拼接进 SQL 语句
关键链路：request.getParameter("name") -> queryParam -> sql.append(queryParam) -> executeQuery(sql)
```

## 作者的思考

**现在AI基模已经足够聪明，加上SKILL加持，是否还需要codeql这样的工具去辅助代码审计？**

codeql的好处是提供了确定性，可以连接出一个数据流，一定程度上缓解了LLM遇到长上下文容易幻觉的情况，目前我的看法是codeql还有一定的价值，但是ql语句的建构也很重要，当前项目假定的扫描结果都是codeql官方规则集扫出来的，都很宽泛，误报率自然不低。这是这个项目目前的情况。

**更好的解决方案假象：**

1. 直接写SKILL（定义好codeql使用手册，ql查询语法，ql建模思想）交给claude这样的code agent，他们自己有grep，read等工具，对结果研判更加方便，不用再写tool。并且如今模型基础能力也在提升，这些任务交给AI准确率也会更好。
2. 设计一个多agent结构，一个**Orchestrator**agent负责调用子agent（参考DeepAudit的结构），一个agent负责写ql，一个agent负责检查ql写的是否正确，，一个agent对扫描结果研判，几个agent各自运作相互反馈，可能结果会更稳健。

其实现在codeagent 和openclaw足够厉害，这种自定义tool、规定好每个步骤的agent其实已经有点过时了（少了些自由度），但是因为几个月前就在做，想着还是做好闭环最后还是做了，未来也许会在这个项目基础上修改，也可能会新建一个skill项目，敬请期待。

如果你无意间刷到这个项目，有不一样的看法或意见，十分欢迎和我交流反馈，谢谢🙏
