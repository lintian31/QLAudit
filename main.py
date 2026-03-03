#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""QLAudit 入口：加载 CodeQL 输出的审计数据，驱动 ReAct Agent 进行漏洞研判。"""

import json
import sys

from Agent.AuditAgent import AuditAgent
from Agent.AuditLLM import AuditLLM
from Tool.Tool import ToolExecutor
from Tool.source_snippet_tool import (
    get_source_snippet,
    search_code_in_file,
    search_project_files,
    search_symbol_in_project,
)


# ------------------------------------------------------------------
#  工具注册
# ------------------------------------------------------------------

def _build_tool_executor() -> ToolExecutor:
    """创建并注册所有可用工具，返回 ToolExecutor 实例。"""
    executor = ToolExecutor()

    executor.registerTool(
        "get_source_snippet",
        "根据 CodeQL/SARIF 提供的文件路径和行列信息，从源码中提取对应的代码片段（仅返回干净的代码文本，可包含少量上下文）。",
        get_source_snippet,
    )
    executor.registerTool(
        "search_project_files",
        "查看指定项目根目录下的文件结构，并根据关键词查找相关文件（以及可选的目录），返回相对项目根目录的路径列表。",
        search_project_files,
    )
    executor.registerTool(
        "search_code_in_file",
        "在单个源文件中根据关键字搜索相关代码片段，返回若干段包含该关键字的代码文本（每段可带少量上下文）。",
        search_code_in_file,
    )
    executor.registerTool(
        "search_symbol_in_project",
        (
            "在整个项目目录下按符号名（变量 / 字段 / 方法等）搜索相关代码位置，"
            "用于快速了解某个 symbol 在项目中的定义、赋值和使用点；"
            "输入 JSON 示例："
            '{"root_dir": "/你的项目根路径", "symbol": "parameterMap", "maxResults": 100}'
        ),
        search_symbol_in_project,
    )

    return executor


# ------------------------------------------------------------------
#  数据加载
# ------------------------------------------------------------------

def _load_audit_data(json_path: str) -> str:
    """从 JSON 文件加载 CodeQL 审计数据，返回格式化后的文本供 Agent 消费。"""
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return json.dumps(data, ensure_ascii=False, indent=2)


# ------------------------------------------------------------------
#  主流程
# ------------------------------------------------------------------

def main():
    # 默认数据文件路径，可通过命令行参数覆盖
    data_path = sys.argv[1] if len(sys.argv) > 1 else "output8.json"

    prompt_prefix = (
        "以下是codeql查询给出的流数据，我给你以下多个json片段，"
        "帮我分别读取到对应的代码内容，及其附近的上下文，"
        "你帮我读出其中的关联，以及使用工具进一步确认漏洞是否真的存在，"
        "数据链会不会被断，类和类之间的关联，这个是不是codeql误报：\n"
    )

    audit_data = _load_audit_data(data_path)
    prompt = prompt_prefix + audit_data

    llm_client = AuditLLM()
    tool_executor = _build_tool_executor()
    agent = AuditAgent(llm_client, tool_executor, max_steps=25)

    agent.run(prompt)


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as e:
        print(f"[ERROR] 数据文件未找到: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
