#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""QLAudit 入口：加载 CodeQL 输出的审计数据，驱动 ReAct Agent 进行漏洞研判。

使用方式：
    python main.py <data.json> --project-root /path/to/project         # 逐条研判
    python main.py <data.json> --project-root /path/to/project --list  # 仅列出概览
    python main.py <data.json> --project-root /path/to/project --rule java/xss
"""

import json
import sys
from collections import defaultdict
from typing import Dict, List

from Agent.AuditAgent import AuditAgent
from Agent.AuditLLM import AuditLLM
from Tool.Tool import ToolExecutor
from Tool.source_snippet_tool import (
    get_source_snippet,
    search_code_in_file,
    search_project_files,
    search_symbol_in_project,
)
from config import AUDIT_RULES, MAX_STEPS


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
#  数据加载与分组
# ------------------------------------------------------------------

def _load_results(json_path: str) -> List[dict]:
    """从 JSON 文件加载 CodeQL 审计结果列表。"""
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _resolve_paths(item: dict, project_root: str) -> dict:
    """将单条结果中所有相对文件路径拼接上 project_root，变为绝对路径。"""
    import os
    import copy
    item = copy.deepcopy(item)

    # fileLocation.file
    fl = item.get("fileLocation") or {}
    if fl.get("file") and not os.path.isabs(fl["file"]):
        fl["file"] = os.path.join(project_root, fl["file"])

    # codeFlows 中每个 location 的 file
    for cf in item.get("codeFlows") or []:
        for tf in cf.get("threadFlows") or []:
            for loc in tf.get("locations") or []:
                if loc.get("file") and not os.path.isabs(loc["file"]):
                    loc["file"] = os.path.join(project_root, loc["file"])

    return item


def _group_by_rule(results: List[dict]) -> Dict[str, List[dict]]:
    """按 ruleId 将结果分组，返回 {ruleId: [结果列表]}。"""
    groups: Dict[str, List[dict]] = defaultdict(list)
    for item in results:
        rule_id = item.get("ruleId") or "unknown"
        groups[rule_id].append(item)
    return dict(groups)


def _should_audit(rule_id: str) -> bool:
    """判断某条规则是否需要研判（子串匹配，不区分大小写）。

    白名单为空时，所有规则都需要研判。
    """
    if not AUDIT_RULES:
        return True
    rule_lower = rule_id.lower()
    return any(pattern.lower() in rule_lower for pattern in AUDIT_RULES)


# ------------------------------------------------------------------
#  展示概览
# ------------------------------------------------------------------

def _print_summary(groups: Dict[str, List[dict]]):
    """打印规则分组概览。"""
    print("=" * 60)
    print(f"  CodeQL 扫描结果概览（共 {sum(len(v) for v in groups.values())} 条）")
    print("=" * 60)
    for rule_id, items in sorted(groups.items(), key=lambda x: -len(x[1])):
        tag = "" if _should_audit(rule_id) else "  [跳过]"
        print(f"  {rule_id}: {len(items)} 条{tag}")
    print("=" * 60)


# ------------------------------------------------------------------
#  主流程
# ------------------------------------------------------------------

PROMPT_TEMPLATE = (
    "以下是codeql查询给出的流数据，我给你以下多个json片段，"
    "帮我分别读取到对应的代码内容，及其附近的上下文，"
    "你帮我读出其中的关联，以及使用工具进一步确认漏洞是否真的存在，"
    "数据链会不会被断，类和类之间的关联，这个是不是codeql误报。\n"
    "被审计项目的根目录为：{project_root}\n\n"
)


def _parse_named_arg(args: list, flag: str) -> str | None:
    """从参数列表中解析 --flag value 形式的命名参数。"""
    if flag in args:
        idx = args.index(flag)
        if idx + 1 < len(args):
            return args[idx + 1]
        print(f"[ERROR] {flag} 后需要指定值", file=sys.stderr)
        sys.exit(1)
    return None


def main():
    # ---- 解析命令行参数 ----
    # args = sys.argv[1:]
    # if not args:
    #     print("用法: python main.py <data.json> --project-root <path> [--list] [--rule <ruleId>]")
    #     sys.exit(1)
    #
    # data_path = args[0]
    # list_only = "--list" in args
    # project_root = _parse_named_arg(args, "--project-root")
    target_rule = _parse_named_arg(args, "--rule")
    data_path = '1.json'
    project_root = "/Users/lingtian/Downloads/jshERP-master"
    list_only = False
    target_rule = "java/xss"


    if not project_root:
        print("[ERROR] 必须通过 --project-root 指定被审计项目的根目录", file=sys.stderr)
        sys.exit(1)

    # ---- 加载 & 分组 ----
    results = _load_results(data_path)
    groups = _group_by_rule(results)

    _print_summary(groups)

    if list_only:
        return

    # ---- 过滤要研判的规则 ----
    if target_rule:
        # 只研判用户指定的规则
        if target_rule not in groups:
            print(f"[ERROR] 未找到规则: {target_rule}", file=sys.stderr)
            print(f"  可选规则: {', '.join(groups.keys())}")
            sys.exit(1)
        rules_to_audit = {target_rule: groups[target_rule]}
    else:
        # 只保留白名单中的规则
        rules_to_audit = {
            rule_id: items
            for rule_id, items in groups.items()
            if _should_audit(rule_id)
        }

    if not rules_to_audit:
        print("\n没有匹配到需要研判的规则。")
        return

    # ---- 初始化 Agent ----
    llm_client = AuditLLM()
    tool_executor = _build_tool_executor()
    agent = AuditAgent(llm_client, tool_executor, max_steps=MAX_STEPS)

    # ---- 展开为逐条结果，每条单独研判 ----
    audit_queue = [
        (rule_id, item)
        for rule_id, items in rules_to_audit.items()
        for item in items
    ]
    total = len(audit_queue)

    prompt_prefix = PROMPT_TEMPLATE.format(project_root=project_root)

    for i, (rule_id, item) in enumerate(audit_queue, 1):
        # 将相对路径补全为绝对路径
        resolved_item = _resolve_paths(item, project_root)

        location = resolved_item.get("fileLocation") or {}
        file_hint = location.get("file", "")
        line_hint = location.get("startLine", "?")

        print("\n" + "=" * 60)
        print(f"  [{i}/{total}] 规则: {rule_id}")
        print(f"  文件: {file_hint}:{line_hint}")
        print("=" * 60)

        audit_data = json.dumps(resolved_item, ensure_ascii=False, indent=2)
        prompt = prompt_prefix + audit_data

        result = agent.run(prompt)

        if result:
            print(f"\n📋 [{i}/{total}] {rule_id} 研判完成")
        else:
            print(f"\n⚠️ [{i}/{total}] {rule_id} 研判未能得出结论")


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as e:
        print(f"[ERROR] 数据文件未找到: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n用户中断，退出。")
        sys.exit(0)
    except ValueError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
