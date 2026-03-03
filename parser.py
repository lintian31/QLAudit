#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""将 CodeQL 生成的 SARIF 结果文件转换为简化版 JSON 结构。

输出格式示例：
[
  {
    "ruleId": "java/xx-injection",
    "message": "问题描述……",
    "severity": "warning",
    "fileLocation": {
      "file": "src/main/java/xxx.java",
      "startLine": 10,
      "startColumn": 5,
      "endLine": 10,
      "endColumn": 20
    },
    "codeSnippet": "这里是一小段相关代码片段",
    "codeFlows": [...]
  }
]
"""

import json
import os
import sys


# ====================================================================
#  内部辅助函数
# ====================================================================

def _extract_code_flows(result, project_root: str = ""):
    """从 result.codeFlows 中提取 Source -> Sink 的流信息。

    保留关键信息：
    - 每一步的 message
    - 文件路径
    - 位置（行 / 列）
    - 角色（例如 CodeQL/DataflowRole 标记的 source / step / sink 等）
    """
    flows_out = []
    for cf in result.get("codeFlows") or []:
        cf_out = {"threadFlows": []}
        for tf in cf.get("threadFlows") or []:
            tf_out = {"locations": []}
            for loc_wrap in tf.get("locations") or []:
                loc = (loc_wrap or {}).get("location") or {}
                physical = loc.get("physicalLocation") or {}
                artifact = physical.get("artifactLocation") or {}
                region = physical.get("region") or {}

                # message
                msg_obj = loc.get("message") or {}
                if isinstance(msg_obj, dict):
                    step_msg = msg_obj.get("text") or msg_obj.get("markdown") or ""
                else:
                    step_msg = str(msg_obj) if msg_obj is not None else ""

                uri = artifact.get("uri") or ""
                step = {
                    "message": step_msg,
                    "file": os.path.join(project_root, uri) if project_root else uri,
                    "startLine": region.get("startLine"),
                    "startColumn": region.get("startColumn"),
                    "endLine": region.get("endLine"),
                    "endColumn": region.get("endColumn"),
                }

                # 角色信息（比如 CodeQL/DataflowRole: source/step/sink）
                roles = []
                for t in (loc_wrap or {}).get("taxa") or []:
                    role = (t.get("properties") or {}).get("CodeQL/DataflowRole") or t.get("id")
                    if role:
                        roles.append(role)
                if roles:
                    step["roles"] = roles

                tf_out["locations"].append(step)

            cf_out["threadFlows"].append(tf_out)
        flows_out.append(cf_out)
    return flows_out


def _build_rule_map(run):
    """根据 run 中的 tool.driver.rules 构建 ruleId -> ruleInfo 的映射。"""
    rule_map = {}
    driver = run.get("tool", {}).get("driver", {})
    for rule in driver.get("rules", []) or []:
        rule_id = rule.get("id")
        if not rule_id:
            continue
        rule_map[rule_id] = {
            "name": rule.get("name"),
            "shortDescription": (rule.get("shortDescription") or {}).get("text"),
            "fullDescription": (rule.get("fullDescription") or {}).get("text"),
            "properties": rule.get("properties") or {},
        }
    return rule_map


# ====================================================================
#  核心转换函数
# ====================================================================

def sarif_to_simple_json_obj(sarif_obj, project_root: str = ""):
    """传入已解析的 SARIF dict，返回简化后的 list[dict]。

    :param sarif_obj:     SARIF 解析后的字典
    :param project_root:  项目根路径，拼接在 artifact URI 前面
    """
    results_out = []
    if not isinstance(sarif_obj, dict):
        return results_out

    runs = sarif_obj.get("runs") or []
    for run in runs:
        rule_map = _build_rule_map(run)

        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId")
            rule_info = rule_map.get(rule_id, {})

            # message
            message = ""
            msg_obj = res.get("message") or {}
            if isinstance(msg_obj, dict):
                message = msg_obj.get("text") or msg_obj.get("markdown") or ""
            elif isinstance(msg_obj, str):
                message = msg_obj

            # severity
            severity = res.get("level") or res.get("kind") or ""
            if not severity:
                severity = (rule_info.get("properties") or {}).get("problem.severity", "")

            # location
            file_path = ""
            start_line = start_col = end_line = end_col = None
            code_snippet = ""
            code_flows = _extract_code_flows(res, project_root)

            locations = res.get("locations") or []
            if locations:
                loc = locations[0] or {}
                physical = loc.get("physicalLocation") or {}
                artifact = physical.get("artifactLocation") or {}
                region = physical.get("region") or {}

                file_path = artifact.get("uri") or ""
                start_line = region.get("startLine")
                start_col = region.get("startColumn")
                end_line = region.get("endLine")
                end_col = region.get("endColumn")

                snippet_obj = region.get("snippet") or {}
                if isinstance(snippet_obj, dict):
                    code_snippet = snippet_obj.get("text") or snippet_obj.get("markedUp") or ""

            simple_item = {
                "ruleId": rule_id,
                "message": message,
                "severity": severity,
                "fileLocation": {
                    "file": os.path.join(project_root, file_path) if project_root else file_path,
                    "startLine": start_line,
                    "startColumn": start_col,
                    "endLine": end_line,
                    "endColumn": end_col,
                },
                "codeSnippet": code_snippet,
                "codeFlows": code_flows,
            }

            results_out.append(simple_item)

    return results_out


def sarif_file_to_json(in_sarif_path, out_json_path=None, project_root="", encoding="utf-8"):
    """将 SARIF 文件转换为简化 JSON。

    :param in_sarif_path:  输入的 .sarif / .json 文件路径
    :param out_json_path:  输出 JSON 文件路径；为 None 时只返回对象不写文件
    :param project_root:   项目根路径，拼接在 artifact URI 前面
    :param encoding:       文件编码，默认 utf-8
    :return: list[dict] 形式的结果列表
    """
    if not os.path.isfile(in_sarif_path):
        print(f"[ERROR] sarif file not exists: {in_sarif_path}", file=sys.stderr)
        return []

    try:
        with open(in_sarif_path, "r", encoding=encoding) as f:
            sarif_obj = json.load(f)
    except Exception as e:
        print(f"[ERROR] read sarif file error: {e}", file=sys.stderr)
        return []

    simple_results = sarif_to_simple_json_obj(sarif_obj, project_root)

    if out_json_path:
        try:
            out_dir = os.path.dirname(out_json_path)
            if out_dir and not os.path.isdir(out_dir):
                os.makedirs(out_dir)
            with open(out_json_path, "w", encoding="utf-8") as w:
                json.dump(simple_results, w, ensure_ascii=False, indent=2)
            print(f"[INFO] write json result to: {out_json_path}")
        except Exception as e:
            print(f"[ERROR] write json file error: {e}", file=sys.stderr)

    return simple_results


# ====================================================================
#  命令行入口
# ====================================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python parser.py <input.sarif> [output.json] [project_root]")
        sys.exit(1)

    in_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else None
    root = sys.argv[3] if len(sys.argv) > 3 else ""

    sarif_file_to_json(in_path, out_path, project_root=root)
