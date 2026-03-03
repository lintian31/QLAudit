#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""源码片段提取与搜索工具集。

提供以下工具函数：
- get_source_snippet:   根据文件路径和行列信息提取代码片段
- search_code_in_file:  在单个文件中按关键字搜索代码片段
- search_project_files: 在项目目录下按关键词查找文件
- search_symbol_in_project: 在项目目录下按符号名搜索代码位置
"""

import os
from typing import Any, Dict, Optional, List


# ====================================================================
#  内部工具函数
# ====================================================================

def _safe_read_lines(file_path: str, encoding: str = "utf-8"):
    """读取文件所有行。成功返回 (True, 行列表)；失败返回 (False, 错误信息)。"""
    if not os.path.isfile(file_path):
        return False, f"file not found: {file_path}"
    try:
        with open(file_path, "r", encoding=encoding, errors="replace") as f:
            return True, f.readlines()
    except Exception as e:
        return False, f"read file error: {e}"


def _extract_snippet_from_lines(
    lines,
    start_line: int,
    start_column: Optional[int] = None,
    end_line: Optional[int] = None,
    end_column: Optional[int] = None,
    context_lines: int = 3,
) -> str:
    """在给定行列表中，根据行列信息提取代码片段和上下文。

    - start_line / end_line 使用 1-based 行号（与编辑器 / SARIF 对齐）
    - 如果 end_line 为空，则视为与 start_line 相同
    - context_lines 表示向前/向后各取多少行上下文
    """
    total_lines = len(lines)
    if total_lines == 0:
        return ""

    # 边界修正
    if start_line is None or start_line <= 0:
        start_line = 1
    if start_line > total_lines:
        start_line = total_lines
    if end_line is None or end_line <= 0:
        end_line = start_line
    if end_line > total_lines:
        end_line = total_lines

    # 计算上下文范围（转成 0-based 索引）
    main_start_idx = start_line - 1
    main_end_idx = end_line - 1
    ctx_start_idx = max(0, main_start_idx - context_lines)
    ctx_end_idx = min(total_lines - 1, main_end_idx + context_lines)

    before_lines = [l.rstrip("\n") for l in lines[ctx_start_idx:main_start_idx]]
    main_lines = [l.rstrip("\n") for l in lines[main_start_idx:main_end_idx + 1]]
    after_lines = [l.rstrip("\n") for l in lines[main_end_idx + 1:ctx_end_idx + 1]]

    # 如果只在一行上有列信息，可以尝试在该行内裁剪主行
    if len(main_lines) == 1 and (start_column or end_column):
        line_text = main_lines[0]
        s_col = (start_column or 1) - 1  # 转为 0-based
        e_col = end_column or len(line_text)
        s_col = max(0, min(len(line_text), s_col))
        e_col = max(s_col, min(len(line_text), e_col))
        main_lines = [line_text[s_col:e_col]]

    snippet_full = "\n".join(before_lines + main_lines + after_lines)
    return snippet_full.strip("\n")


# ====================================================================
#  对外工具函数
# ====================================================================

def get_source_snippet(
    file: str,
    startLine: int,
    startColumn: Optional[int] = None,
    endLine: Optional[int] = None,
    endColumn: Optional[int] = None,
    project_root: Optional[str] = None,
    contextLines: int = 3,
    encoding: str = "utf-8",
) -> str:
    """根据文件路径和行列信息，返回代码片段和上下文。"""
    file_path = os.path.join(project_root, file) if project_root else file

    ok, data = _safe_read_lines(file_path, encoding=encoding)
    if not ok:
        return f"// ERROR: {data} (file={file_path})"

    return _extract_snippet_from_lines(
        data,
        start_line=startLine,
        start_column=startColumn,
        end_line=endLine,
        end_column=endColumn,
        context_lines=contextLines,
    )


def search_code_in_file(
    file: str,
    query: Optional[str] = None,
    project_root: Optional[str] = None,
    case_sensitive: bool = False,
    contextLines: int = 3,
    maxSnippets: int = 20,
    encoding: str = "utf-8",
    keyword: Optional[str] = None,
    maxResults: Optional[int] = None,
) -> List[str]:
    """在单个源文件中根据关键字搜索相关代码片段。

    - 支持参数名 query 或 keyword，二者等价（兼容不同提示示例）
    - 返回的每个元素都是一段多行代码字符串
    - 最多返回 maxSnippets 段
    """
    file_path = os.path.join(project_root, file) if project_root else file

    # 兼容 keyword / maxResults 参数别名
    if query is None and keyword is not None:
        query = keyword
    if not query:
        return ["// ERROR: missing 'query' or 'keyword' parameter for search_code_in_file"]
    if maxResults is not None:
        maxSnippets = maxResults

    ok, lines = _safe_read_lines(file_path, encoding=encoding)
    if not ok:
        return [f"// ERROR: {lines} (file={file_path})"]

    q = query if case_sensitive else query.lower()
    snippets: List[str] = []

    for idx, line in enumerate(lines):
        hay = line if case_sensitive else line.lower()
        if q in hay:
            snippet = _extract_snippet_from_lines(
                lines,
                start_line=idx + 1,
                context_lines=contextLines,
            )
            snippets.append(snippet)
            if len(snippets) >= maxSnippets:
                break

    return snippets


def search_project_files(
    root_dir: str,
    keyword: str,
    maxResults: int = 200,
    include_dirs: bool = False,
) -> List[str]:
    """在指定项目根目录下，根据关键词查找文件（以及可选的目录），返回相对路径列表。"""
    matches: List[str] = []
    k = keyword.lower()

    for dirpath, dirnames, filenames in os.walk(root_dir):
        rel_dir = os.path.relpath(dirpath, root_dir)
        if rel_dir == ".":
            rel_dir = ""

        # 目录匹配
        if include_dirs:
            for d in dirnames:
                if k in d.lower():
                    rel_path = os.path.join(rel_dir, d) if rel_dir else d
                    matches.append(rel_path)
                    if len(matches) >= maxResults:
                        return matches

        # 文件匹配
        for f in filenames:
            if k in f.lower():
                rel_path = os.path.join(rel_dir, f) if rel_dir else f
                matches.append(rel_path)
                if len(matches) >= maxResults:
                    return matches

    return matches


def search_symbol_in_project(
    root_dir: str,
    symbol: str,
    case_sensitive: bool = True,
    maxResults: int = 300,
    include_exts: Optional[List[str]] = None,
    encoding: str = "utf-8",
) -> List[Dict[str, Any]]:
    """在整个项目目录下按符号名搜索相关代码位置。

    返回的每一项包含：相对路径、行号、行内容。
    """
    DEFAULT_EXTS = {
        ".java", ".kt", ".xml", ".yml", ".yaml",
        ".properties", ".sql", ".jsp", ".js", ".ts", ".py",
    }

    results: List[Dict[str, Any]] = []

    if not os.path.isdir(root_dir):
        return [{"file": "", "line": 0, "text": f"[ERROR] root_dir is not a directory: {root_dir}"}]

    exts = {e.lower() for e in (include_exts or DEFAULT_EXTS)}
    target = symbol if case_sensitive else symbol.lower()

    for dirpath, _, filenames in os.walk(root_dir):
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if exts and ext not in exts:
                continue

            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "r", encoding=encoding, errors="ignore") as f:
                    for idx, line in enumerate(f, start=1):
                        hay = line if case_sensitive else line.lower()
                        if target in hay:
                            rel_path = os.path.relpath(fpath, root_dir)
                            results.append({
                                "file": rel_path,
                                "line": idx,
                                "text": line.rstrip("\n"),
                            })
                            if len(results) >= maxResults:
                                return results
            except Exception as e:
                rel_path = os.path.relpath(fpath, root_dir)
                results.append({
                    "file": rel_path,
                    "line": 0,
                    "text": f"[ERROR] read file failed: {e}",
                })
                if len(results) >= maxResults:
                    return results

    return results
