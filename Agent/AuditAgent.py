import re
import json

from Agent.AuditLLM import AuditLLM
from Tool.Tool import ToolExecutor
from Agent.prompt import REACT_SYSTEM_PROMPT


class AuditAgent:
    """基于 ReAct 范式的安全审计 Agent，循环执行 Thought → Action → Observation。"""

    def __init__(self, llm_client: AuditLLM, tool_executor: ToolExecutor, max_steps: int = 25):
        self.llm_client = llm_client
        self.tool_executor = tool_executor
        self.max_steps = max_steps
        self.history = []

    # ------------------------------------------------------------------
    #  主循环
    # ------------------------------------------------------------------

    def run(self, question: str):
        """启动 ReAct 循环，对给定的 CodeQL 流数据进行研判。"""

        self.history = []
        current_step = 0

        # 初始对话 messages: system + 用户任务描述
        tools_desc = self.tool_executor.getAvailableTools()
        system_prompt = REACT_SYSTEM_PROMPT.format(tools=tools_desc)
        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": (
                    "下面是 CodeQL 给出的流数据和分析任务，请你按照 Thought / Action / Finish 的规范，"
                    "逐步调用工具进行研判，最终判断这是否为真实漏洞还是误报，并给出理由。\n\n"
                    f"{question}"
                ),
            },
        ]

        while current_step < self.max_steps:
            current_step += 1
            print(f"--- 第 {current_step} 步 ---")

            # 调用 LLM 开始思考
            response_text = self.llm_client.think(messages)

            if not response_text:
                print("错误：LLM未能返回有效响应")
                break

            thought, action = self._parse_output(response_text)

            # 记录本轮 assistant 输出到对话历史
            messages.append({"role": "assistant", "content": response_text})

            if thought:
                print(f"思考：{thought}")

            if not action:
                print("没有解析出有效action，不推进下一步")
                break

            # ---------- Finish 分支 ----------
            if action.strip().lower().startswith("finish"):
                final_answer = self._extract_final_answer(action)
                print(f"🎉 最终答案: {final_answer}")
                return final_answer

            # ---------- 工具调用分支 ----------
            tool_name, tool_input = self._parse_action(action)
            if not tool_name or not tool_input:
                print("无效action格式，不处理，推进下一步")
                continue

            print(f"🎶 行动: {tool_name}{tool_input}")

            observation = self._execute_tool(tool_name, tool_input)
            print(f"👀 观察: {observation}")

            # 将本轮的 Action 和 Observation 添加到文本历史（调试用）
            self.history.append(f"Action: {action}")
            self.history.append(f"Observation: {observation}")

            # 同时把 Observation 作为新的 user 消息加入对话，使下一轮能够基于最新信息继续推理
            messages.append({
                "role": "user",
                "content": (
                    f"Observation: {observation}\n\n"
                    "请基于上述 Observation 继续输出新的 Thought 和 Action，"
                    "不要重复之前已经给出的长篇分析，只关注新的推理和下一步行动。"
                ),
            })

        print("已达到最大步数，流程终止。")
        return None

    # ------------------------------------------------------------------
    #  解析辅助方法
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_final_answer(action: str) -> str:
        """从 Finish 动作中提取最终答案，兼容多种格式。"""
        m = (
            re.search(r"Finish\[(.*)\]", action, re.IGNORECASE | re.DOTALL)
            or re.search(r"Finish\((.*)\)", action, re.IGNORECASE | re.DOTALL)
            or re.search(r"Finish[:：](.*)", action, re.IGNORECASE | re.DOTALL)
        )
        return m.group(1).strip() if m else action

    @staticmethod
    def _parse_output(text: str):
        """解析 LLM 的输出，提取 Thought 和 Action。

        兼容两种情况：
        1. 正常的 ReAct 输出，包含显式的 'Action: ...'
        2. 只写了 Thought 和一个 'Finish:' 段落（没有 Action 行）
        """
        thought_match = re.search(r"^Thought:\s*(.*)$", text, re.MULTILINE)
        action_match = re.search(r"^Action:\s*(.*)$", text, re.MULTILINE)

        thought = thought_match.group(1).strip() if thought_match else None
        action = action_match.group(1).strip() if action_match else None

        # 如果没有显式 Action，但正文里有 Finish: 段，就把那一段包装成 Finish[...] 当作 Action
        if action is None:
            finish_match = re.search(r"Finish[:：]\s*(.*)", text, re.IGNORECASE | re.DOTALL)
            if finish_match:
                final_text = finish_match.group(1).strip()
                action = f"Finish[{final_text}]"

        return thought, action

    @staticmethod
    def _parse_action(action_text: str):
        """解析 Action 字符串，提取工具名称和输入。

        期望格式示例：
            get_source_snippet[{"file": "...", "startLine": 50, ...}]
        """
        action_text = action_text.strip()
        match = re.match(r"^([A-Za-z_]\w*)\s*\[(.*)\]\s*$", action_text, re.DOTALL)
        if match:
            return match.group(1), match.group(2).strip()
        return None, None

    def _execute_tool(self, tool_name: str, tool_input: str) -> str:
        """根据工具名称查找并执行工具，返回 observation 字符串。"""
        tool_function = self.tool_executor.getTool(tool_name)
        if not tool_function:
            return f"错误：未找到名为'{tool_name}'的工具"

        # tool_input 是 JSON 对象字符串，优先尝试解析为 kwargs
        try:
            parsed = json.loads(tool_input)
            if isinstance(parsed, dict):
                return tool_function(**parsed)
            return tool_function(parsed)
        except json.JSONDecodeError:
            return tool_function(tool_input)
