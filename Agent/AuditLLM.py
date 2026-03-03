import os
from openai import OpenAI
from typing import List, Dict


class AuditLLM:
    """封装 LLM 调用，通过 OpenAI 兼容接口与大模型交互。"""

    def __init__(
        self,
        model: str = None,
        api_key: str = None,
        base_url: str = None,
        timeout: int = 60,
    ):
        self.model = model or os.environ.get("AUDIT_LLM_MODEL", "kimi-k2.5")
        api_key = api_key or os.environ.get(
            "AUDIT_LLM_API_KEY",
            "",
        )
        base_url = base_url or os.environ.get(
            "AUDIT_LLM_BASE_URL",
            "https://api.moonshot.cn/v1",
        )

        self.client = OpenAI(api_key=api_key, base_url=base_url, timeout=timeout)

    def think(self, messages: List[Dict[str, str]], temperature: float = 1) -> str:
        """调用模型进行思考，返回完整响应文本。"""
        print(f"🧠 正在调用 {self.model} 模型")
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                stream=True,
            )

            print("✅ 模型思考响应成功")
            # 处理流式响应
            collected_content = []
            for chunk in response:
                content = chunk.choices[0].delta.content or ""
                print(content, end="", flush=True)
                collected_content.append(content)
            print()
            return "".join(collected_content)
        except Exception as e:
            print(f"❌ 调用LLM API时发生错误: {e}")
            return None
