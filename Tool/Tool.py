"""工具注册与管理模块。"""

from typing import Callable, Dict, Any


class ToolExecutor:
    """工具执行器，负责管理和执行工具。"""

    def __init__(self):
        self.tools: Dict[str, Dict[str, Any]] = {}

    def registerTool(self, name: str, description: str, func: Callable):
        """注册一个工具。"""
        if name in self.tools:
            print(f"Tool {name} already registered")
        self.tools[name] = {"description": description, "func": func}
        print(f"Tool {name} registered")

    def getTool(self, name: str) -> Callable:
        """根据工具名称获取对应的执行函数。"""
        return self.tools.get(name, {}).get("func")

    def getAvailableTools(self) -> str:
        """获取所有可用工具的格式化描述字符串。"""
        return "\n".join(
            f"- {name}: {info['description']}"
            for name, info in self.tools.items()
        )
