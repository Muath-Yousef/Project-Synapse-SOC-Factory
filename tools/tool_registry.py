import os
import sys
import importlib
import inspect
import logging

logger = logging.getLogger(__name__)

class ToolRegistry:
    """
    Dynamically discovers and registers all tools in the tools directory
    that inherit from BaseTool. Re-evaluates plugins at runtime.
    """
    def __init__(self):
        self.available_tools = {}
        self.discover_tools()

    def discover_tools(self):
        logger.info("[ToolRegistry] Initiating Tool Auto-Discovery Phase...")
        tools_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Ensure parent directory is in sys.path to resolve 'tools.' imports smoothly
        parent_dir = os.path.dirname(tools_dir)
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)
            
        from tools.base_tool import BaseTool

        for filename in os.listdir(tools_dir):
            if filename.endswith(".py") and filename not in ["__init__.py", "base_tool.py", "tool_registry.py"]:
                module_name = f"tools.{filename[:-3]}"
                try:
                    # Dynamically import the module
                    module = importlib.import_module(module_name)
                    
                    # Inspect classes within the module
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        # Ensure it subclasses BaseTool and is not the BaseTool itself
                        if issubclass(obj, BaseTool) and obj is not BaseTool:
                            # Instantiate and register
                            instance = obj()
                            self.available_tools[instance.name] = instance
                            logger.info(f"[ToolRegistry] Discovered and Registered Tool: {instance.name} (from {filename})")
                            
                except Exception as e:
                    logger.error(f"[ToolRegistry] Failed to load module {module_name}: {e}")

    def get_tool(self, tool_name: str):
        return self.available_tools.get(tool_name)
        
    def list_tools(self):
        return list(self.available_tools.keys())
