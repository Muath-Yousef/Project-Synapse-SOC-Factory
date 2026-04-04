from enum import Enum

class ActionType(Enum):
    BLOCK_IP        = "block_ip"
    NOTIFY_ONLY     = "notify_only"
    PATCH_ADVISORY  = "patch_advisory"
    ESCALATE_HUMAN  = "escalate_human"

class BasePlaybook:
    def __init__(self, name, trigger_rules=None):
        self.name = name
        self.trigger_rules = trigger_rules or []

    def execute(self, alert: dict):
        raise NotImplementedError("Subclasses must implement execute()")
