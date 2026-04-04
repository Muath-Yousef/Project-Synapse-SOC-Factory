class BasePlaybook:
    def __init__(self, name, trigger_rules=None):
        self.name = name
        self.trigger_rules = trigger_rules or []

    def execute(self, alert: dict):
        raise NotImplementedError("Subclasses must implement execute()")
