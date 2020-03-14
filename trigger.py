
class TriggerType:
    PROC_NAME, PROC_CWD, PROC_PID, CON_IP, CON_PORT, HASH_MOD = range(6)


class Trigger:
  
    ''' Triggers support multiple actions
        trigger type must be valid TriggerType enum
        trigger must be a string; process name, directory|subdirectory
        action must be a single function, this function can obviously call as many helpers
        as needed
    '''
  
    def __init__(self, trigger_type, trigger, actions):
        self._trigger_type = trigger_type
        self._trigger = trigger
        self._actions = actions if isinstance(actions, list) else [actions]
        assert isinstance(self._trigger_type, int)
        if self._trigger_type == TriggerType.CON_PORT:
            assert isinstance(self._trigger, int)
        else: assert isinstance(self._trigger, str)
        for action in self._actions:
            assert callable(action)

    @property
    def trigger_type(self):
        return self._trigger_type

    @property
    def trigger(self):
        if isinstance(self._trigger_type, int):
            return self._trigger
        return self._trigger.lower()

    @property
    def actions(self):
        return self._actions

    def act(self):
        for act in self._actions:
            act()