import os
import psutil
from trigger import Trigger, TriggerType
from error import Error

class Locker:

    '''
    :param: lockdown          True if you want to trigger screen_lock
    :param: panic             True if you want to trigger change_password
    :param: user              String user name that is changed in change_password
    :param: panic_pass        String password to change when change_password is triggered
    :param: private_paths     String or list of Strings representing paths or partial paths
                                that, if seen, trigger actions based on set flags
    :param: private_exes      String or list of Strings representing executable names
                                that, if seen, trigger actions based on set flags
    '''
    def __init__(self,
        lockdown=False,
        panic=False,
        user='%USERNAME%',
        panic_pass=None,
        private_paths=None,
        private_exes=None,
        private_networks=None,
        private_ports=None,
        triggers=None,
        debug=False
    ):
        if private_paths == None: private_paths = []
        if private_exes == None: private_exes = []
        if private_networks == None: private_networks = []
        if private_ports == None: private_ports = []
        if triggers == None: triggers = []
        self._lockdown = lockdown
        self._panic = panic
        self._user = user
        self._panic_pass = panic_pass
        self._private_paths = private_paths if isinstance(private_paths, list) else [private_paths]
        self._private_exes = private_exes if isinstance(private_exes, list) else [private_exes]
        self._private_networks = private_networks if isinstance(private_networks, list) else [private_networks]
        self._private_ports = private_ports if isinstance(private_ports, list) else [private_ports]
        self._connection_memory = {}
        self._process_memory = {}
        self._go = True
        self._triggers = triggers if isinstance(triggers, list) else [triggers]
        self._errored = False
        self._debug = debug
        self._locked = False

    @property
    def lockdown(self):
        return self._lockdown

    @property
    def panic(self):
        return self._panic

    @property
    def user(self):
        return self._user

    @property
    def private_paths(self):
        return self._private_paths

    @property
    def private_exes(self):
        return self._private_exes

    @property
    def private_networks(self):
        return self._private_networks
        
    @property
    def private_ports(self):
        return self._private_ports

    @property
    def panic_pass(self):
        return self._panic_pass

    @property
    def go(self):
        return self._go

    @property
    def triggers(self):
        return self._triggers

    @triggers.setter
    def triggers(self, triggers):
        if isinstance(triggers, list):
            for trigger in triggers:
                assert isinstance(trigger, Trigger), Error.TRIGGER_TYPE
                self._triggers.append(trigger)
        else:
            assert isinstance(triggers, Trigger), Error.TRIGGER_TYPE
            self._triggers.append(triggers)

    @lockdown.setter
    def lockdown(self, boolean):
        if isinstance(boolean, bool):
            self._lockdown = boolean

    @panic.setter
    def panic(self, panic):
        if isinstance(panic, bool):
            self._panic = panic
        
    @panic_pass.setter
    def panic_pass(self, passwd):
        if isinstance(passwd, str):
            self._panic_pass = passwd
        
    @private_paths.setter
    def private_paths(self, paths):
        if isinstance(paths, list):
            for path in paths:
                assert isinstance(path, str)
                self._private_paths.append(path.lower())
        else:
            assert isinstance(paths, str)
            self._private_paths.extend(paths.lower())

    @private_exes.setter
    def private_exes(self, exes):
        if isinstance(exes, list):
            for exe in exes:
                assert isinstance(exe, str)
                self._private_exes.append(exe.lower())
        else:
            assert isinstance(exes, str)
            self._private_exes.extend(exes.lower())
            
    @private_networks.setter
    def private_networks(self, nets):
        if isinstance(nets, list):
            for net in nets:
                assert isinstance(net, str)
                self._private_networks.append(net.lower())
        else:
            assert isinstance(nets, str)
            self._private_networks.extend(nets.lower())

    @private_ports.setter
    def private_ports(self, ports):
        if isinstance(ports, list):
            for port in ports:
                assert isinstance(port, int)
                self._private_ports.append(port)
        else:
            assert isinstance(ports, int)
            self._private_ports.append(ports)

    @go.setter
    def go(self, go):
        if isinstance(go, bool):
            self._go = go

    def set_state(self):

        ''' Set the current state of process list'''

        process_list = []
        for process_id in psutil.pids():
            try:
                temp_process = psutil.Process(process_id)
                process_list.append(temp_process)
                self._process_memory[process_id] = temp_process.name()
                self._connection_memory[temp_process.name()] = temp_process.connections()
            except Exception:
                pass
        return process_list

    def monitor_process_list(self, previous_process_list):

        ''' Monitor proccesses running and finishing
            if in debug mode print changes to process list to stdout
        '''

        current_process_list = self.set_state()
        matched = 0
        
        for proc_current in current_process_list:
            for proc_previous in previous_process_list:
                if proc_previous == proc_current:
                    matched = 1
                    break
            if not matched:
                name = str(proc_current.name()).lower()
                if self._debug: print(' +++ ' + name + ' : ' + str(proc_current.pid))
                if proc_current.connections():
                    if self._debug: print(proc_current.connections())
                self._check_for_trigger(proc_current)
            
            matched = 0
        matched = 0

        for proc_previous in previous_process_list:
            try:
                name = proc_previous.name()
            except Exception:
                try:
                    name = str(self._process_memory[proc_previous.pid])
                except Exception:
                    name = proc_previous
            for proc_current in current_process_list:
                if proc_previous == proc_current:
                    matched = 1
                    break
            if not matched:
                if self._debug: print(' --- ' + str(name) + ' : ' + str(proc_previous.pid))
            matched = 0

        return current_process_list

    def _act(self):
        if self._panic: self._change_password()
        if self._lockdown: self._lock_screen()

    def _check_for_trigger(self, proc_current):

        ''' Looking for exe or paths
        may trigger locks or password changes depending on flags set

        '''
        
        name = proc_current.name().lower()

        for trigger in self._triggers:
            if trigger.trigger_type == TriggerType.PROC_NAME:
                if trigger.trigger == name:
                    trigger.act()

            if trigger.trigger_type == TriggerType.HASH_MOD:
                if trigger.trigger == name:
                    trigger.act()

            elif trigger.trigger_type == TriggerType.PROC_CWD:
                try: dir = proc_current.cwd().lower()
                except: dir = ''
                if trigger.trigger in dir:
                    trigger.act()

            elif trigger.trigger_type == TriggerType.CON_PORT or trigger.trigger_type == TriggerType.CON_IP:
                for con in proc_current.connections():
                    if len(con.raddr):
                        if trigger.trigger == con.raddr[1]:
                            trigger.act()
                        if trigger.trigger == con.raddr[0]:
                            trigger.act()
                
                
        for bad in self._private_paths:
            try: dir = proc_current.cwd().lower()
            except: dir = ''
            try: files = proc_current.open_files()
            except: files = ''
            if bad in dir or bad in files:
                self._act()

        if name in self._private_exes:
            self._act()

        for con in proc_current.connections():
            if len(con.raddr):
                for ip in self._private_networks:
                    if con.raddr[0] == ip:
                        self._act()
            for port in self._private_ports:
                if con.raddr[1] == port:
                    self._act()

    def _lock_screen(self):

        ''' Lock the screen'''
        if self._locked: return
        action = ('gnome-screensaver-command --lock', 'rundll32.exe user32.dll,LockWorkStation')[os.name == 'nt']
        os.system(action)
        self._locked = True

    def _change_password(self):

        ''' Change password
        windows specific
        '''

        try:
            os.system('net user ' + self._user + ' ' + self._panic_pass)
        except Exception:
            return 0
        return 1

    def run(self):

        ''' Loop to collect process state, check for not-allowed, and print changes to screen'''

        init = self.set_state()
        while self._go:
            init = self.monitor_process_list(init)
        return
        