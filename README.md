# lockdown
### A python tool that monitors processess and triggers actions
- Triggers
  * Found specified process names
  * Found processes spawned from specific directories or subdirectories
  * Found network connections to specific IPs
  * Found connections to specific ports
  
- Actions
  * Change user password
  * Lock screen
  * Custom functions supported

##### run as admin to use password change feature
```python
from action import *
from lockdown import Locker
lock = Locker(panic=True,
              panic_pass='panicpassword',
              private_exes='notepad.exe',
              pivate_paths=['c:']) #set up your Locker
lock.private_exes = 'secret.exe' #append more exes
lock.private_exes = ['slack.exe', 'excel.exe'] #lists are ok too
lock.private_paths = '/user' #add new paths the same way
lock.private_ports = 443 #trigger action on port traffic
lock.actions = Action(TriggerType.CON_IP, '23.213.175.172', lambda : print('connected to 23.213.175.172'))
lock.run() #run main loop
```

Install dependencies
-------------------------------
`setup.py install`
