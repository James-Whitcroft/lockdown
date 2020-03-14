from lockdown import Locker
from action import Action, TriggerType


def custom():
  print('custom')

def main():
  
  action = Action(TriggerType.PROC_NAME, 'notepad.exe', custom)
#   port_action = Action(TriggerType.CON_PORT, 443, custom)
#   ip_action = Action(TriggerType.CON_IP, '23.213.175.172', custom)
  lock = Locker(panic=False, panic_pass='panicpassword') #set up your Locker
#   lock.actions = port_action
#   lock.actions = ip_action
#   lock.private_exes = 'secret.exe' #append more exes
#   lock.private_exes = ['slack.exe', 'excel.exe'] #lists are ok too
  lock.private_paths = '/user'
  lock.actions = action
  lock.run()

if __name__ == '__main__':
  main()