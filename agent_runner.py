import win32serviceutil
import win32service
import win32event
import time
import subprocess
import os

class AgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "Dela-Agent-Service"
    _svc_display_name_ = "Dela Agent Service"
    _svc_description_ = "Service to monitor and restart agent application"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.running = True

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.running = False
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        while self.running:
            agent_path = r"C:\Program Files (x86)\Dela Tools\agent.exe"
            subprocess.run([agent_path], check=True)
            time.sleep(5) 

def configure_service():
    """Set service recovery options, startup type, and start the service using PowerShell."""
    SERVICE_NAME = AgentService._svc_name_

    subprocess.run([
        "sc", "failure", SERVICE_NAME, 
        "reset=86400",  
        "actions=restart/5000/restart/5000/restart/5000" 
    ], check=True)
    print(f"Restart options configured for {SERVICE_NAME}")

    subprocess.run([
        "sc", "config", SERVICE_NAME, "start=", "auto"
    ], check=True)
    print(f"Startup type set to automatic for {SERVICE_NAME}")

   
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'install':
        win32serviceutil.HandleCommandLine(AgentService)
        configure_service()
    else:
        win32serviceutil.HandleCommandLine(AgentService)
