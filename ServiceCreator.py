import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import os
# python .\ServiceCreator.py --startup=auto install
class AppServerSvc (win32serviceutil.ServiceFramework):
    _svc_name_ = "Test Service"
    _svc_display_name_ = "Test Service"
    _svc_description_  = "Testing"*5

    def __init__(self,args):
        win32serviceutil.ServiceFramework.__init__(self,args)
        self.hWaitStop = win32event.CreateEvent(None,0,0,None)
        socket.setdefaulttimeout(60)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                          servicemanager.PYS_SERVICE_STARTED,
                          (self._svc_name_,''))
        self.main()

    def main(self):
        # Your business logic or call to any class should be here
        # this time it creates a text.txt and writes Test Service in a daily manner 
        rc = None
        while rc != win32event.WAIT_OBJECT_0:
            os.system("exepath")
            # block for 24*60*60 seconds and wait for a stop event
            # it is used for a one-day loop
            rc = win32event.WaitForSingleObject(self.hWaitStop, 24 * 60 * 60 * 1000)
        return

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(AppServerSvc)