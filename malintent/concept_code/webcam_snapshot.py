##################################################################
# webcam_snapshot.py
# Author: Shameek Hargrave 
# Purpose: Take a picture from the webcam.
##################################################################

import cv2
from datetime import datetime

def take_screenshot(filename, camera_index=0):
    # default to the first camera available
    camera = cv2.VideoCapture(camera_index)
    res, image = camera.read()
    
    if image is not None:
        cv2.imshow(filename, image)
        cv2.imwrite(filename, image)
        

if __name__ == "__main__":
    # set image name to current time/date
    current_time = datetime.now().strftime('%H:%M:%S %m-%d-%Y') + ".jpeg"
    take_screenshot(current_time)
