##################################################################
# send_file_updates.py
# Author: Shameek Hargrave 
# Purpose: Fetches a list of files, checking the last time they 
# updated to send the updated versions over ftp.
##################################################################

import ftplib

def send_files_to_server(files_list, hostname, username, password):
    ftp_server = ftplib.FTP(hostname, username, password)
    ftp_server.encoding = "utf-8"
    for filename in files_list:
        with open(filename, "rb") as file:
            ftp_server.storbinary(f"STOR {filename}", file)
    ftp_server.quit()

    