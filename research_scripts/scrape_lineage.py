##################################################################
# scrape_lineage.py
# Author: Shameek Hargrave 
# Purpose: Examines the Adobe Reader CVEs from 2000-2024,
# packaging them into a CSV file for segmentation by
#  impacted software version, vulnerability type.
##################################################################

# import libraries selenium and time 
from selenium import webdriver 
from selenium.webdriver.common.by import By 
from time import sleep 
import csv

def save_to_csv(row_data, filename):
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        # writer.writerow(fields) [includes the header]
        writer.writerows(row_data)

def fetch_data():
    # Create webdriver object 
    driver = webdriver.Chrome()

    # navigate to Adobe Reader CVE List
    driver.get("https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=adobe+reader")
    sleep(2) 

    table_xpath = "/html/body/div[2]/div[3]/div[2]/table/tbody"  

    rows = len(driver.find_elements(By.XPATH, f"{table_xpath}/tr")) 
    cols = len(driver.find_elements(By.XPATH, f"{table_xpath}/tr[1]/td")) 
    
    # init with csv file header
    row_data = [["Name", "Description"]]
    for r in range(1, rows+1): 
        name = ""
        description = ""
        for p in range(1, cols+1): 
            value = driver.find_element(By.XPATH, f"{table_xpath}/tr["+str(r)+"]/td["+str(p)+"]").text 
            if p == 1:
                name = value
            elif p == 2:
                description = value
        row_data.append([name, description])

    driver.quit()
    return row_data

if __name__ == "__main__":
    data = fetch_data()
    save_to_csv(data, filename='adobe_reader_cves.csv')

