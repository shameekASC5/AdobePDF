# Producing PDF Malware: A Wakeup Call to the Masses

Disclaimer: This production is for research purposes only! Please do not use any of this code for
malicious purposes.

Paper Summary (Claude AI): This project aims to reproduce known vulnerabilities in Adobe Reader version 9.0 and test obfuscation techniques against antivirus software. Specifically, it creates a malicious PDF file that exploits CVE-2010-1242 to launch a reverse shell, and another PDF that uses a heap spray attack. The malware payloads include a keylogger and a program to take webcam screenshots. The project obfuscates the malware using techniques like encoding and JavaScript functions, and then tests the detection rates of 63 antivirus programs on VirusTotal against the plain and obfuscated versions. It also compares the malware to existing Metasploit exploits targeting the same vulnerabilities.

## Repository Description

This repository houses a folder of malicious PDF files, another folder of basic malware written in python, and a collection of scripts to source and analyze CVEs for the Adobe Reader software as reported by https://cve.mitre.org/. The PDF files are detailed in the paper. 

## Getting Started

Run pip install -r requirements.txt to fetch the dependencies for the selenium webscraper and the malware scripts. 

### Research Scripts

1. ```scrape_lineage.py```: produces a csv file from the table of CVEs at https://cve.mitre.org/
2. ```prepare_cve_insights.py```: examines each CVE in the csv file, updating the csv to include year of report, affected software versions and the types of vulnerabilities reported in the CVE. 
3. ```extract_cve_insights.py```: uses the updated csv file with year, version and vulnerability type information to build JSON files with a filtered subset of the CVEs. Allows for search by affected year, version or vulnerability types.
4. ```quick_extract.py```: uses the extract script to source data for all CVEs by year. Produces 25 JSON files, on for each year. Used it to build the graph below after combining the data into a list.
