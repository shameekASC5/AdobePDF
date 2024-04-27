##################################################################
# extract_cve_insights.py
# Author: Shameek Hargrave 
# Purpose: Examines the Adobe Reader CVEs from 2000-2024,
# producing a CSV file detailing each CVE with the impacted
# software version, vulnerability type, year and other semantic info
##################################################################
import csv
from prepare_cve_insights import segment_cves_by_year_and_version
import re
import json

vulnerability_types = [
    "use after free", 
    "out of bounds read", 
    "heap based buffer overflow", 
    "stack based buffer overflow",
    "heap overflow",
    "out of bounds write", 
    "denial of service",
    'untrusted search path vulnerability',
    'arbitrary code execution',
    'crlf injection vulnerability',
    'double free vulnerability',
    'cross-site scripting',
    'xml external entity vulnerability',
    'format string vulnerability',
    "do not properly validate input",
    "uninitialized pointer vulnerability",
    "information disclosure vulnerability",
    "privilege escalation",
    "improper input validation",
    "disclosure of sensitive data vulnerability",
    "security bypass vulnerability",
    "race condition vulnerability",
    "invalid memory access vulnerability",
    "insecure library loading (dll hijacking) vulnerability",
    "memory address leak vulnerability",
    "integer overflow vulnerability",
    "NTLM SSO hash theft vulnerability",
    "memory corruption vulnerability",
    "sensitive data exposure", # seems to be code for buffer overflow in modern day
    "buffer overflow", #keep this last, see part about avoiding double
    "other"
]

def is_version_match(version_pattern, list_of_versions):
    """
    Returns the number of pattern matches for version_pattern
    in list_of_versions. 
    """
    total_length = 0
    for version in list_of_versions:
        matches = re.findall(version_pattern, version)
        total_length += len(matches)
    return total_length

def is_vulnerability_in_list_of_vulns(vuln, list_vulns):
    "Returns a boolean, indicating whether or not vuln string is in list_vulns."
    for vulnerability in list_vulns:
        if vuln == vulnerability:
            return True
    return False

def find_cve_type_counts(row_data, cve_types, version= "all", year_match= "all", specific_vulnerabilities = [], all_versions_with_num=False):
    """
    Based on the provided row_data, and specific_vulnerabilities/version number/year, 
    returns a dictionary of metrics on the CVEs that fit the search params.  
    
    Note: To get all the CVES for 8.X.X set year_match = "8" and all_versions_with_num=True
    
    Returns
    "params": initial filters (version/year_match)
    "most recent year": the most recent year found in all the records, 
    "oldest year": the oldest recent year found in all the records, 
    "number of records": the number of CVEs that matched search params,
    "number of vulnerabilities": cumulative total vulnerabilities across all CVEs that fit this request,
    "number of vulnerability types": the different vulnerability types found, as sourced from a preset list of 29,
    "count by vulnerability type": a dictionary with keys for each vulnerability type and values of the number of CVEs 
    it was found in,
    "cves with multiple vulnerabilities": number of CVEs that cite multiple vulnerabilities from the list of 29.
    """
    cve_type_counts = []
    total_vuln_types = 0
    num_vulns = 0
    num_row_matches = 0
    points_w_multiple_types = 0
    # acrobat_only_count = 0
    # reader_only_count = 0
    # both_count = 0
    # find every instance of this vulnerability
    seen_vulns = []
    for vuln in cve_types:
        count = 0

        if len(specific_vulnerabilities) == 0 or (len(specific_vulnerabilities) > 0 and is_vulnerability_in_list_of_vulns(vuln, specific_vulnerabilities)):

            for row in row_data:
                year = row[0]
                reader_version = row[1]
                vulnerability_types = row[2]
                # effects_reader = row[5]
                # effects_acrobat = row[6]
                # test
                version_matches = is_version_match(f"^{version}\.[0-9]*", reader_version)
                if (year_match == "all" and version == "all") or ((year == year_match) or (version in reader_version)) or (all_versions_with_num and version_matches > 0):
                    if vuln in vulnerability_types:
                        # some cves uncover vulnerabilities in multiple versions, 
                        # thus some rows may contain multiple version matches, whereas a year can only be matched once
                        if (all_versions_with_num and version_matches > 0):
                            count += version_matches
                        else:
                            count += 1
                        if vuln not in seen_vulns:
                            seen_vulns.append(vuln)
                            total_vuln_types += 1
                    # if len(vulnerability_types) > 0:
                    #     points_w_multiple_types = 1

                    # if effects_acrobat and effects_reader:
                    #     both_count += 1
                    # elif effects_reader:
                    #     reader_only_count += 1
                    # elif effects_acrobat:
                    #     acrobat_only_count +=1
            cve_type_counts.append({
                "name": vuln,
                "count": count,
            })
            num_vulns += count
    min_year = 2025
    max_year = 1990
    # loop through each row and count the total number of records and #of records with multiple vulnerabilites
    for row in row_data:
        year = row[0]
        reader_version = row[1]
        vulnerability_types = row[2]
        version_matches = is_version_match(f"^{version}\.[0-9]*", reader_version)
        vuln_match = False
        for vuln in vulnerability_types:
            if is_vulnerability_in_list_of_vulns(vuln, specific_vulnerabilities):
                vuln_match = True
                break
        if len(specific_vulnerabilities) == 0 or (len(specific_vulnerabilities) > 0 and vuln_match):
            if ((year_match == "all" and version == "all") or ((year == year_match) or (version in reader_version)) or (all_versions_with_num and version_matches > 0)):
                if (all_versions_with_num and version_matches > 0):
                    num_row_matches += version_matches
                else:
                    num_row_matches += 1
                if len(vulnerability_types) > 1:
                    # print(vulnerability_types)
                    # print(len(vulnerability_types))
                    points_w_multiple_types += 1
                if min_year > int(year):
                    min_year = int(year)
                elif max_year < int(year):
                    max_year = int(year)
    output = {
        "params" : {
            "version": version,
            "year": year_match
        },
        "most recent year": max_year, 
        "oldest year": min_year,
        "number of records": num_row_matches,
        "number of vulnerabilities": num_vulns,
        "number of vulnerability types": total_vuln_types,
        "cves with multiple vulnerabilities": points_w_multiple_types, 
        "count by vulnerability type": cve_type_counts,
        # "acrobat_only": acrobat_only_count, 
        # "reader only": reader_only_count,
        # "both": both_count,
    }
    return output
        
if __name__ == "__main__":
    # Format: ["Year", "Reader Versions", "Types", "Name", "Description", "Adobe Reader", "Adobe Acrobat"]
    data = segment_cves_by_year_and_version()
    # remove header
    del data[0]

    # for each year, show the vulnerability types by #cves
    start_year = 1999
    end_year = 2024
    cve_types = vulnerability_types.copy()
    
    print("...Running Unit Tests...")
    # basic example
    all_cves = find_cve_type_counts(row_data=data, cve_types=cve_types)
    with open("../output/samples/all_cves.json", "w") as file:
        json.dump(all_cves, file, indent=4)
    print("All CVES done!")
    
    # specific cves 
    buffer_overflow_cves = find_cve_type_counts(row_data=data, cve_types=cve_types, specific_vulnerabilities=["heap based buffer overflow", "buffer overflow"])
    with open("../output/samples/buffer_overflow_cves.json", "w") as file:
        json.dump(buffer_overflow_cves, file, indent=4)
    print("Buffer overflow CVES done!")

    # returns data on the different cve types for all versions 11.XXX.XXX
    version11_cves = find_cve_type_counts(row_data=data, cve_types=cve_types, version="11", all_versions_with_num=True)
    with open("../output/samples/adobe_v11.json", "w") as file:
        json.dump(version11_cves, file, indent=4)
    print("Adobe Reader v11 CVES done!")

    cves_2010 = find_cve_type_counts(row_data=data, cve_types=cve_types, year_match="2010")
    with open("../output/samples/2010_cves.json", "w") as file:
        json.dump(cves_2010, file, indent=4)
    print("2010 CVES done!")

    # for the heap based buffer overflow in particular, show the trend over the years


        


