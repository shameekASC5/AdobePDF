##################################################################
# extract_cve_insights.py
# Author: Shameek Hargrave 
# Purpose: Examines the Adobe Reader CVEs from 2000-2024,
# producing a CSV file detailing each CVE with the impacted
# software version, vulnerability type, year and other semantic info
##################################################################
import csv
from scrape_lineage import save_to_csv
from prepare_cve_insights import vulnerability_types, segment_cves_by_year_and_version
import re
import json
def read_cves_from_csv():
    # read the csv file
    row_data = []
    with open('segmented_adobe_reader_cves.csv', 'r') as file:
        reader = csv.reader(file)
        # reader.writerow(fields) [includes the header]
        for row in reader:
            row_data.append(row) 
        # remove header
        del row_data[0]
    return row_data

def is_version_match(version_pattern, list_of_versions):
    total_length = 0
    for version in list_of_versions:
        matches = re.findall(version_pattern, version)
        total_length += len(matches)
    return total_length

def is_vulnerability_in_list_of_vulns(vuln, list_vulns):
    for vulnerability in list_vulns:
        if vuln == vulnerability:
            return True
    return False

def find_cve_type_counts(row_data, cve_types, version= "all", year_match= "all", specific_vulnerabilities = [], all_versions_with_num=False):
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
        "count by vulnerability type": cve_type_counts,
        "cves with multiple vulnerabilities": points_w_multiple_types, 
        # "acrobat_only": acrobat_only_count, 
        # "reader only": reader_only_count,
        # "both": both_count,
    }
    return output
        
if __name__ == "__main__":
    # Format: ["Year", "Reader Versions", "Types", "Name", "Description", "Adobe Reader", "Adobe Acrobat"]
    # data = read_cves_from_csv()
    data = segment_cves_by_year_and_version()
    # remove header
    del data[0]

    # for each year, show the vulnerability types by #cves
    start_year = 1999
    end_year = 2024
    cve_types = vulnerability_types.copy()
    cve_types.append("other")
    output = find_cve_type_counts(row_data=data, cve_types=cve_types)
    # output = find_cve_type_counts(row_data=data, cve_types=cve_types, specific_vulnerabilities=["heap based buffer overflow", "buffer overflow"])
    # returns data on the different cve types for all versions 9.XXX.XXX
    # output = find_cve_type_counts(row_data=data, cve_types=cve_types, version="11", all_versions_with_num=True)

    # print(output)
    with open("sample.json", "w") as file:
        json.dump(output, file, indent=4)
    # for each reader version, show the vulnerability types, should be similar as year 
    # list comes from the traversal of each row
    versions_to_check = []
    # for the heap based buffer overflow in particular, show the trend over the years



    # save_to_csv(transformed_data, filename='segmented_adobe_reader_cves.csv')
        


