##################################################################
# quick_extract.py
# Author: Shameek Hargrave 
# Purpose: Examines the Adobe Reader CVEs from 1999-2023,
# producing a JSON file detailing all Adobe Readers CVE for each year 
# in the above range. 
##################################################################
from extract_cve_insights import find_cve_type_counts, vulnerability_types
from prepare_cve_insights import segment_cves_by_year_and_version
import json
def get_all_cves_by_year(min_year, max_year):
    "Writes a json file for each year in range, detailing the cves."
    for i in range(int(min_year), int(max_year)+1):
        year = str(i)
        cves_2010 = find_cve_type_counts(row_data=segment_cves_by_year_and_version(), cve_types=vulnerability_types, year_match=year)
        with open(f"../output/cves_by_year/{year}_cves.json", "w") as file:
            json.dump(cves_2010, file, indent=4)

if __name__ == "__main__":
    print("...Starting to write JSON files...")
    get_all_cves_by_year(1999, 2023)
    print("...Job Finished! Check the ../output/cves_by_year directory...")

