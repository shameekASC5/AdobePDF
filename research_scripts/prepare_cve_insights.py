##################################################################
# prepare_cve_insights.py
# Author: Shameek Hargrave 
# Purpose: Examines the Adobe Reader CVEs from 2000-2024,
# producing a CSV file detailing each CVE with the impacted
# software version, vulnerability type, year and other semantic info
##################################################################
import csv
from scrape_lineage import save_to_csv
import re

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
    ]
    
def read_cves_from_csv():
    # read the csv file
    row_data = []
    with open('adobe_reader_cves.csv', 'r') as file:
        reader = csv.reader(file)
        # reader.writerow(fields) [includes the header]
        for row in reader:
            row_data.append(row) 
        # remove header
        del row_data[0]
    return row_data

def segment_cves_by_year_and_version(verbose=False):
    data = read_cves_from_csv()
    # add more types later 
    patterns = [
        "use.after.free",
        "out.of.bounds.read",
        "heap.based.buffer.overflow", 
        "stack.based.buffer.overflow",
        "heap.overflow",
        "out.of.bounds.write", 
        "denial.of.service",
        'untrusted.search.path.vulnerability',
        'arbitrary.code',
        'crlf.injection.vulnerability',
        'double.free.vulnerability',
        'cross.site.scripting',
        'xml.external.entity.vulnerability',
        'format.string.vulnerability',
        "do.not.properly.validate.input",
        "uninitialized.pointer.vulnerability",
        "information.disclosure.vulnerability",
        "privilege.escalation",
        "improper.input.validation",
        "disclosure.of.sensitive.data.vulnerability",
        "security.bypass.vulnerability",
        "race.condition.vulnerability",
        "invalid.memory.access.vulnerability",
        "insecure.library.loading.(dll.hijacking).vulnerability",
        "memory.address.leak.vulnerability",
        "integer.overflow.vulnerability",
        "NTLM.SSO.hash.theft.vulnerability",
        "memory.corruption.vulnerability",
        "sensitive.data.exposure",
        "buffer.overflow", #keep this last, see part about avoiding double
    ]

    extraneous_types = [
        ".* .* vulnerability",
        "vulnerability .* .*",
    ]
    # extract insight from each row, change to new format
    transformed_data = [["Year", "Reader Versions", "Types", "Name", "Description", "Adobe Reader", "Adobe Acrobat"]]
    other_data = [["Year", "Reader Versions", "Types", "Name", "Description", "Adobe Reader", "Adobe Acrobat"]]
    for row in data:
        name = row[0]
        description = row[1]
        year = name.split("-")[1]
        #versions need regex 10.1.16 || 11.x || 2015.006.300094
        versions = re.findall('[0-9]+\.[0-9]+\.?[0-9]*', description)
        this_vulnerability_type = []
        effects_reader = False
        effects_acrobat = False
        
        normalized_descrip = description.lower()

        # if name == "CVE-2003-0508":
        #     print(normalized_descrip)

        # make sure adobe reader is referenced
        if "Adobe Reader" in description:
            effects_reader = True
        elif "Adobe Acrobat Reader" in description:
            effects_reader = True
            effects_acrobat = True
        elif "Adobe Acrobat and Reader" in description:
            effects_reader = True
            effects_acrobat = True

        skip_double_overflow = False
        # only searches for one vulnerability type, havent found multiple
        for i in range(0, len(patterns)):
            matches = re.findall(patterns[i], normalized_descrip)
            # avoids double for heap/stack overflow
            if len(matches) > 0:
                if (i == len(patterns)-1 and not skip_double_overflow):
                    this_vulnerability_type.append(vulnerability_types[i])
                elif i < len(patterns)-1:
                    this_vulnerability_type.append(vulnerability_types[i])
                    if i == 2 or i == 3:
                        skip_double_overflow = True

        if len(this_vulnerability_type) > 1 and verbose:
            print(f"{name} matched multiple vulnerabilities")
            print(this_vulnerability_type)
        # help find unknown vulnerabilty types
        if len(this_vulnerability_type) == 0:
            for i in range(0, len(extraneous_types)):
                matches = re.findall(extraneous_types[i], normalized_descrip)
                if len(matches) > 0:
                    this_vulnerability_type.append(matches)
            other_data.append([year, versions, this_vulnerability_type, name, description, effects_reader, effects_acrobat])
        # add other in worst case
        if len(this_vulnerability_type) == 0:
            this_vulnerability_type.append("other")

        
        transformed_data.append([year, versions, this_vulnerability_type, name, description, effects_reader, effects_acrobat])
    # print(other_data)
    return transformed_data
          

if __name__ == "__main__":
    transformed_data = segment_cves_by_year_and_version()       
    save_to_csv(transformed_data, filename='segmented_adobe_reader_cves.csv')

