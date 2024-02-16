import json
import sys
from bs4 import BeautifulSoup
import re
from xml.dom import minidom
from datetime import datetime
import dicttoxml
import os
import json
import re

def main(args):
    #path should be entered like: C:\path\file.html
    html_file = input("HTML file (C:\\path\\file.html): ")
    analyze_html_file(html_file)

def analyze_html_file(html_file):
    try:
        with open(html_file, encoding = "utf8") as file:
            high_findings = []
            medium_findings = []
            low_findings = []
            soup = BeautifulSoup(file, "html.parser")

            for x in range(3):
                findings_list = []
                match x:
                    case 0:
                        severity = "high"
                    case 1:
                        severity = "medium"
                    case 2:
                        severity = "low"
                
                vulnerabilities = soup.find_all("div", {"data-snyk-test": severity})

                if len(vulnerabilities) > 0:
                    for i in range(0, len(vulnerabilities)):
                        instances_list = []
                        cwe_id = vulnerabilities[i].find_all("ul", {"class": "card__meta"})[0].find_all("li")[1].text
                        
                        if len(cwe_id) > 7:
                            cwe_id = cwe_id[0:6]

                        name = vulnerabilities[i].find_all("h2", {"class": "card__title"})[0].text
                        desc = vulnerabilities[i].find_all("div", {"class": f"card__summary severity--{severity}"})[0].find_all("p")
                        full_desc = ""
                        full_solution = ""
                        full_detail = ""
                        details_list = []
                        solutions_list = []
                        class_name = vulnerabilities[i].find_all("div", {"class": "file-location"})[0].find_all("strong")[0].text
                        class_name_text = (re.sub(r"\([^()]*\)", "", class_name))
                        detail = vulnerabilities[i].find("h2", {"id": "details"}).next_siblings
                        solution_start = vulnerabilities[i].find("h2", {"id": "best-practices-for-prevention"})

                        overall_findings = vulnerabilities[i].find_all("div", {"class": "card__panel dataflow"})[0]
                        file_names = vulnerabilities[i].find_all("div", {"class": "dataflow__filename"})
                        
                        if solution_start is not None:
                            solution = solution_start.next_siblings
                            
                            for tag in solution:
                                if tag.name == "h2":
                                    break
                                solutions_list.append(tag.text.strip())

                            for j in range(0, len(solutions_list)):
                                full_solution += solutions_list[j]
                        else:
                            full_solution = solution_map(name)

                        for tag in detail:
                            if tag.name == "h2":
                                break
                            details_list.append(tag.text.strip())

                        code_count = -1
                        lines_count = 0

                        for item in overall_findings:
                            if item is not None:
                                found_file = str(item).find("dataflow__filename")
                                found_line = str(item).find("dataflow__lineno")
                                found_code = str(item).find("dataflow__code")
                                    
                                if found_file > -1:
                                    code = {
                                        "uri": item.text.strip(),
                                        "fullcode": []
                                    }
                                    instances_list.append(code)
                                    code_count += 1
                                    lines_count = 0
                                if (found_file == -1 or len(file_names) == 0) and code_count < 0:
                                    code = {
                                        "uri": re.sub(r'\([^)]*\)', "", class_name).strip(),
                                        "fullcode": []
                                    }
                                    instances_list.append(code)
                                    code_count += 1
                                if found_line > -1:
                                    line = re.findall(r'\d{1,9}:\d{1,9}', item.text)
                                    instances_list[code_count]["fullcode"].append({
                                        "lineno": line[0],
                                        "param": ""
                                    })
                                if found_code > -1:
                                    param = re.findall(r'\n(.*)', item.text)[1].strip()
                                    instances_list[code_count]["fullcode"][lines_count]["param"] = param
                                    lines_count += 1
                
                        for j in range(0, len(desc)):
                            full_desc += desc[j].text

                        for j in range(0, len(details_list)):
                            full_detail += details_list[j]

                        findings_list = populate_object(findings_list, cwe_id, name, severity, full_desc, full_solution, full_detail, instances_list)

                match x:
                    case 0:
                        high_findings = findings_list
                    case 1:
                        medium_findings = findings_list
                    case 2:
                        low_findings = findings_list
           
            create_threadfix_file(high_findings, medium_findings, low_findings)
                        
    except FileNotFoundError:
        print("File not found")
        exit(1)
    except IOError: 
        print("Error while opening the file")
        exit(1)

def populate_object(findings_list, cwe_id, name, severity, full_desc, full_solution, full_detail, instances):
    findings_list.append({
        "cweid": cwe_id,
        "name": name,
        "riskdesc": severity.capitalize(),
        "desc": full_desc,
        "instances": instances,
        "solution": full_solution,
        "detail": full_detail
    })

    return findings_list

def create_threadfix_file(high_findings, medium_findings, low_findings): #function to construct .threadfix file based on properties mentioned in https://denimgroup.atlassian.net/wiki/spaces/TDOC/pages/496009270/ThreadFix+File+Format
    date_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_time = date_time[:11] + 'T' + date_time[11:]
    date_time = (date_time[:len(date_time)] + 'Z' + date_time[len(date_time):]).replace(" ", "")
    findings_list = []
    reported_findings = []

    threadfix = {
        "id": 0,
        "created": date_time,
        "updated": date_time,
        "exported": date_time,
        "collectionType": "SAST",
        "source": "ManualFinding",
        "executiveSummary": "Peri source code review using snyk plugin on VS code",
        "findings": []
    }

    count = 0

    for x in range(3):
        match x:
            case 0:
                findings_list = high_findings
            case 1:
                findings_list = medium_findings
            case 2:
                findings_list = low_findings

        if len(findings_list) > 0:
            for y in range(len(findings_list)):
                cwe = findings_list[y]["cweid"][4:len(findings_list[y]["cweid"])]
                reference = f"\nReference: https://cwe.mitre.org/data/definitions/{cwe}.html"
                data_flow_routes = []
                file = ""

                for x in range(len(findings_list[y]["instances"])):
                    if x == 0:
                        file = findings_list[y]["instances"][0]["uri"]
                    for w in range(len(findings_list[y]["instances"][x]["fullcode"])):
                        line_no = findings_list[y]["instances"][x]["fullcode"][w]["lineno"]
                        code = findings_list[y]["instances"][x]["fullcode"][w]["param"]

                        data_flow_element = {
                            "file": findings_list[y]["instances"][x]["uri"],
                            "lineNumber": int(line_no[:line_no.find(":")]),
                            "columnNumber": int(line_no[(line_no.find(":") + 1):]),
                            "text": code,
                            "sequence": 1
                        }

                        data_flow_routes.append(data_flow_element)
                
                finding = {
                    "id": count,
                    "nativeId": str(count),
                    "severity": findings_list[y]["riskdesc"],
                    "nativeSeverity": findings_list[y]["riskdesc"],
                    "summary": findings_list[y]["name"],
                    "description": findings_list[y]["desc"] + reference,
                    "scannerDetail": findings_list[y]["detail"],
                    "scannerRecommendation": findings_list[y]["solution"],
                    "statuses": { "False Positive": False },
                    "staticDetails": {
                        "parameter": "",
                        "file": file,
                        "dataFlow": data_flow_routes
                    },
                    "mappings": [{
                        "mappingType": "CWE",
                        "value": cwe,
                        "primary": True
                    }]
                }

                reported_findings.append(finding)
                count += 1

    threadfix["findings"] = reported_findings
    
    threadfix_path = input("Path to save .threadfix file: ")
    threadfix_file_name = input("Add a file name: ")

    if os.path.exists(threadfix_path):
        try:
            with open(f"{threadfix_path}\\{threadfix_file_name}.threadfix", "w") as f:
                json.dump(threadfix, f, indent=4)
                print("File saved")
        except IOError: 
            print("Error wile saving file")
            exit(1)
    else:
        print("Error with path")
        exit(1)

def create_xml_file(findings_list, xml_path, xml_file_name): #function to construct XML based on OWASP ZAP template
    root = minidom.Document()
    xml = root.createElement("OWASPZAPReport")
    xml.setAttribute("generated", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
    root.appendChild(xml)
    site = root.createElement("site")
    site.setAttribute("name", "peri-sourcecode")
    alerts = root.createElement("alerts")

    for y in range(0, len(findings_list)):
        alert_item = root.createElement("alertitem")
        alert = root.createElement("alert")
        alert.appendChild(root.createTextNode(findings_list[y]["name"]))
        name = root.createElement("name")
        name.appendChild(root.createTextNode(findings_list[y]["name"]))
        risk_desc = root.createElement("riskdesc")
        risk_desc.appendChild(root.createTextNode(findings_list[y]["riskdesc"]))
        desc = root.createElement("desc")
        desc.appendChild(root.createTextNode(findings_list[y]["desc"]))
        cwe_id = root.createElement("cweid")
        cwe_id.appendChild(root.createTextNode(findings_list[y]["cweid"][4:len(findings_list[y]["cweid"])]))
        solution = root.createElement("solution")
        solution.appendChild(root.createTextNode(findings_list[y]["solution"]))
        risk_code = root.createElement("riskcode")
        risk_code.appendChild(root.createTextNode(findings_list[y]["riskcode"]))
        instances = root.createElement("instances")
                
        alert_item.appendChild(alert)
        alert_item.appendChild(name)
        alert_item.appendChild(risk_desc)
        alert_item.appendChild(desc)
        alert_item.appendChild(cwe_id)
        alert_item.appendChild(solution)
        alert_item.appendChild(risk_code)
        
        for finding in findings_list[y]["instances"]:
            instance = root.createElement("instance")
            uri = root.createElement("uri")
            uri.appendChild(root.createTextNode(finding["uri"]))
            param = root.createElement("param")
            param.appendChild(root.createTextNode(finding["param"]))
            
            instance.appendChild(uri)
            instance.appendChild(param)
            instances.appendChild(instance)
            
            alert_item.appendChild(instances)
        
        alerts.appendChild(alert_item)

    site.appendChild(alerts)
    xml.appendChild(site)
    final_results = root.toprettyxml(indent ="\t")

    if os.path.exists(xml_path):
        try:
            with open(f"{xml_path}\\{xml_file_name}.xml", "w") as results:
                results.write(final_results)
                print("File saved")
        except IOError: 
            print("Error wile saving file")
            exit(1)
    else:
        print("Error with path")
        exit(1)

def analyze_json_file(filename, severity): #function to construct XML if json file is selected, will use in the future for CVE
    try:
        print("Analyzing " + severity + " severity file...")
        with open(filename, encoding="utf8") as file:
            vulnerabilities = json.load(file)
            findings = vulnerabilities["runs"][0]["tool"]["driver"]["rules"]
            vulnerabilities_list = vulnerabilities["runs"][0]["results"]
            overall_findings = []
            xml_results = []
            n = len(vulnerabilities_list)

            for i in range(0, len(findings)):
                    item = {
                        "id": findings[i]["id"],
                        "name": findings[i]["shortDescription"]["text"],
                        "solution": findings[i]["help"]["markdown"],
                        "cwe":findings[i]["properties"]["cwe"][0][4:7]
                    }
                    overall_findings.append(item)

            for i in range(n - 1):
                for j in range(0, n - i - 1):
                    if vulnerabilities_list[j]["ruleId"] > vulnerabilities_list[j + 1]["ruleId"]:
                        swapped = True
                        vulnerabilities_list[j], vulnerabilities_list[j + 1] = vulnerabilities_list[j + 1], vulnerabilities_list[j]

                    if not swapped:
                        return

            for i in range(0, len(overall_findings)):
                mapped_vulnerability = [v for v in vulnerabilities_list if v["ruleId"] == overall_findings[i]["id"]]
                reported_finding = {
                        "name": overall_findings[i]["name"],
                        "desc": mapped_vulnerability[0]["message"]["text"],
                        "riskdesc": severity,
                        "cweid": overall_findings[i]["cwe"],
                        "solution": overall_findings[i]["solution"],
                        "instances": []
                    }
                
                for j in range(0, len(mapped_vulnerability)):
                    mapped_finding = mapped_vulnerability[j]["codeFlows"][0]["threadFlows"][0]["locations"]
                    
                    for k in range(0, len(mapped_finding)):
                        instance = {
                            "uri": mapped_finding[k]["location"]["physicalLocation"]["artifactLocation"]["uri"],
                            "param": "" #change parameter
                        }
                        
                        reported_finding["instances"].append(instance)
                        
                    xml_results.append(reported_finding)

            xml_path = input("Enter path to save XML output file: ")
            with open(xml_path + "\\report.xml", 'w') as f:
                xml = dicttoxml.dicttoxml(xml_results)
                print("File saved")
    except FileNotFoundError: 
        print("File not found") 
    except IOError: 
        print("Error while opening the file")

def solution_map(name):
    solution = ""
    match name:
        case "Path Traversal":
            solution = """Validate the user input before processing it. Ideally, compare the user input with a whitelist of permitted values. 
            If that isn't possible, verify that the input contains only permitted content, such as alphanumeric characters only. \n
            After validating the supplied input, append the input to the base directory and use a platform filesystem API to canonicalize the path. 
            Verify that the canonicalized path starts with the expected base directory."""
        case _:
            solution = "ERROR: No mapping was found for this vulnerability, missing parameter."
    return solution

def run():
    args = sys.argv[1:]
    main(args)

if __name__ == "__main__":
    run()