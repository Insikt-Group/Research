
import argparse
import requests
import json
from datetime import date, datetime
import argparse
import requests
from urllib3.exceptions import LocationValueError
import multiprocessing as mp
from multiprocessing import Pool, Queue, Manager
from tqdm import tqdm
from requests.exceptions import ConnectionError
import urllib3
import yara
import re
urllib3.disable_warnings()


def yara_scan(data, file):
    rules = yara.compile(filepaths={'namespace1': file})

    matches = rules.match(data=data)

    if len(matches) > 0:
        return matches
    else:
        return None


def regexSearch(data):
    hits = []

    webshell_regex = [
        {
            "name": "Generic_Execution",
            "description": "Looks for execution associated with web shells",
            "regex": "(?i)(?:\w+\.run\(\"%comspec% /c)"
        },
        {
            "name": "Generic_Webshell_Keywords",
            "description": "Looks for common keywords associated with web shells",
            "regex": "(?i)(?:xp_cmdshell|Database\s+Dump|ShiSanObjstr|Net\s+Sploit|SQLI\+Scan|shell\s?code|envlpass|files?man|c0derz\s?shell|md5\s?cracker|umer\s?rock|asp\s?cmd\s?shell|JspSpy|uZE\s?Shell|AK-74\s?Security\s?Team\s?Web\s?Shell|WinX\s?Shell|PHP C0nsole|cfmshell|cmdshell|Gamma\s?Web\s?Shell|ASPXSpy|IISSpy|Webshell|ASPX?\s?Shell|STNC WebShell|GRP\s?WebShell|National Cracker Crew)"
        },
        {
            "name": "Generic_Windows_Reconnaissance",
            "description": "Looks for commands associated with reconnaissance",
            "regex": "(?i)(?:tasklist|netstat|ipconfig|whoami|net\s+(?:localgroup|user)(?:\s|\w)+/add|net\s+start\s+)"
        },
        {
            "name": "Generic_Windows_Commands",
            "description": "Looks for calls to commonly used windows binaries",
            "regex": "(?i)(?:[wc]script\.(?:shell|network)|(?:powershell|[wc]script)(?:\.exe)?|cmd\.exe\s+/c)"
        },
        {
            "name": "Generic_Defense_Evasion",
            "description": "Looks for registry paths associated with Windows persistence mechanisms",
            "regex": "(?i)(?:strpos\(\$_SERVER\['HTTP_USER_AGENT'\],'Google'\))"
        },
        {
            "name": "PHP_Banned_Function",
            "description": "Banned PHP functions are commonly disabled by hosting providers due to security concerns",
            "regex": "(?i)(?:allow_url_fopen\(|fsockopen\(|getrusage\(|get_current_user\(|set_time_limit\(|getmyuid\(|getmypid\(|dl\(|leak\(|listen\(|chown\(|chgrp\(|realpath\(|passthru\(|curl_init\()"
        },
        {
            "name": "PHP_Reconnaissance",
            "description": "Looks for common PHP functions used for gaining further insight into the environment.",
            "regex": "(?i)(?:@ini_get\(\"disable_functions\"\)|gethostbyname\(|phpversion\(|disk_total_space\(|posix_getpwuid\(|posix_getgrgid\(|phpinfo\()"
        },
        {
            "name": "PHP_Database_Operations",
            "description": "Looks for common PHP functions used for interacting with a database.",
            "regex": "(?i)(?:'mssql_connect\('|ocilogon\(|mysql_list_dbs\(mysql_num_rows\(|mysql_dbname\(|mysql_create_db\(|mysql_drop_db\(|mysql_query\(|mysql_exec\()"

        },
        {
            "name": "PHP_Disk_Operations",
            "description": "Looks for common PHP functions used for interacting with a file system.",
            "regex": "(?i)(?:(?:\s|@)rename\(|(%s|@)chmod\(|(%s|@)fileowner\(|(%s|@)filegroup\(|fopen\(|fwrite\(\))"
        },
        {
            "name": "PHP_Execution",
            "description": "Looks for common PHP functions used for executing code.",
            "regex": "(?i)(?:(?:\s|\()(?:curl_exec\(|exec\(|shell_exec\(|passthru\()|(?:assert|array)\(\$_REQUEST\['?\"?\w+\"?'?\]|\$\{\"?'?_REQUEST'?\"?\})"
        },
        {
            "name": "PHP_Defense_Evasion",
            "description": "Looks for common PHP functions used for hiding or obfuscating code.",
            "regex": "(?i)(?:gzinflate\(base64_decode\(|preg_replace\(|\(md5\(md5\(\$\w+\))"

        },
        {
            "name": "PHP_Network_Operations",
            "description": "Looks for common PHP functions used for network operations such as call backs",
            "regex": "(?i)(?:fsockopen\()"
        },
        {
            "name": "ASP_Execution",
            "description": "ASP functions associated with code execution",
            "regex": "(?i)(?:e[\"+/*-]+v[\"+/*-]+a[\"+/*-]+l[\"+/*-]+\(|system\.diagnostics\.processstartinfo\(\w+\.substring\(|startinfo\.filename=\"?'?cmd\.exe\"?'?|\seval\(request\.item\[\"?'?\w+\"?'?\](?:,\"?'?unsafe\"?'?)?|RunCMD\(|COM\('?\"?WScript\.(?:shell|network)\"?'?|response\.write\()"
        },
        {
            "name": "Database_Command_Execution",
            "description": "ASP functions associated with code execution using database commands",
            "regex": "(?i)\w+\.(?:ExecuteNonQuery|CreateCommand)\("
        },
        {
            "name": "ASP_Disk_Operations",
            "description": "ASP functions associated with disk operations",
            "regex": "(?i)(?:createtextfile\(|server\.createobject\(\"Scripting\.FileSystemObject\"\))"
        },
        {
            "name": "ASP_Suspicious",
            "description": "ASP code blocks that are suspicious",
            "regex": "(?i)(?:deletefile\(server\.mappath\(\"\w+\.\w+\"\)\)|language\s+=\s+vbscript\.encode\s+%>(?:\s*|\r|\n)<%\s+response\.buffer=true:server\.scripttimeout=|(?i)language\s+=\s+vbscript\.encode%><%\n?\r?server\.scripttimeout=|executeglobal\(|server\.createobject\(\w+\(\w{1,5},\w{1,5}\)\))"
        },
        {
            "name": "ASP_Targeted_Object_Creation",
            "description": "ASP object creations commonly leveraged in webshells",
            "regex": "(?i)server\.createobject\(\"(?:msxml2\.xmlhttp|microsoft\.xmlhttp|WSCRIPT\.SHELL|ADODB\.Connection)\"\)"
        },
        {
            "name": "ASP_Suspicious_imports",
            "description": "Looks for imported dependencies that are common with WebShells",
            "regex": "(?i)name(?:space)?=\"(?:system\.(?:serviceprocess|threading|(?:net\.sockets)))\"?\""
        },
        {
            "name": "ASP_Process_Threads",
            "description": "Looks for a new process or thread being leveraged",
            "regex": "(?:new\s+process\(\)|startinfo\.(?:filename|UseShellExecute|Redirect(?:StandardInput|StandardOutput|StandardError)|CreateNoWindow)|WaitForExit())"
        },
        {
            "name": "ASP_Database",
            "description": "Looks for database access, imports and usage",
            "regex": "(?:(?:SqlDataAdapter|SqlConnection|SqlCommand)\(|System\.Data\.SqlClient|System\.Data\.OleDb|OleDbConnection\(\))"
        },
        {
            "name": "CFM_Execution",
            "description": "CFM functions associated with code execution",
            "regex": "(?i)(?:\"?/c\s+\"?'?#?cmd#?'?\"?)"
        }
    ]

    try:
        for we_re in webshell_regex:
            regex = we_re['regex']
            reg = re.compile(regex)
            if reg.findall(data):
                for hit in reg.findall(data):
                    temp = {
                        "name": we_re['name'], "description": we_re['description'], "result": hit}
                    hits.append(temp)
        return hits

    except TypeError:
        print(data)
        return hits


def record(response, url, yara_file):
    events = []

    matches = yara_scan(response, yara_file)
    if matches != None:
        for match in matches:
            hit = {'url': url, 'match_type': 'YARA', 'rule': match.rule, 'strings': "N/A", 'response': str(response),
                   'description': match.meta['description'], 'scan_type': "Webshell Scanner", 'timestamp': datetime.now().replace(microsecond=0).isoformat()}
            events.append(hit)

    hits = regexSearch(response)
    if hits:
        for hit in hits:
            hit = {'url': url, 'rule': hit['name'], 'match_type': 'RegEx', 'strings': hit['result'], 'response': response, 'description': hit['description'],
                   'scan_type': "Webshell Scanner", 'timestamp': datetime.now().replace(microsecond=0).isoformat()}
            events.append(hit)
    return events


def scanURL(arg_dict):
    """
    This is a multiprocessing worker
    """
    url = arg_dict["url"]
    yara_file = arg_dict["yara"]
    error_queue = arg_dict["error_queue"]
    result_queue = arg_dict["result_queue"]
    events = None
    try:
        response = requests.get(url, timeout=(10, 20))
        if response.status_code == 200 or response.status_code == 404:
            # print(url)
            # print(len(response.text))
            if len(response.text) == 0:
                kryptonHeaders = {"cookie": "cmd=aw2t6jKTnxnZVp1HchbANg=="}
                response_post = requests.post(
                    url, headers=kryptonHeaders, timeout=(10, 20))
                if "96eqMita1X+2XnbnbKwKKKpcMgjZliWoXZV7D9OLH/Q=" in response_post.text:
                    events = []
                    hit = {'url': url, 'rule': 'KRYPTON', 'match_type': 'HTTP Response Match', 'strings': "N/A", 'response': response_post.text,
                           'description': "Looks for correct response back from KRYPTON webshell", 'scan_type': "Webshell Scanner", 'timestamp': datetime.now().replace(microsecond=0).isoformat()}
                    events.append(hit)

                SharPyShellHeaders = {"content-type": "multipart/form-data; boundary=4789b83194a64e7cbfda29e6879a75de",
                                      "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0"}
                SharPyShellPayload = bytearray([0x2d, 0x2d, 0x34, 0x37, 0x38, 0x39, 0x62, 0x38, 0x33, 0x31, 0x39, 0x34, 0x61, 0x36, 0x34, 0x65, 0x37, 0x63, 0x62, 0x66, 0x64, 0x61, 0x32, 0x39, 0x65, 0x36, 0x38, 0x37, 0x39, 0x61, 0x37, 0x35, 0x64, 0x65, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x44, 0x69, 0x73, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x2d, 0x64, 0x61, 0x74, 0x61, 0x3b, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x64, 0x61, 0x74, 0x61, 0x22, 0x0a, 0x0a, 0x51, 0x55, 0x5a, 0x44, 0x52, 0x55, 0x4e, 0x4d, 0x53, 0x6c, 0x42, 0x62, 0x41, 0x68, 0x52, 0x6b, 0x47, 0x45, 0x49, 0x51, 0x56, 0x31, 0x6b, 0x4e, 0x46, 0x30, 0x70, 0x52, 0x43, 0x77, 0x56, 0x44, 0x61, 0x6b, 0x38, 0x52, 0x45, 0x56, 0x49, 0x4d, 0x47, 0x58, 0x70, 0x39, 0x43, 0x45, 0x64, 0x41, 0x44, 0x41, 0x73, 0x43, 0x45, 0x32, 0x6f, 0x64, 0x53, 0x6b, 0x5a, 0x52, 0x58, 0x52, 0x35, 0x79, 0x44, 0x41, 0x52, 0x57, 0x43, 0x6c, 0x74, 0x42, 0x46, 0x56, 0x42, 0x55, 0x53, 0x67, 0x4d, 0x58, 0x53, 0x6c, 0x41, 0x4b, 0x55, 0x30, 0x45, 0x31, 0x47, 0x68,
                                               0x59, 0x58, 0x58, 0x46, 0x51, 0x58, 0x59, 0x51, 0x42, 0x4d, 0x51, 0x31, 0x6f, 0x37, 0x52, 0x42, 0x49, 0x55, 0x46, 0x6b, 0x49, 0x5a, 0x47, 0x45, 0x56, 0x43, 0x51, 0x78, 0x6b, 0x57, 0x51, 0x6b, 0x55, 0x58, 0x51, 0x55, 0x64, 0x47, 0x55, 0x46, 0x39, 0x62, 0x55, 0x45, 0x55, 0x47, 0x43, 0x56, 0x4a, 0x4b, 0x46, 0x78, 0x6c, 0x68, 0x58, 0x46, 0x46, 0x43, 0x5a, 0x68, 0x77, 0x32, 0x57, 0x51, 0x46, 0x59, 0x58, 0x6d, 0x73, 0x5a, 0x46, 0x78, 0x6b, 0x59, 0x51, 0x68, 0x6b, 0x5a, 0x52, 0x42, 0x52, 0x42, 0x52, 0x6b, 0x4e, 0x46, 0x51, 0x78, 0x6b, 0x5a, 0x51, 0x68, 0x56, 0x46, 0x46, 0x42, 0x64, 0x42, 0x45, 0x55, 0x51, 0x53, 0x46, 0x42, 0x5a, 0x43, 0x47, 0x52, 0x68, 0x46, 0x51, 0x6b, 0x4d, 0x5a, 0x46, 0x6b, 0x4a, 0x46, 0x50, 0x55, 0x45, 0x58, 0x45, 0x78, 0x49, 0x54, 0x45, 0x68, 0x4e, 0x46, 0x52, 0x55, 0x55, 0x54, 0x47, 0x3d, 0x0a, 0x2d, 0x2d, 0x34, 0x37, 0x38, 0x39, 0x62, 0x38, 0x33, 0x31, 0x39, 0x34, 0x61, 0x36, 0x34, 0x65, 0x37, 0x63, 0x62, 0x66, 0x64, 0x61, 0x32, 0x39, 0x65, 0x36, 0x38, 0x37, 0x39, 0x61, 0x37, 0x35, 0x64, 0x65, 0x2d, 0x2d, 0x0d, 0x0a])
                response_post = requests.post(
                    url, data=SharPyShellPayload, headers=SharPyShellHeaders, timeout=(10, 20))
                if response_post.status_code == 500:
                    events = []
                    hit = {'url': url, 'rule': 'SharPyShell', 'match_type': 'HTTP Response Code', 'strings': "N/A", 'response': response_post.text,
                           'description': "Looks for Internal Server Error when sending malformed POST", 'scan_type': "Webshell Scanner", 'timestamp': datetime.now().replace(microsecond=0).isoformat()}
                    events.append(hit)
            else:
                events = record(response.text, url, yara_file)
        if events:
            result_queue.put(events)

    except (OSError, IOError, ConnectionError, LocationValueError, UnicodeError, UnicodeEncodeError) as e:
        error_queue.put(url)


def runScan(urlList, file):

    manager = Manager()
    result_queue = manager.Queue()
    error_queue = manager.Queue()
    return_values = []

    with Pool(mp.cpu_count()) as pool:
        scanList = [
            dict(url=x, error_queue=error_queue,
                 result_queue=result_queue, yara=file)
            for x in urlList]
        for result in tqdm(pool.imap_unordered(scanURL, scanList), total=len(scanList)):
            return_values.append(result)

        pool.close()
        pool.join()

    results = {"results": []}
    while not result_queue.empty():
        res = result_queue.get()
        results['results'].append(res[0])
    print("url,rule,match_type,description")
    for result in results['results']:
        print("%s,%s,%s,%s" % (result["url"],result["rule"],result["match_type"],result["description"]))

    with open("webshell_scan.json", 'w') as ws_w:
        ws_w.write(json.dumps(results, indent=4))
    errors = []
    while not error_queue.empty():
        errors.append(error_queue.get())
    return len(errors), results


def main():
    parser = argparse.ArgumentParser(
        description='Recorded Future Webshell Scanner. Results are saved to webshell_scan.json in current directory')
    parser.add_argument('-d', '--domains', action='store', dest='domains',
                        help='File containing list of domains / ips to scan.')
    parser.add_argument('-y', '--yara', action='store',
                        dest='yara', help='YARA rule file')
    args = parser.parse_args()

    if args.domains and args.yara:
        urls = []
        paths = []

        with open("webshell_paths.txt", "r") as uri_paths:
            uri_paths = uri_paths.readlines()

        for uri_path in uri_paths:
            paths.append(uri_path.rstrip())

        with open(args.domains, "r") as domainList:
            domains = domainList.readlines()

        for domain in domains:
            uri = "http://%s" % (domain.rstrip())
            for path in paths:
                url = "%s%s" % (uri, path)
                urls.append(url)
            uri = "https://%s" % (domain.rstrip())
            for path in paths:
                url = "%s%s" % (uri, path)
                urls.append(url)
        runScan(urls, args.yara)
    else:
        print("Must supply list of domains and / or YARA rule file")


if __name__ == "__main__":
    main()
