import requests
import json
from urllib.parse import quote
requests.packages.urllib3.disable_warnings()
import datetime
import time
import threading
import queue
import os

with open('config.json', 'r') as fd:
    cfg = json.load(fd)

cb_api = cfg.get('cb_api')
url = cfg.get('cb_url')
year = cfg.get('year')
month = cfg.get('month')
day = cfg.get('day')

payload = {'X-Auth-Token': cb_api}
intelKeyz = list(cfg.get('queries').keys())
intelz = cfg.get('queries')
orig = datetime.datetime(year, month, day)
delta = datetime.datetime.today() - orig
date_list = [orig + datetime.timedelta(days=i) for i in range(delta.days + 1)]

baseHeaders = ["Hostname", "ProcessStart", "ProcessName", "ProcessPath", "Cmdline", "ProcessMD5",
               "Username", "ParentName", "ParentMD5", "Id", "SegmentId", "CBR_Link", "QueryName",
               "QueryTimestamp"]

attributes = ["netconn", "modload", "regmod", "filemod", "crossproc", "childproc"]

regmod_operations = {
    "1": "Created the registry key",
    "2": "First wrote to the registry key",
    "4": "Deleted the key",
    "8": "Deleted the value"
}

filemod_operations = {
    "1": "Created the file",
    "2": "First wrote to the file",
    "4": "Deleted the file",
    "8": "Last wrote to the file"
}

filemod_types = {
    "0":  "Unknown",
    "1":  "PE",
    "2":  "Elf",
    "3":  "UniversalBin",
    "8":  "EICAR",
    "16": "OfficeLegacy",
    "17": "OfficeOpenXml",
    "48": "Pdf",
    "64": "ArchivePkzip",
    "65": "ArchiveLzh",
    "66": "ArchiveLzw",
    "67": "ArchiveRar",
    "68": "ArchiveTar",
    "69": "Archive7zip"
}

crossproc_subtypes = {
    "": "Unknown",
    "1": "Handle open to process",
    "2": "Handle open to thread in process"
}

class INTEL_TESTER():
    def begin(self):
        while queue.Queue.qsize(q) != 0:
            taskObj = q.get()
            query = taskObj.get("query")
            timestamp = taskObj.get("mehTime")
            title = taskObj.get("title")
            attribute = taskObj.get("attribute")

            print("[+] {} for {}\nQuery: {}".format(title, timestamp, query))
            try:
                start_offset = 0
                dataFileName = "{}_{}".format(title, attribute)
                exists = os.path.isfile(dataFileName)

                with open(dataFileName, "a+") as dataFile:

                    if attribute in attributes:
                        if attribute == "netconn":
                            if exists == False:
                                dataFile.write('|'.join(
                                    map(str,
                                        baseHeaders+
                                        ["Timestamp", "LocalIP", "RemoteIP", "LocalPort", "RemotePort", "Protocol", "Direction", "Domain"])) + "\n")

                        elif attribute == "modload":
                            if exists == False:
                                dataFile.write('|'.join(
                                    map(str, baseHeaders +
                                        ["Timestamp", "ModuleMD5", "ModulePath"])) + "\n")

                        elif attribute == "regmod":
                            if exists == False:
                                dataFile.write('|'.join(
                                    map(str, baseHeaders +
                                        ["Timestamp", "Operation", "KeyPath"])) + "\n")

                        elif attribute == "filemod":
                            if exists == False:
                                dataFile.write('|'.join(
                                    map(str, baseHeaders +
                                        ["Timestamp", "Operation", "Path", "MD5LastWrite", "FileType", "TamperAttempt"])) + "\n")

                        elif attribute == "crossproc":
                            if exists == False:
                                dataFile.write('|'.join(
                                    map(str, baseHeaders +
                                        ["Timestamp","AccessType", "TargetId", "TargetMD5", "TargetPath", "SubType", "RequestedPrivs", "TamperAttempt"])) + "\n")

                        elif attribute == "childproc":
                            if exists == False:
                                dataFile.write('|'.join(
                                    map(str, baseHeaders +
                                        ["Timestamp", "EventType", "ProcessCbId","Path","CmdLine", "Username","Pid", "MD5", "Is_Suppression", "Is_Tamper"])) + "\n")

                    else:
                        if exists == False:
                            dataFile.write('|'.join(
                                map(str,
                                    baseHeaders)) + "\n")

                    while True:
                        queryResults = process_query(500, start_offset, quote(query, safe='&='), timestamp)
                        ttlRecords = len(queryResults.get("results"))

                        for d in queryResults.get("results"):

                            core_fields = '|'.join(
                                    map(str, [
                                    d.get("hostname"),
                                    d.get("start"),
                                    d.get("process_name"),
                                    d.get("path"),
                                    d.get("cmdline"),
                                    d.get("process_md5"),
                                    d.get("username"),
                                    d.get("parent_name"),
                                    d.get("parent_md5"),
                                    d.get("id"),
                                    d.get("segment_id"),
                                    "{}/#/analyze/{}/{}".format(url, d.get("id"), d.get("segment_id")),
                                    title,
                                    timestamp]))

                            if attribute == "summary":
                                dataFile.write(core_fields + "\n")

                            elif attribute in attributes:
                                substack_details = process_details(d.get("id"), d.get("segment_id"))

                                if attribute == "netconn":
                                    getNets = substack_details.get("process").get("netconn_complete")
                                    if getNets:
                                        for n in getNets:
                                            remote_ip = n.get("remote_ip")
                                            timestamp = n.get("timestamp")
                                            local_port = n.get("local_port")
                                            remote_port = n.get("remote_port")
                                            proto = n.get("proto")
                                            local_ip = n.get("local_ip")
                                            direction = n.get("direction")
                                            domain = n.get("domain")

                                            conntype = None
                                            if proto == 6:
                                                conntype = "TCP"
                                            elif proto == 17:
                                                conntype = "TCP"

                                            if direction == "true":
                                                direction = "outbound"
                                            elif direction == "false":
                                                direction = "inbound"

                                            netconns = '|'.join(
                                                map(str, [
                                                    timestamp,
                                                    local_ip,
                                                    remote_ip,
                                                    local_port,
                                                    remote_port,
                                                    conntype,
                                                    direction,
                                                    domain

                                                ]))
                                            dataFile.write(core_fields + "|" + netconns + "\n")

                                elif attribute == "modload":
                                    getModLoads = substack_details.get("process").get("modload_complete")
                                    if getModLoads:
                                        for m in getModLoads:
                                            ml = m.split("|")
                                            timestamp = ml[0]
                                            md5 = ml[1]
                                            path = ml[2]
                                            modloads = '|'.join(
                                                map(str, [
                                                    timestamp,
                                                    md5,
                                                    path
                                                ]))
                                            dataFile.write(core_fields + "|" + modloads + "\n")

                                elif attribute == "regmod":
                                    getRegMods = substack_details.get("process").get("regmod_complete")
                                    if getRegMods:
                                        for r in getRegMods:
                                            rms = r.split("|")
                                            operation = regmod_operations[rms[0]]
                                            timestamp = rms[1]
                                            keypath = rms[2]
                                            regmods = '|'.join(
                                                map(str, [
                                                    timestamp,
                                                    operation,
                                                    keypath
                                                ]))
                                            dataFile.write(core_fields + "|" + regmods + "\n")

                                elif attribute == "filemod":
                                    getFileMods = substack_details.get("process").get("filemod_complete")
                                    if getFileMods:
                                        for f in getFileMods:
                                            fms = f.split("|")
                                            operation = filemod_operations[fms[0]]
                                            timestamp =fms[1]
                                            path = fms[2]
                                            lastMD5 = fms[3]
                                            fileType = filemod_types[fms[4]]
                                            tamper = fms[5]

                                            filemods = '|'.join(
                                                map(str, [
                                                    timestamp,
                                                    operation,
                                                    path,
                                                    lastMD5,
                                                    fileType,
                                                    tamper
                                                ]))
                                            dataFile.write(core_fields + "|" + filemods + "\n")

                                elif attribute == "crossproc":
                                    getCrossProc = substack_details.get("process").get("crossproc_complete")
                                    if getCrossProc:
                                        for cp in getCrossProc:
                                            cps = cp.split("|")
                                            evtType = cps[0]
                                            timestamp = cps[1]
                                            tgtId = cps[2]
                                            tgtMD5 = cps[3]
                                            tgtPath = cps[4]
                                            subType = crossproc_subtypes[cps[5]]
                                            accessPrivs = cps[6]
                                            tamper = cps[7]

                                            crossprocs = '|'.join(
                                                map(str, [
                                                    timestamp,
                                                    evtType,
                                                    tgtId,
                                                    tgtMD5,
                                                    tgtPath,
                                                    subType,
                                                    accessPrivs,
                                                    tamper
                                                ]))
                                            dataFile.write(core_fields + "|" + crossprocs + "\n")

                                elif attribute == "childproc":
                                    getChildProc = substack_details.get("process").get("childproc_complete")
                                    if getChildProc:
                                        for child in getChildProc:
                                            evtType = child.get("type")
                                            timestamp = child.get(evtType)
                                            procCbId = child.get("processId")
                                            path = child.get("path")
                                            commandLine = child.get("commandLine")
                                            userName = child.get("userName")
                                            pid = child.get("pid")
                                            md5 = child.get("md5")
                                            suppress = child.get("is_suppressed")
                                            tamper = child.get("is_tampered")

                                            childprocs = '|'.join(
                                                map(str, [
                                                    timestamp,
                                                    evtType,
                                                    procCbId,
                                                    path,
                                                    commandLine,
                                                    userName,
                                                    pid,
                                                    md5,
                                                    suppress,
                                                    tamper
                                                ]))
                                            dataFile.write(core_fields + "|" + childprocs + "\n")

                        if ttlRecords == 500:
                            start_offset = start_offset + 500
                            continue
                        else:
                            break

            except Exception as e:
                print("----> Exception with {} on {}: Error: {}".format(title, meh_time, e))
                exit()
            q.task_done()

def process_query(rows, start, query, date):
    get_deets = requests.get("{}/api/v1/process?cb.urlver=&rows={}&start={}&sort=&q={}&cb.min_last_update={}T00:00:00Z&cb.max_last_update={}T23:59:59Z".format(url, rows, start, query, date, date), headers=payload, verify=False)
    return get_deets.json()

def process_details(id, segment_id):
        get_full_details = requests.get("{}/api/v4/process/{}/{}/event?cb.legacy_5x_mode=false".format(url, id, segment_id), headers=payload, verify=False)
        all_full_deets = get_full_details.json()
        return all_full_deets

if __name__ == '__main__':
    q = queue.Queue()

    for i in intelKeyz:
        ke = intelz[i]
        for d in date_list:
            meh_time = d.strftime('%Y-%m-%d')

            ## Don't run the query for today because today is not over
            if meh_time == time.strftime("%Y-%m-%d"):
                continue

            taskItem = {}
            taskItem["mehTime"] = meh_time
            taskItem["query"] = ke.get("query")
            taskItem["title"] = i
            taskItem["attribute"] = ke.get("attribute", "summary")
            q.put(taskItem)

    for i in range(1):
        stk = INTEL_TESTER()
        worker = threading.Thread(target=stk.begin, daemon=False)
        worker.start()