import os
import xml.etree.ElementTree as ET

class WDISUI:
    pass


def parse_startup_info(xml_path):
    try:
        with open(xml_path,'rb') as f:
            root = ET.fromstring(f.read())
    
        res = []

        for child_process in root:
            if child_process.tag == 'Process':         
                aux_dict = ({ x.tag: x.text for x in child_process.getchildren()})
                test = WDISUI()            
                test.process_name = child_process.get('Name')
                test.pid =  child_process.get('PID')
                test.started_trace_in_sec= child_process.get('StartedInTraceSec')
                test.start_time = aux_dict['StartTime']            
                test.command_line = aux_dict['CommandLine']
                test.disk_usage = int(aux_dict['DiskUsage'])
                test.cpu_usage = int(aux_dict['CpuUsage'])
                test.parent_PID = aux_dict['ParentPID']
                test.parent_start_time = aux_dict['ParentStartTime'] 
                test.parent_name = aux_dict['ParentName']
                test.start_time = test.start_time[:10] + ' ' + test.start_time[11:]         
                test.parent_start_time = test.parent_start_time[:10] + ' ' + test.parent_start_time[11:]         
                res.append(test)
        return res
    except Exception as e:
        raise