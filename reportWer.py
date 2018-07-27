# Sample module in the public domain. Feel free to use this as a template
# for your modules (and you can remove this header and take complete credit
# and liability)
#
# Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# See http://sleuthkit.org/autopsy/docs/api-docs/4.4/index.html for documentation

import os
import inspect
import bs4
import xlsxwriter
import datetime
from urllib2 import urlopen
import time

from dfxmlwriter import dfxml_writer

from math import ceil
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import Version
from org.sleuthkit.autopsy.report import GeneralReportModuleAdapter
from org.sleuthkit.autopsy.report.ReportProgressPanel import ReportStatus
from org.sleuthkit.datamodel import AbstractFile

from javax.swing import JPanel
from javax.swing import JCheckBox
from javax.swing import JLabel
from javax.swing import BoxLayout

XLS_REPORTED_HEADER_COUNT = 7
XLS_IPS_HEADER_COUNT = 7
XLS_REGEX_HEADER_COUNT = 4
XLS_WSU_HEADER_COUNT = 10
XLS_FILES_HEADER_COUNT = 6
WS_NAME_STATISTICS = 'Statistics'
WS_NAME_STATISTICS_DATA = 'Raw data'
WS_NAME_REPORTED_PROGRAMS = 'Reported programs'
WS_NAME_FILES = 'All files'
WS_NAME_LOGGED_IPS = 'Logged IPs'
WS_NAME_CUSTOM_REGEX = 'Custom RegExs'
WS_NAME_WSU = 'Windows Startup'

class LogForensicsForAutopsyGeneralReportModule(GeneralReportModuleAdapter):

    moduleName = "LFA Report"

    _logger = None

    def log(self, level, msg):
        if self._logger is None:
            self._logger = Logger.getLogger(self.moduleName)
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def getName(self):
        return self.moduleName

    def getDescription(self):
        return "Report of LFA ingest module information enhanced"

    def getRelativeFilePath(self):
        return "LFA_" + Case.getCurrentCase().getName() + ".html"

    def getRelativeFilePathIPsHTML(self):
        return "LFA_IPs" + Case.getCurrentCase().getName() + ".html"

    def getRelativeFilePathRegExHTML(self):
        return "LFA_RegEx" + Case.getCurrentCase().getName() + ".html"

    def getRelativeFilePathWSUHTML(self):
        return "LFA_WSU" + Case.getCurrentCase().getName() + ".html"

    def getRelativeFilePathFilesHTML(self):
        return "LFA_Files" + Case.getCurrentCase().getName() + ".html"

    def getRelativeFilePathDFXML(self):
        return "LFA_" + Case.getCurrentCase().getName() + ".xml"

    def getRelativeFilePathXLS(self):
        return "LFA_" + Case.getCurrentCase().getName() + ".xlsx"

    def write_artifact_to_report(self, skCase, progressBar, art_count, generateHTML, generateXLS, artifact, xls_row_count, html_file, xls_ws):
        row = None
        # Create row
        if generateHTML:
            row = html_file.new_tag("tr")

        if generateXLS:
            xls_col_count = 0

        # Get artifact's attributes
        attributes = artifact.getAttributes()
        for attribute in attributes:
            attribute_value = attribute.getDisplayString()
            # Create a cell and add attribute value as content
            if generateHTML:
                cell = html_file.new_tag("td")
                cell.string = attribute_value

                # Append cell to the row
                row.append(cell)

            if generateXLS:
                xls_ws.write(xls_row_count, xls_col_count, attribute_value)
                xls_col_count += 1

        # Update progress bar every 10 artifacts
        if art_count % 10 == 0:
            progressBar.increment()

        return row

    def write_artifact_to_dfxml_report(self, skCase, progressBar, artifact, dfxml):
        dfxml_src = dfxml.generateSource(artifact.getDataSource().getName())

        source_file = skCase.getAbstractFileById(artifact.getObjectID())
        filename, file_extension = os.path.splitext(source_file.getName())

        fo = dfxml.newFileObject({'filename': filename+file_extension})
        dfxml.addParamsToNode(fo, 'mtime', datetime.datetime.fromtimestamp(source_file.getMtime()).strftime('%Y-%m-%dT%H:%M:%SZ%z'))
        dfxml.addParamsToNode(fo, 'ctime', datetime.datetime.fromtimestamp(source_file.getCtime()).strftime('%Y-%m-%dT%H:%M:%SZ%z'))
        dfxml.addParamsToNode(fo, 'atime', datetime.datetime.fromtimestamp(source_file.getAtime()).strftime('%Y-%m-%dT%H:%M:%SZ%z'))
        dfxml.addParamsToNode(fo, 'crtime', datetime.datetime.fromtimestamp(source_file.getCrtime()).strftime('%Y-%m-%dT%H:%M:%SZ%z'))
        
        md5 = source_file.getMd5Hash() 
        if md5 is not None:
            dfxml.addHashDigestToFO(fo, ['MD5',md5])

    def insert_top20_column_chart(self,name,xls_wb,xls_ws_stats,xls_ws_stats_data,data,data_cat_col,data_val_col,pos_x,pos_y):
        data_len = len(data)
        start_cell_row = data_len-20 if data_len >= 20 else 0
        self.insert_column_chart(name,xls_wb,xls_ws_stats,xls_ws_stats_data,data,start_cell_row,data_cat_col,data_val_col,pos_x,pos_y)

    def insert_column_chart(self,name,xls_wb,xls_ws_stats,xls_ws_stats_data,data,data_row,data_cat_col,data_val_col,pos_x,pos_y):
        list_data = [[], []]
        data_len = len(data)

        for (key,value) in sorted(data.iteritems(), key = lambda (k,v): (v,k)):
            list_data[0].append(key)
            list_data[1].append(value)

        xls_ws_stats_data.write_column(0, data_cat_col, list_data[0])
        xls_ws_stats_data.write_column(0, data_val_col, list_data[1])

        chart = xls_wb.add_chart({'type': 'column'})

        chart.set_x_axis({
            'name': name,
            'name_font': {'size': 14, 'bold': True},
            'num_font':  {'italic': True }
        })

        chart.add_series({
            'categories': [WS_NAME_STATISTICS_DATA, data_row, data_cat_col, data_len, data_cat_col],
            'values':     [WS_NAME_STATISTICS_DATA, data_row, data_val_col, data_len, data_val_col],
            'gap': 150,
            'data_labels': {'value': True}
        })
        number_of_elements = data_len - data_row
        chart_width = int(round(float((480*(number_of_elements+5))/20)))
        chart.set_size({'width': chart_width, 'height': 300})

        xls_ws_stats.insert_chart(pos_x,pos_y, chart)

    def insert_2categories_pie_chart(self,name,xls_wb,xls_ws_stats,xls_ws_stats_data,data_row,data_cat_col,data_val_col,cat1,val1,cat2,val2,pos_x,pos_y):
        data = [[cat1,cat2],[val1,val2]]

        # Write data to Excel in order to add chart with that data
        xls_ws_stats_data.write_column(data_row,data_cat_col, data[0])
        xls_ws_stats_data.write_column(data_row,data_val_col, data[1])


        chart = xls_wb.add_chart({'type': 'pie'})
        chart.set_title({'name':name})

        chart.add_series({
            'categories': [WS_NAME_STATISTICS_DATA, data_row, data_cat_col, data_row+1, data_cat_col],
            'values':     [WS_NAME_STATISTICS_DATA, data_row, data_val_col, data_row+1, data_val_col],
            'data_labels': {'value': True}
        })

        xls_ws_stats.insert_chart(pos_x,pos_y, chart)
    # The 'baseReportDir' object being passed in is a string with the directory that reports are being stored in.   Report should go into baseReportDir + getRelativeFilePath().
    # The 'progressBar' object is of type ReportProgressPanel.
    #   See: http://sleuthkit.org/autopsy/docs/api-docs/4.4/classorg_1_1sleuthkit_1_1autopsy_1_1report_1_1_report_progress_panel.html
    def generateReport(self, baseReportDir, progressBar):
        self.log(Level.INFO, "Starting LFA report module")

        # Count execution time
        start_time = time.time()

        # Configure progress bar for 2 tasks
        progressBar.setIndeterminate(False)
        progressBar.start()
        progressBar.updateStatusLabel("Getting files and artifacts...")

        skCase = Case.getCurrentCase().getSleuthkitCase()
        services = Services(skCase)
        file_manager = services.getFileManager()

        # Get file counts
        files_wer = skCase.findAllFilesWhere("name like '%.wer'")
        files_wer_count = len(files_wer)
        files_log = skCase.findAllFilesWhere("name like '%.log'")
        files_log_count = len(files_log)

        # Get artifact lists
        art_list_reported_progs = skCase.getBlackboardArtifacts("TSK_LFA_REPORTED_PROGRAMS")
        art_list_logged_ips = skCase.getBlackboardArtifacts("TSK_LFA_LOG_FILE_IP")
        art_list_wsu = skCase.getBlackboardArtifacts("TSK_LFA_WIN_SU_INFO")

        # For the next lists of files, we're doing a different approach
        # We want a table with all the type of log files
        # So, we're doing a list of lists with all types of files
        list_art_list_files = [skCase.getBlackboardArtifacts('TSK_LFA_EVT_FILES'), skCase.getBlackboardArtifacts('TSK_LFA_WER_FILES'),
             skCase.getBlackboardArtifacts('TSK_LFA_ETL_FILES'), skCase.getBlackboardArtifacts('TSK_LFA_DMP_FILES'),
             skCase.getBlackboardArtifacts('TSK_LFA_LOG_FILES'), skCase.getBlackboardArtifacts('TSK_LFA_WIN_SU_FILES')]

        # Get artifact list regarding custom RegExs
        # Had to dig in to Autopsy source code for database knowledge...
        art_list_custom_regex = skCase.getMatchingArtifacts("JOIN blackboard_artifact_types AS types ON blackboard_artifacts.artifact_type_id = types.artifact_type_id WHERE types.type_name LIKE 'TSK_LFA_CUSTOM_REGEX_%'")

        len_files = 0
        for art_list in list_art_list_files:
            len_files += len(art_list)
        total_artifact_count = len(art_list_reported_progs) + len(art_list_logged_ips) + len(art_list_custom_regex) + len(art_list_wsu) + len_files


        # Dividing by ten because progress bar shouldn't be updated too frequently
        # So we'll update it every 10 artifacts
        # Plus 2 for 2 additional steps
        max_progress = (ceil(total_artifact_count / 10) + 2)
        progressBar.setMaximumProgress(int(max_progress))

        # Get what reports the user wants
        generateHTML = self.configPanel.getGenerateHTML()
        generateXLS = self.configPanel.getGenerateXLS()
        generateDFXML = self.configPanel.getGenerateDFXML()
        generateOnlyTop20 = self.configPanel.getGenerateOnlyTop20()

        # First additional step here
        progressBar.increment()
        progressBar.updateStatusLabel("Creating report(s)")

        # Init variables to avoid undefined errors
        html_programs = None
        html_ips = None
        html_regex = None
        html_wsu = None
        html_files = None
        xls_ws_reported = None
        xls_ws_logged_ips = None
        xls_ws_regex = None
        xls_ws_wsu = None
        xls_ws_files = None
        dfxml = None

        # Init reports
        if generateHTML:
            # Get html_file_name
            html_file_name = os.path.join(baseReportDir, self.getRelativeFilePath())
            html_file_name_ips = os.path.join(baseReportDir, self.getRelativeFilePathIPsHTML())
            html_file_name_regex = os.path.join(baseReportDir, self.getRelativeFilePathRegExHTML())
            html_file_name_wsu = os.path.join(baseReportDir, self.getRelativeFilePathWSUHTML())
            html_file_name_files = os.path.join(baseReportDir, self.getRelativeFilePathFilesHTML())
            # Get template path
            template_name_programs = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report_template_programs.html")
            template_name_ips = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report_template_ips.html")
            template_name_regex = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report_template_regex.html")
            template_name_wsu = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report_template_wsu.html")
            template_name_files = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report_template_files.html")
            
            # Open template HTML
            # The template has a table and a basic interface to show results
            with open(template_name_programs) as inf:
                txt = inf.read()
                html_programs = bs4.BeautifulSoup(txt)

            with open(template_name_ips) as inf:
                txt = inf.read()
                html_ips = bs4.BeautifulSoup(txt)

            with open(template_name_regex) as inf:
                txt = inf.read()
                html_regex = bs4.BeautifulSoup(txt)

            with open(template_name_wsu) as inf:
                txt = inf.read()
                html_wsu = bs4.BeautifulSoup(txt)

            with open(template_name_files) as inf:
                txt = inf.read()
                html_files = bs4.BeautifulSoup(txt)

        if generateXLS:
            # Get xls_file_name
            xls_file_name = os.path.join(baseReportDir, self.getRelativeFilePathXLS())

            # Create a workbook and add a worksheet.
            report_xls_wb = xlsxwriter.Workbook(xls_file_name)
            xls_ws_reported = report_xls_wb.add_worksheet(WS_NAME_REPORTED_PROGRAMS)
            xls_ws_logged_ips = report_xls_wb.add_worksheet(WS_NAME_LOGGED_IPS)
            xls_ws_regex = report_xls_wb.add_worksheet(WS_NAME_CUSTOM_REGEX)
            xls_ws_wsu = report_xls_wb.add_worksheet(WS_NAME_WSU)
            xls_ws_files = report_xls_wb.add_worksheet(WS_NAME_FILES)

        if generateDFXML:
            dfxml_path = os.path.join(baseReportDir, self.getRelativeFilePathDFXML())
            dfxml = dfxml_writer.DFXMLWriter(self.getDescription(),Version.getName(), Version.getVersion())
        # Create counter to operate Excel
        # Start row at 1 because of headers
        xls_row_count = 1

        # Get Attribute types
        att_ip_counter = skCase.getAttributeType("TSK_LFA_IP_COUNTER")
        att_ip_address = skCase.getAttributeType("TSK_LFA_IP_ADDRESS")
        att_ip_log_path = skCase.getAttributeType("TSK_LFA_CASE_FILE_PATH")
        att_ip_type = skCase.getAttributeType("TSK_LFA_IP_TYPE")
        att_ip_version = skCase.getAttributeType("TSK_LFA_IP_VERSION")
        att_ip_domain = skCase.getAttributeType("TSK_LFA_IP_DOMAIN")
        att_event_name = skCase.getAttributeType("TSK_LFA_EVENT_NAME")
        att_reported_app_path = skCase.getAttributeType("TSK_LFA_APP_PATH")
        att_content_matched = skCase.getAttributeType("TSK_LFA_CUSTOM_MATCH")

        #################################################
        #            _  _   ______  _  _                # 
        #     /\    | || | |  ____|(_)| |               # 
        #    /  \   | || | | |__    _ | |  ___  ___     # 
        #   / /\ \  | || | |  __|  | || | / _ \/ __|    # 
        #  / ____ \ | || | | |     | || ||  __/\__ \    # 
        # /_/    \_\|_||_| |_|     |_||_| \___||___/    #
        #################################################
        
        progressBar.updateStatusLabel("Going through all files...")

        art_count = 0

        for art_list in list_art_list_files:
            if art_list:
                for artifact in art_list:
                    art_count += 1

                    row = self.write_artifact_to_report(skCase, progressBar, art_count, generateHTML, generateXLS, artifact, xls_row_count, html_files, xls_ws_files)
                    
                    # Add file type
                    file_type = artifact.getDisplayName()
                    if generateXLS:
                        xls_ws_files.write(xls_row_count,XLS_FILES_HEADER_COUNT-1, file_type)
                        xls_row_count += 1
                    
                    if generateHTML:
                        file_type_cell = html_files.new_tag("td")
                        file_type_cell.string = file_type
                        # Append row to table
                        row.append(file_type_cell)

                        # Select tag with ID filestable - 0 because report_html.select returns an array
                        table = html_files.select("#filestable")[0]
                        table.append(row)

                    if generateDFXML:
                        self.write_artifact_to_dfxml_report(skCase, progressBar, artifact, dfxml)

        if generateXLS:
            # Start table at cell 0,0 and finish at row counter-1 (because it was incremented) and 5 (amount of headers - 1)
            xls_ws_files.add_table(0,0,xls_row_count-1,XLS_FILES_HEADER_COUNT-1, 
                                            {'columns':[
                                                {'header': 'Log size'},
                                                {'header': 'Create date'},
                                                {'header': 'Last modified'},
                                                {'header': 'Last access'},
                                                {'header': 'File path'},
                                                {'header': 'File type'}
                                            ]})


        #########################################################
        #  _____                            _             _     #
        # |  __ \                          | |           | |    #
        # | |__) | ___  _ __    ___   _ __ | |_  ___   __| |    #
        # |  _  / / _ \| '_ \  / _ \ | '__|| __|/ _ \ / _` |    #
        # | | \ \|  __/| |_) || (_) || |   | |_|  __/| (_| |    #
        # |_|  \_\\___|| .__/  \___/ |_|    \__|\___| \__,_|    #
        #              | |                                      #
        #              |_|                                      #
        #########################################################

        progressBar.updateStatusLabel("Going through Reported program artifacts now, takes some time...")

        # Reset counters
        art_count = 0
        xls_row_count = 1

        if art_list_reported_progs:
            # Statistics variables
            event_dictionary = {}
            programs_detected = 0

            # Create a table row for each attribute
            for artifact in art_list_reported_progs:
                art_count += 1
                # Function returns an HTML row in case we're doing a HTML report
                # So that we can add more info to that row reference if required
                # Not required for Excel because it can be done with coordinates
                row = self.write_artifact_to_report(skCase, progressBar, art_count, generateHTML, generateXLS, artifact, xls_row_count, html_programs, xls_ws_reported)
                
                # Get reported app name
                reported_app_path = artifact.getAttribute(att_reported_app_path).getValueString()
                # Take drive off path (ex: C:\)
                reported_app_path = reported_app_path[3:]
                # Invert slashes and take of space-like characters
                reported_app_path = reported_app_path.replace('\\', '/').encode('utf-8').split('/')[-1]

                # Search for the AppPath, found in the .wer, in the datasource
                data_source = artifact.getDataSource()
                files_found = file_manager.findFiles(data_source, reported_app_path)

                # Check if the reported program was found
                if files_found:
                    is_detected_string = "Yes"
                    programs_detected += 1
                else:
                    is_detected_string = "No"

                # Write to report
                if generateXLS:
                    xls_ws_reported.write(xls_row_count,XLS_REPORTED_HEADER_COUNT-1, is_detected_string)
                    xls_row_count += 1
                
                if generateHTML:
                    is_detected_cell = html_programs.new_tag("td")
                    is_detected_cell.string = is_detected_string
                    # Append row to table
                    row.append(is_detected_cell)

                    # Select tag with ID reportedinstalls - 0 because report_html.select returns an array
                    table = html_programs.select("#reportedinstalls")[0]
                    table.append(row)

                # For statistics
                # Count event types
                event_name = artifact.getAttribute(att_event_name).getValueString()
                # If Event is already in dictionary, add 1
                if event_dictionary.get(event_name):
                    event_dictionary[event_name] += 1
                # If it's not, add it to dictionary and start with 1
                else:
                    event_dictionary[event_name] = 1

            # Add number of artifacts to table info panel
            # Need to turn one of the ints into float so the division works
            percentage = round((float(art_count)/files_wer_count)*100,2) if files_wer_count != 0 else 0
            reported_info_str = str(art_count) + " artifacts out of " + str(files_wer_count) + " files ("+ str(percentage) + "%)"

            if generateHTML:
                # Select tag '<p>' with ID tableinfo - 0 because report_html.select returns an array
                info = html_programs.select("p#tableinfo")[0]
                info.string = reported_info_str

            if generateXLS:
                # Start table at cell 0,0 and finish at row counter-1 (because it was incremented) and 5 (amount of headers - 1)
                xls_ws_reported.add_table(0,0,xls_row_count-1,XLS_REPORTED_HEADER_COUNT-1, 
                                                {'columns':[
                                                    {'header': 'Program name'},
                                                    {'header': 'Event'},
                                                    {'header': 'Time of report'},
                                                    {'header': 'Path to program'},
                                                    {'header': 'Windows version'},
                                                    {'header': 'Dump files'},
                                                    {'header': 'Is detected'}
                                                ]})
                xls_ws_reported.write(xls_row_count+1, 0, reported_info_str)

        #############################################################
        #  _                                     _   _____  _____   #
        # | |                                   | | |_   _||  __ \  #
        # | |      ___    __ _   __ _   ___   __| |   | |  | |__) | #
        # | |     / _ \  / _` | / _` | / _ \ / _` |   | |  |  ___/  #
        # | |____| (_) || (_| || (_| ||  __/| (_| |  _| |_ | |      #
        # |______|\___/  \__, | \__, | \___| \__,_| |_____||_|      #
        #                 __/ |  __/ |                              #
        #                |___/  |___/                               #
        #############################################################
        
        progressBar.updateStatusLabel("Going through IP artifacts now...")

        # Reset counters
        art_count = 0
        xls_row_count = 1
        if art_list_logged_ips:
            # Statistics variables
            ip_dictionary = {}

            # Order specified below in ip_type_arr_str
            array_ip_dicts_by_type = [{},{},{},{}, {}]
            ip_type_arr_str = ['Public', 'Private','Reserved', 'Loopback', 'Link-local']

            # Order specified below in ip_version_arr_str
            array_ip_dicts_by_version = [{}, {}]
            ip_version_arr_str = ['IPv4', 'IPv6']
            
            ip_file_dictionary = {}
            ipv4_occurrences = 0
            ipv6_occurrences = 0

            for art_logged_ip in art_list_logged_ips:
                art_count += 1
                row = self.write_artifact_to_report(skCase, progressBar, art_count, generateHTML, generateXLS, art_logged_ip, xls_row_count, html_ips, xls_ws_logged_ips)
                
                if generateXLS:
                    xls_row_count += 1
                if generateHTML:
                    table = html_ips.select("#loggedipstable")[0]
                    table.append(row)

                # For statistics
                # IPs are separated by file
                # With this, we basically join the occurrences counter
                ip_address = art_logged_ip.getAttribute(att_ip_address).getValueString()
                ip_counter = int(art_logged_ip.getAttribute(att_ip_counter).getValueString())
                ip_log_file = art_logged_ip.getAttribute(att_ip_log_path).getValueString()
                ip_type = art_logged_ip.getAttribute(att_ip_type).getValueString()
                ip_version = art_logged_ip.getAttribute(att_ip_version).getValueString()

                # If IP is already in dictionary, add the counter
                if ip_dictionary.get(ip_address):
                    # Increment it in main dictionary
                    ip_dictionary[ip_address] += ip_counter

                    # Increment it in it's type dictionary
                    array_ip_dicts_by_type[ip_type_arr_str.index(ip_type)][ip_address] += ip_counter
                   

                    # Add it to it's version dictionary
                    if ip_version == ip_version_arr_str[0]:
                        ipv4_occurrences += ip_counter
                        array_ip_dicts_by_version[0][ip_address] += ip_counter
                    elif ip_version == ip_version_arr_str[1]:
                        ipv6_occurrences += ip_counter
                        array_ip_dicts_by_version[1][ip_address] += ip_counter
                # If it's not, add it to dictionary and start with counter
                else:
                    # Add it to main dictionary
                    ip_dictionary[ip_address] = ip_counter

                    # Add it to it's type dictionary
                    array_ip_dicts_by_type[ip_type_arr_str.index(ip_type)][ip_address] = ip_counter
                   
                    # Add it to it's version dictionary
                    if ip_version == ip_version_arr_str[0]:
                        ipv4_occurrences += ip_counter
                        array_ip_dicts_by_version[0][ip_address] = ip_counter
                    elif ip_version == ip_version_arr_str[1]:
                        ipv6_occurrences += ip_counter
                        array_ip_dicts_by_version[1][ip_address] = ip_counter

                # Every time the IP is mentioned (once for every artifact)
                # Increment a counter by 1
                if ip_file_dictionary.get(ip_address):
                    ip_file_dictionary[ip_address] += 1
                else:
                    ip_file_dictionary[ip_address] = 1

            # Add final info to IP reports
            ips_info_str = str(len(art_list_logged_ips)) + " artifacts out of " + str(files_log_count) + " .log files and " + str(len(ip_dictionary)) + " unique IPs."

            if generateHTML:
                # Select tag '<p>' with ID tableipsinfo - 0 because report_html.select returns an array
                info = html_ips.select("p#tableipsinfo")[0]
                info.string = reported_info_str

            if generateXLS:
                # Start table at cell 0,0 and finish at row counter and 5 (amount of headers - 1)
                xls_ws_logged_ips.add_table(0,0,xls_row_count-1,XLS_IPS_HEADER_COUNT-1, 
                                                {'columns':[
                                                    {'header': 'Type'},
                                                    {'header': 'Domain'},
                                                    {'header': 'Version'},
                                                    {'header': 'IP Address'},
                                                    {'header': 'Protocol'},
                                                    {'header': 'Occurrences'},
                                                    {'header': 'Log path'}
                                                ]})

                xls_ws_logged_ips.write(xls_row_count+1, 0, ips_info_str)
        
        #############################################
        #  _____               ______               #
        # |  __ \             |  ____|              #
        # | |__) | ___   __ _ | |__   __  __ ___    #
        # |  _  / / _ \ / _` ||  __|  \ \/ // __|   #
        # | | \ \|  __/| (_| || |____  >  < \__ \   #
        # |_|  \_\\___| \__, ||______|/_/\_\|___/   #
        #                __/ |                      #
        #               |___/                       #
        #############################################

        progressBar.updateStatusLabel("Going through custom RegEx artifacts now...")

        # Reset counters
        art_count = 0
        xls_row_count = 1

        # Statistics variables
        dict_custom_regex = {}

        if art_list_custom_regex:
            # Create a table row for each attribute
            for artifact in art_list_custom_regex:
                art_count += 1
                # Function returns an HTML row in case we're doing a HTML report
                # So that we can add more info to that row reference if required
                # Not required for Excel because it can be done with coordinates
                row = self.write_artifact_to_report(skCase, progressBar, art_count, generateHTML, generateXLS, artifact, xls_row_count, html_regex, xls_ws_regex)
                
                regex_name = artifact.getDisplayName()
                if generateXLS:
                    xls_ws_regex.write(xls_row_count,XLS_REGEX_HEADER_COUNT-1, regex_name)
                    xls_row_count += 1

                if generateHTML:
                    regex_name_cell = html_regex.new_tag("td")
                    regex_name_cell.string = regex_name
                    # Append row to table
                    row.append(regex_name_cell)
                    # Select tag with ID regextable - 0 because report_html.select returns an array
                    table = html_regex.select("#regextable")[0]
                    table.append(row)


                # For statistics
                content = artifact.getAttribute(att_content_matched).getValueString()
                occ_counter = int(artifact.getAttribute(att_ip_counter).getValueString())
                if dict_custom_regex.get(content):
                    # Increment it in main dictionary
                    dict_custom_regex[content] += occ_counter
                # If it's not, add it to dictionary and start with counter
                else:
                    # Add it to main dictionary
                    dict_custom_regex[content] = occ_counter

            # Add headers to XLS
            if generateXLS:
                # Start table at cell 0,0 and finish at row counter and 5 (amount of headers - 1)
                xls_ws_regex.add_table(0,0,xls_row_count-1,XLS_REGEX_HEADER_COUNT-1, 
                                                {'columns':[
                                                    {'header': 'Pattern'},
                                                    {'header': 'Occurrences'},
                                                    {'header': 'Log path'},
                                                    {'header': 'RegEx name'}
                                                ]})


            #############################################################
            # __          __ _____  _                _                  #   
            # \ \        / // ____|| |              | |                 #
            #  \ \  /\  / /| (___  | |_  __ _  _ __ | |_  _   _  _ __   #
            #   \ \/  \/ /  \___ \ | __|/ _` || '__|| __|| | | || '_ \  #
            #    \  /\  /   ____) || |_| (_| || |   | |_ | |_| || |_) | #
            #     \/  \/   |_____/  \__|\__,_||_|    \__| \__,_|| .__/  #
            #                                                   | |     #
            #                                                   |_|     #
            #############################################################
            
            if art_list_wsu:
                progressBar.updateStatusLabel("Going through Windows Startup artifacts now...")
                                      
                # Reset counters
                art_count = 0
                xls_row_count = 1

                # Create a table row for each attribute
                for artifact in art_list_wsu:
                    art_count += 1
                    # Function returns an HTML row in case we're doing a HTML report
                    # So that we can add more info to that row reference if required
                    # Not required for Excel because it can be done with coordinates
                    row = self.write_artifact_to_report(skCase, progressBar, art_count, generateHTML, generateXLS, artifact, xls_row_count, html_wsu, xls_ws_wsu)
                    
                    if generateXLS:
                        xls_row_count += 1

                    if generateHTML:
                        # Select tag with ID regextable - 0 because report_html.select returns an array
                        table = html_wsu.select("#wsutable")[0]
                        table.append(row)

                # Add headers to XLS
                if generateXLS:
                    # Start table at cell 0,0 and finish at row counter and 5 (amount of headers - 1)
                    xls_ws_wsu.add_table(0,0,xls_row_count-1,XLS_WSU_HEADER_COUNT-1, 
                                                    {'columns':[
                                                        {'header': 'Name'},
                                                        {'header': 'PID'},
                                                        {'header': 'Started in trace sec'},
                                                        {'header': 'Start time'},
                                                        {'header': 'Command line'},
                                                        {'header': 'Disk usage'},
                                                        {'header': 'CPU usage'},
                                                        {'header': 'Parent PID'},
                                                        {'header': 'Parent start time'},
                                                        {'header': 'Parent name'}
                                                    ]})

        #########################################################################
        #   _____                                _____  _          _            #
        #  / ____|                      ___     / ____|| |        | |           #
        # | (___    __ _ __   __ ___   ( _ )   | (___  | |_  __ _ | |_  ___     #
        #  \___ \  / _` |\ \ / // _ \  / _ \/\  \___ \ | __|/ _` || __|/ __|    #
        #  ____) || (_| | \ V /|  __/ | (_>  <  ____) || |_| (_| || |_ \__ \    #
        # |_____/  \__,_|  \_/  \___|  \___/\/ |_____/  \__|\__,_| \__||___/    #
        #########################################################################                                                                

        # Third additional step before saving
        progressBar.increment()
        progressBar.updateStatusLabel("Saving reports...")

        if generateHTML:
            # Edit href to link each HTML page
            ip_link = html_programs.select('#loggedipslink')[0]
            ip_link['href'] = self.getRelativeFilePathIPsHTML()

            program_link = html_ips.select('#programslink')[0]
            program_link['href'] = self.getRelativeFilePath()

            regex_link = html_programs.select('#customregexslink')[0]
            regex_link['href'] = self.getRelativeFilePathRegExHTML()            

            with open(html_file_name, "w") as outf:
                outf.write(str(html_programs))

            with open(html_file_name_ips, "w") as outf:
                outf.write(str(html_ips))

            with open(html_file_name_regex, "w") as outf:
                outf.write(str(html_regex))

            with open(html_file_name_wsu, "w") as outf:
                outf.write(str(html_wsu))

            with open(html_file_name_files, "w") as outf:
                outf.write(str(html_files))

            self.log(Level.INFO, "Saving HTML Report to: "+html_file_name)
            # Add the report to the Case, so it is shown in the tree
            Case.getCurrentCase().addReport(html_file_name, self.moduleName, "LFA HTML Report")

        if generateDFXML:
            dfxml.writeToFile(dfxml_path)
            self.log(Level.INFO, "Saving DFXML Report to: "+dfxml_path)

            # Add the report to the Case, so it is shown in the tree
            Case.getCurrentCase().addReport(dfxml_path, self.moduleName, "LFA DFXML Report")

        if generateXLS:
            progressBar.updateStatusLabel("Generating statistics for Excel...")
            
            # Generate statistics charts
            xls_ws_statistics = report_xls_wb.add_worksheet(WS_NAME_STATISTICS)
            xls_ws_statistics_data = report_xls_wb.add_worksheet(WS_NAME_STATISTICS_DATA)
            chart_event_name = report_xls_wb.add_chart({'type': 'bar'})

            chart_event_name.set_x_axis({
                'name': 'Event name occurrences',
                'name_font': {'size': 14, 'bold': True},
                'num_font':  {'size': 8, 'italic': True }
            })

            # An array with two arrays inside
            event_data = [[],[]]

            # Iterate over Event dictionary, sorted by ascending counter
            for (event,counter) in sorted(event_dictionary.iteritems(), key = lambda (k,v): (v,k)):
                event_data[0].append(event)
                event_data[1].append(counter)

            # Iterate over each IP type dict
            # Add its chart to the report
            for i in xrange(len(array_ip_dicts_by_type)):
                ip_type_str = ip_type_arr_str[i]
                chart_name = 'Top 20 '+ ip_type_str +' IP address occurrences'

                self.insert_top20_column_chart(chart_name,report_xls_wb,xls_ws_statistics,xls_ws_statistics_data,array_ip_dicts_by_type[i],8+i*2,9+i*2,0,18+i*10)

            # Same deal with the IP version
            for i in xrange(len(array_ip_dicts_by_version)):
                ip_version_str = ip_version_arr_str[i]
                chart_name = 'Top 20 '+ ip_version_str +' IP address occurrences'
                self.insert_top20_column_chart(chart_name,report_xls_wb,xls_ws_statistics,xls_ws_statistics_data,array_ip_dicts_by_version[i],18+i*2,19+i*2,35,0+i*10)

            event_dict_len = len(event_dictionary)

            xls_ws_statistics_data.write_column(0, 2, event_data[0])
            xls_ws_statistics_data.write_column(0, 3, event_data[1])

            chart_event_name.add_series({
                'categories': [WS_NAME_STATISTICS_DATA, 0, 2, event_dict_len, 2], 
                'values':     [WS_NAME_STATISTICS_DATA, 0, 3, event_dict_len, 3],
                'gap': 150,
                'data_labels': {'value': True}
            })
            xls_ws_statistics.write(0, 0, reported_info_str)
            xls_ws_statistics.write(1, 0, ips_info_str)

            xls_ws_statistics.insert_chart(0,10, chart_event_name)

            programs_not_detected = len(art_list_reported_progs)-programs_detected

            self.insert_2categories_pie_chart('Programs detected in datasource',report_xls_wb,xls_ws_statistics,xls_ws_statistics_data,0,4,5,'Detected',programs_detected,'Not detected',programs_not_detected,18,18)
            self.insert_2categories_pie_chart('IP occurrences by version',report_xls_wb,xls_ws_statistics,xls_ws_statistics_data,2,4,5,'IPv4',ipv4_occurrences,'IPv6',ipv6_occurrences,18,10)
            self.insert_top20_column_chart('Top 20 RegEx matches',report_xls_wb,xls_ws_statistics,xls_ws_statistics_data,dict_custom_regex,26,27,18,26)
            self.insert_top20_column_chart('Top 20 IP addresses',report_xls_wb,xls_ws_statistics,xls_ws_statistics_data,ip_dictionary,0,1,2,0)
            self.insert_top20_column_chart('Top 20 IP address file occurrences',report_xls_wb,xls_ws_statistics,xls_ws_statistics_data,ip_file_dictionary,6,7,18,0)

            if not generateOnlyTop20:
                self.insert_column_chart('IP address occurrences',report_xls_wb,xls_ws_statistics,xls_ws_statistics_data,ip_dictionary,0,22,23,64,0)
                self.insert_column_chart('IP address file occurrences', report_xls_wb,xls_ws_statistics,xls_ws_statistics_data,ip_file_dictionary,0,24,25,79,0)

            report_xls_wb.close()
            self.log(Level.INFO, "Saving Excel Report to: "+xls_file_name)

            # Add the report to the Case, so it is shown in the tree
            Case.getCurrentCase().addReport(xls_file_name, self.moduleName, "LFA Excel Report")

        # Elapsed time
        elapsed_time = time.time() - start_time

        self.log(Level.INFO, "Execution time: "+str(elapsed_time))

        # Call this with ERROR if report was not generated
        progressBar.complete(ReportStatus.COMPLETE)

    def getConfigurationPanel(self):
        self.configPanel = LFA_ConfigPanel()
        return self.configPanel

#########################################################################
#   _____                __  _          _____                     _     #
#  / ____|              / _|(_)        |  __ \                   | |    #
# | |      ___   _ __  | |_  _   __ _  | |__) |__ _  _ __    ___ | |    #
# | |     / _ \ | '_ \ |  _|| | / _` | |  ___// _` || '_ \  / _ \| |    #
# | |____| (_) || | | || |  | || (_| | | |   | (_| || | | ||  __/| |    #
#  \_____|\___/ |_| |_||_|  |_| \__, | |_|    \__,_||_| |_| \___||_|    #
#                                __/ |                                  #
#                               |___/                                   #
#########################################################################

class LFA_ConfigPanel(JPanel):
    generateXLS = True
    generateHTML = True
    generateDFXML = True
    generateOnlyTop20 = False
    cbGenerateExcel = None
    cbGenerateCSV = None
    cbGenerateDFXML = None
    cbGenerateOnlyTop20 = None

    def __init__(self):
        self.initComponents()

    def getGenerateHTML(self):
        return self.generateHTML

    def getGenerateXLS(self):
        return self.generateXLS

    def getGenerateDFXML(self):
        return self.generateDFXML

    def getGenerateOnlyTop20(self):
        return self.generateOnlyTop20

    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))

        descriptionLabel = JLabel(" LFA - Log Forensics for Autopsy")
        self.add(descriptionLabel)

        self.cbGenerateExcel = JCheckBox("Generate Excel format report (sortable and with statistics)", actionPerformed=self.cbGenerateExcelActionPerformed)
        self.cbGenerateExcel.setSelected(True)
        self.add(self.cbGenerateExcel)

        self.cbGenerateHTML = JCheckBox("Generate HTML format report", actionPerformed=self.cbGenerateHTMLActionPerformed)
        self.cbGenerateHTML.setSelected(True)
        self.add(self.cbGenerateHTML)

        self.cbGenerateDFXML = JCheckBox("Generate DFXML format report", actionPerformed=self.cbGenerateDFXMLActionPerformed)
        self.cbGenerateDFXML.setSelected(True)
        self.add(self.cbGenerateDFXML)

        self.cbGenerateOnlyTop20 = JCheckBox("Generate only Top 20 charts (Excel only)", actionPerformed=self.cbGenerateOnlyTop20ActionPerformed)
        self.cbGenerateOnlyTop20.setSelected(False)
        self.add(self.cbGenerateOnlyTop20)

    def cbGenerateExcelActionPerformed(self, event):
        self.generateXLS = event.getSource().isSelected()

    def cbGenerateHTMLActionPerformed(self, event):
        self.generateHTML = event.getSource().isSelected()

    def cbGenerateDFXMLActionPerformed(self, event):
        self.generateDFXML = event.getSource().isSelected()

    def cbGenerateOnlyTop20ActionPerformed(self, event):
        self.generateOnlyTop20 = event.getSource().isSelected()