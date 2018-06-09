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

XLS_REPORTED_HEADER_COUNT = 6
XLS_IPS_HEADER_COUNT = 5
WS_NAME_STATISTICS = 'Statistics'
WS_NAME_STATISTICS_DATA = 'Raw data'
WS_NAME_REPORTED_PROGRAMS = 'Reported programs'
WS_NAME_LOGGED_IPS = 'Logged IPs'

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

    def getRelativeFilePathDFXML(self):
        return "LFA_" + Case.getCurrentCase().getName() + ".xml"

    def getRelativeFilePathXLS(self):
        return "LFA_" + Case.getCurrentCase().getName() + ".xlsx"

    def write_artifact_to_report(self, skCase, progressBar, art_count, generateHTML, generateXLS, generateDFXML, artifact, xls_row_count, html_file, xls_ws, dfxml):
        row = None
        # Create row
        if generateHTML:
            row = html_file.new_tag("tr")

        if generateXLS:
            xls_col_count = 0

        if generateDFXML:
            dfxml_src = dfxml.generateSource(artifact.getDataSource().getName())

            source_file = skCase.getAbstractFileById(artifact.getObjectID())
            vol = dfxml.generateVolume('512')
            filename, file_extension = os.path.splitext(source_file.getName())

            fo = dfxml.newFileObject({
                'filename': filename+file_extension,
                'filesize': str(source_file.getSize()),
                'mtime': datetime.datetime.fromtimestamp(source_file.getMtime()).strftime('%Y-%m-%dT%H:%M:%SZ%z'),
                'ctime': datetime.datetime.fromtimestamp(source_file.getCtime()).strftime('%Y-%m-%dT%H:%M:%SZ%z'),
                'atime': datetime.datetime.fromtimestamp(source_file.getAtime()).strftime('%Y-%m-%dT%H:%M:%SZ%z'),
                'crtime': datetime.datetime.fromtimestamp(source_file.getCrtime()).strftime('%Y-%m-%dT%H:%M:%SZ%z'),

            }, vol)
            md5 = source_file.getMd5Hash() 
            if md5 is not None:
                dfxml.addHashDigestToFO(fo, ['MD5',md5])

        # Get artifact's attributes
        attributes = artifact.getAttributes()
        for attribute in attributes:
            attribute_value = attribute.getValueString()
            # Create a cell and add attribute value as content
            if generateHTML:
                cell = html_file.new_tag("td")
                cell.string = attribute_value

                # Append cell to the row
                row.append(cell)

            if generateXLS:
                xls_ws.write(xls_row_count, xls_col_count, attribute_value)
                xls_col_count += 1

            if generateDFXML:
                att = {'type': attribute.getAttributeTypeDisplayName()}
                dfxml.addParamsToNode(fo, 'dc:attribute', attribute_value, att)

                

        # Update progress bar every 10 artifacts
        if art_count % 10 == 0:
            progressBar.increment()

        return row

    # The 'baseReportDir' object being passed in is a string with the directory that reports are being stored in.   Report should go into baseReportDir + getRelativeFilePath().
    # The 'progressBar' object is of type ReportProgressPanel.
    #   See: http://sleuthkit.org/autopsy/docs/api-docs/4.4/classorg_1_1sleuthkit_1_1autopsy_1_1report_1_1_report_progress_panel.html
    def generateReport(self, baseReportDir, progressBar):
        self.log(Level.INFO, "Starting LFA report module")

        # Configure progress bar for 2 tasks
        progressBar.setIndeterminate(False)
        progressBar.start()
        progressBar.updateStatusLabel("Getting files and counting")

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

        total_artifact_count = len(art_list_reported_progs) + len(art_list_logged_ips)


        # Dividing by ten because progress bar shouldn't be updated too frequently
        # So we'll update it every 10 artifacts
        # Plus 3 for 3 additional steps
        max_progress = (ceil(total_artifact_count / 10) + 3)
        progressBar.setMaximumProgress(int(max_progress))

        # Get what reports the user wants
        generateHTML = self.configPanel.getGenerateHTML()
        generateXLS = self.configPanel.getGenerateXLS()
        generateDFXML = self.configPanel.getGenerateDFXML()
        generateOnlyTop20 = self.configPanel.getGenerateOnlyTop20()

        # First additional step here
        progressBar.increment()
        progressBar.updateStatusLabel("Creating report(s)")

        html_programs = None
        html_ips = None
        xls_ws_reported = None
        xls_ws_logged_ips = None
        dfxml = None

        # Init reports
        if generateHTML:
            # Get html_file_name
            html_file_name = os.path.join(baseReportDir, self.getRelativeFilePath())
            html_file_name_ips = os.path.join(baseReportDir, self.getRelativeFilePathIPsHTML())
            # Get template path
            template_name_programs = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report_template_programs.html")
            template_name_ips = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report_template_ips.html")
            
            # Open template HTML
            # The template has a table and a basic interface to show results
            with open(template_name_programs) as inf:
                txt = inf.read()
                html_programs = bs4.BeautifulSoup(txt)

            with open(template_name_ips) as inf:
                txt = inf.read()
                html_ips = bs4.BeautifulSoup(txt)

        if generateXLS:
            # Get xls_file_name
            xls_file_name = os.path.join(baseReportDir, self.getRelativeFilePathXLS())

            # Create a workbook and add a worksheet.
            report_xls_wb = xlsxwriter.Workbook(xls_file_name)
            xls_ws_reported = report_xls_wb.add_worksheet(WS_NAME_REPORTED_PROGRAMS)
            xls_ws_logged_ips = report_xls_wb.add_worksheet(WS_NAME_LOGGED_IPS)

        if generateDFXML:
            dfxml_path = os.path.join(baseReportDir, self.getRelativeFilePathDFXML())
            dfxml = dfxml_writer.DFXMLWriter(self.getDescription(),Version.getName(), Version.getVersion())
        # Create counter to operate Excel
        # Start row at 1 because of headers
        xls_row_count = 1


        # Second additional step here
        progressBar.increment()
        progressBar.updateStatusLabel("Going through Reported program artifacts now, takes some time...")

        # Get Attribute types
        att_ip_counter = skCase.getAttributeType("TSK_LFA_IP_COUNTER")
        att_ip_address = skCase.getAttributeType("TSK_LFA_IP_ADDRESS")
        att_ip_log_path = skCase.getAttributeType("TSK_LFA_CASE_FILE_PATH")
        att_ip_type = skCase.getAttributeType("TSK_LFA_IP_TYPE")
        att_ip_version = skCase.getAttributeType("TSK_LFA_IP_VERSION")
        att_event_name = skCase.getAttributeType("TSK_LFA_EVENT_NAME")
        att_reported_app_path = skCase.getAttributeType("TSK_LFA_APP_PATH")

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

        art_count = 0

        # Statistics variables
        event_dictionary = {}
        programs_detected = 0

        # Create a table row for each attribute
        for artifact in art_list_reported_progs:
            art_count += 1
            # Function returns an HTML row in case we're doing a HTML report
            # So that we can add more info to that row reference if required
            # Not required for Excel because it can be done with coordinates
            row = self.write_artifact_to_report(skCase, progressBar, art_count, generateHTML, generateXLS, generateDFXML, artifact, xls_row_count, html_programs, xls_ws_reported, dfxml)
            
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
            row = self.write_artifact_to_report(skCase, progressBar, art_count, generateHTML, generateXLS, generateDFXML, art_logged_ip, xls_row_count, html_ips, xls_ws_logged_ips, dfxml)
            
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
                if ip_type == ip_type_arr_str[0]:
                    array_ip_dicts_by_type[0][ip_address] += ip_counter
                elif ip_type == ip_type_arr_str[1]:
                    array_ip_dicts_by_type[1][ip_address] += ip_counter
                elif ip_type == ip_type_arr_str[2]:
                    array_ip_dicts_by_type[2][ip_address] += ip_counter
                elif ip_type == ip_type_arr_str[3]:
                    array_ip_dicts_by_type[3][ip_address] += ip_counter
                elif ip_type == ip_type_arr_str[4]:
                    array_ip_dicts_by_type[4][ip_address] += ip_counter

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
                if ip_type == ip_type_arr_str[0]:
                    array_ip_dicts_by_type[0][ip_address] = ip_counter
                elif ip_type == ip_type_arr_str[1]:
                    array_ip_dicts_by_type[1][ip_address] = ip_counter
                elif ip_type == ip_type_arr_str[2]:
                    array_ip_dicts_by_type[2][ip_address] = ip_counter
                elif ip_type == ip_type_arr_str[3]:
                    array_ip_dicts_by_type[3][ip_address] = ip_counter
                elif ip_type == ip_type_arr_str[4]:
                    array_ip_dicts_by_type[4][ip_address] = ip_counter

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
            # Select tag '<p>' with ID tableinfo - 0 because report_html.select returns an array
            info = html_ips.select("p#tableinfo")[0]
            info.string = reported_info_str

        if generateXLS:
            # Start table at cell 0,0 and finish at row counter and 5 (amount of headers - 1)
            xls_ws_logged_ips.add_table(0,0,xls_row_count-1,XLS_IPS_HEADER_COUNT-1, 
                                            {'columns':[
                                                {'header': 'Type'},
                                                {'header': 'Version'},
                                                {'header': 'IP Address'},
                                                {'header': 'Occurrences'},
                                                {'header': 'Log path'}
                                            ]})

            xls_ws_logged_ips.write(xls_row_count+1, 0, ips_info_str)
        
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

            with open(html_file_name, "w") as outf:
                outf.write(str(html_programs))

            with open(html_file_name_ips, "w") as outf:
                outf.write(str(html_ips))

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
            chart_ips_top20 = report_xls_wb.add_chart({'type': 'column'})
            chart_event_name = report_xls_wb.add_chart({'type': 'bar'})
            chart_is_detected = report_xls_wb.add_chart({'type': 'pie'})
            chart_ip_version_occurrences = report_xls_wb.add_chart({'type': 'pie'})
            chart_ip_file_occur_top20 = report_xls_wb.add_chart({'type': 'column'})

            if not generateOnlyTop20:
                chart_ips = report_xls_wb.add_chart({'type': 'column'})
                chart_ip_file_occur = report_xls_wb.add_chart({'type': 'column'})

            # Change titles
            chart_ips_top20.set_x_axis({
                'name': 'Top 20 IP address occurrences',
                'name_font': {'size': 14, 'bold': True},
                'num_font':  {'italic': True }
            })


            chart_event_name.set_x_axis({
                'name': 'Event name occurrences',
                'name_font': {'size': 14, 'bold': True},
                'num_font':  {'size': 8, 'italic': True }
            })

            chart_is_detected.set_title({'name': 'Programs detected in datasource'})
            chart_ip_version_occurrences.set_title({'name': 'IP occurrences by version'})

            chart_ip_file_occur_top20.set_x_axis({
                'name': 'Top 20 IP individual file occurrences',
                'name_font': {'size': 14, 'bold': True},
                'num_font':  {'italic': True }
            })

            if not generateOnlyTop20:
                chart_ips.set_x_axis({
                    'name': 'Rest of IP address occurrences',
                    'name_font': {'size': 14, 'bold': True},
                    'num_font':  {'size': 8, 'italic': True }
                })
                chart_ip_file_occur.set_x_axis({
                    'name': 'IP individual file occurrences (appears in how many files)',
                    'name_font': {'size': 14, 'bold': True},
                    'num_font':  {'size': 8, 'italic': True }
                })

            # Row counter
            xls_row_count = 0
            # An array with two arrays inside
            # First array will contain IPs (Categories)
            # Second will contain the IP's counter (Values)
            ip_data = [[], []]
            event_data = [[], []]
            ip_file_data = [[], []]
            is_detected_data = [['Detected', 'Not detected'], [programs_detected, len(art_list_reported_progs)-programs_detected]]
            ip_version_occurs_data = [['IPv4', 'IPv6'], [ipv4_occurrences, ipv6_occurrences]]
            # Iterate over IP dictionary, sorted by ascending counter
            for (ip,counter) in sorted(ip_dictionary.iteritems(), key = lambda (k,v): (v,k)):
                ip_data[0].append(ip)
                ip_data[1].append(counter)

            # Iterate over IP dictionary, sorted by ascending counter
            for (ip,ip_file_counter) in sorted(ip_file_dictionary.iteritems(), key = lambda (k,v): (v,k)):
                ip_file_data[0].append(ip)
                ip_file_data[1].append(ip_file_counter)

            # Iterate over Event dictionary, sorted by ascending counter
            for (event,counter) in sorted(event_dictionary.iteritems(), key = lambda (k,v): (v,k)):
                event_data[0].append(event)
                event_data[1].append(counter)

            # Iterate over each IP type dict
            # Add its chart to the report
            for i in xrange(len(array_ip_dicts_by_type)):
                ip_type_str = ip_type_arr_str[i]
                ip_by_type_data = [[], []]
                dict_len = len(array_ip_dicts_by_type[i])
                for (ip,ip_by_type_counter) in sorted(array_ip_dicts_by_type[i].iteritems(), key = lambda (k,v): (v,k)):
                    ip_by_type_data[0].append(ip)
                    ip_by_type_data[1].append(ip_by_type_counter)

                xls_ws_statistics_data.write_column(0, 8+i*2, ip_by_type_data[0])
                xls_ws_statistics_data.write_column(0, 9+i*2, ip_by_type_data[1])

                chart_ips_by_type_top20 = report_xls_wb.add_chart({'type': 'column'})

                chart_ips_by_type_top20.set_x_axis({
                    'name': 'Top 20 '+ ip_type_str +' IP address occurrences',
                    'name_font': {'size': 14, 'bold': True},
                    'num_font':  {'italic': True }
                })
                start_cell_row = dict_len-20 if dict_len >= 20 else 0
                chart_ips_by_type_top20.add_series({
                    'categories': [WS_NAME_STATISTICS_DATA, start_cell_row, 8+i*2, dict_len, 8+i*2],
                    'values':     [WS_NAME_STATISTICS_DATA, start_cell_row, 9+i*2, dict_len, 9+i*2],
                    'gap': 150,
                    'data_labels': {'value': True}
                })

                xls_ws_statistics.insert_chart(0,26+i*10, chart_ips_by_type_top20)

            # Same deal with the IP version
            for i in xrange(len(array_ip_dicts_by_version)):
                ip_version_str = ip_version_arr_str[i]
                ip_by_version_data = [[], []]
                dict_len = len(array_ip_dicts_by_version[i])
                for (ip,ip_by_version_counter) in sorted(array_ip_dicts_by_version[i].iteritems(), key = lambda (k,v): (v,k)):
                    ip_by_version_data[0].append(ip)
                    ip_by_version_data[1].append(ip_by_version_counter)

                xls_ws_statistics_data.write_column(0, 18+i*2, ip_by_version_data[0])
                xls_ws_statistics_data.write_column(0, 19+i*2, ip_by_version_data[1])

                chart_ips_by_version_top20 = report_xls_wb.add_chart({'type': 'column'})

                # Double the width, as occurrences can be large numbers
                chart_ips_by_version_top20.set_size({'width': 480*2})

                chart_ips_by_version_top20.set_x_axis({
                    'name': 'Top 20 '+ ip_version_str +' IP address occurrences',
                    'name_font': {'size': 14, 'bold': True},
                    'num_font':  {'italic': True }
                })

                start_cell_row = dict_len-20 if dict_len >= 20 else 0
                chart_ips_by_version_top20.add_series({
                    'categories': [WS_NAME_STATISTICS_DATA, start_cell_row, 18+i*2, dict_len, 18+i*2],
                    'values':     [WS_NAME_STATISTICS_DATA, start_cell_row, 19+i*2, dict_len, 19+i*2],
                    'gap': 150,
                    'data_labels': {'value': True}
                })

                # Around I50
                xls_ws_statistics.insert_chart(49,8+i*20, chart_ips_by_version_top20)

            ip_dict_len = len(ip_dictionary)
            event_dict_len = len(event_dictionary)
            ip_file_dict_len = len(ip_file_dictionary)

            # Write values in two seperate columns
            xls_ws_statistics_data.write_column(0, 0, ip_data[0])
            xls_ws_statistics_data.write_column(0, 1, ip_data[1])

            xls_ws_statistics_data.write_column(0, 2, event_data[0])
            xls_ws_statistics_data.write_column(0, 3, event_data[1])

            xls_ws_statistics_data.write_column(0, 4, is_detected_data[0])
            xls_ws_statistics_data.write_column(0, 5, is_detected_data[1])

            xls_ws_statistics_data.write_column(2, 4, ip_version_occurs_data[0])
            xls_ws_statistics_data.write_column(2, 5, ip_version_occurs_data[1])

            xls_ws_statistics_data.write_column(0, 6, ip_file_data[0])
            xls_ws_statistics_data.write_column(0, 7, ip_file_data[1])

            # Create series

            # All data except top 20
            # Default chart width by height is 480 x 288
            # 480 is enough for 20 records
            # So, we're going to calculate how much width is necessary
            # For the total amount of IPs (except top 20) we have
            if not generateOnlyTop20:
                chart_ips_width = int(round(float((480*(ip_dict_len-20))/20)))
                chart_ips.add_series({
                    'categories': [WS_NAME_STATISTICS_DATA, 0, 0, ip_dict_len-20, 0],
                    'values':     [WS_NAME_STATISTICS_DATA, 0, 1, ip_dict_len-20, 1],
                    'gap': 100,
                    'data_labels': {'value': True}
                })

                # Also doubling height
                chart_ips.set_size({'width': chart_ips_width, 'height': 576})

                # IP mentioned in 'x' files
                chart_ip_file_width = int(round(float((480*(ip_file_dict_len))/20)))
                chart_ip_file_occur.set_size({'width': chart_ip_file_width})
                chart_ip_file_occur.add_series({
                    'categories': [WS_NAME_STATISTICS_DATA, 0, 6, ip_file_dict_len-20, 6],
                    'values':     [WS_NAME_STATISTICS_DATA, 0, 7, ip_file_dict_len-20, 7],
                    'gap': 150,
                    'data_labels': {'value': True}
                })

            # Only top 20
            chart_ips_top20.add_series({
                'categories': [WS_NAME_STATISTICS_DATA, ip_dict_len-20, 0, ip_dict_len, 0], #'=Sheet4!$A$' + (ip_dict_len-20) + ':$A$'+ip_dict_len,
                'values':     [WS_NAME_STATISTICS_DATA, ip_dict_len-20, 1, ip_dict_len, 1], #'=Sheet4!$B$' + (ip_dict_len-20) + ':$B$'+ip_dict_len,
                'gap': 150,
                'data_labels': {'value': True}
            })

            # Doubling width so data labels are readable
            # And since the other IP chart is so big, it should be fine
            chart_ips_top20.set_size({'width': 960})

            chart_event_name.add_series({
                'categories': [WS_NAME_STATISTICS_DATA, 0, 2, event_dict_len, 2], 
                'values':     [WS_NAME_STATISTICS_DATA, 0, 3, event_dict_len, 3],
                'gap': 150,
                'data_labels': {'value': True}
            })

            chart_is_detected.add_series({
                # 'name': '',
                'categories': [WS_NAME_STATISTICS_DATA, 0, 4, 1, 4],
                'values':     [WS_NAME_STATISTICS_DATA, 0, 5, 1, 5],
                'data_labels': {'value': True}
            })

            chart_ip_version_occurrences.add_series({
                'categories': [WS_NAME_STATISTICS_DATA, 2, 4, 3, 4],
                'values':     [WS_NAME_STATISTICS_DATA, 2, 5, 3, 5],
                'data_labels': {'value': True}
            })

            # IP mentioned in 'x' files top20
            chart_ip_file_occur_top20.set_size({'width': 960})
            chart_ip_file_occur_top20.add_series({
                'categories': [WS_NAME_STATISTICS_DATA, ip_file_dict_len-20, 6, ip_file_dict_len, 6],
                'values':     [WS_NAME_STATISTICS_DATA, ip_file_dict_len-20, 7, ip_file_dict_len, 7],
                'gap': 150,
                'data_labels': {'value': True}
            })

            xls_ws_statistics.write(0, 0, reported_info_str)

            xls_ws_statistics.write(1, 0, ips_info_str)

            xls_ws_statistics.insert_chart('A3', chart_ips_top20)

            xls_ws_statistics.insert_chart('Q3', chart_event_name)

            xls_ws_statistics.insert_chart('A50', chart_is_detected)

            xls_ws_statistics.insert_chart('Q65', chart_ip_version_occurrences)

            xls_ws_statistics.insert_chart('A65', chart_ip_file_occur_top20)

            if not generateOnlyTop20:
                xls_ws_statistics.insert_chart('A20', chart_ips)

                xls_ws_statistics.insert_chart('A80', chart_ip_file_occur)

            report_xls_wb.close()
            self.log(Level.INFO, "Saving Excel Report to: "+xls_file_name)

            # Add the report to the Case, so it is shown in the tree
            Case.getCurrentCase().addReport(xls_file_name, self.moduleName, "LFA Excel Report")

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