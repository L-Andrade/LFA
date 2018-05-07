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
import bs4
import xlsxwriter
import codecs
import chardet

from math import ceil
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.report import GeneralReportModuleAdapter
from org.sleuthkit.autopsy.report.ReportProgressPanel import ReportStatus

from javax.swing import JPanel
from javax.swing import JCheckBox
from javax.swing import JLabel
from javax.swing import BoxLayout

XLS_REPORTED_HEADER_COUNT = 6
XLS_IPS_HEADER_COUNT = 3

class LogForensicsForAutopsyGeneralReportModule(GeneralReportModuleAdapter):

    moduleName = "LFA Report"

    _logger = None

    def log(self, level, msg):
        if _logger is None:
            _logger = Logger.getLogger(self.moduleName)

        self._logger.logp(level, self.__class__.__name__,
                          inspect.stack()[1][3], msg)

    def getName(self):
        return self.moduleName

    def getDescription(self):
        return "Get information of reported programs vs. installed programs"

    def getRelativeFilePath(self):
        return "LFA_" + Case.getCurrentCase().getName() + ".html"

    def getRelativeFilePathIPs(self):
        return "LFA_IPs" + Case.getCurrentCase().getName() + ".html"

    def getRelativeFilePathXLS(self):
        return "LFA_" + Case.getCurrentCase().getName() + ".xlsx"

    def write_artifact_to_report(self, progressBar, art_count, generateHTML, generateXLS, artifact, xls_row_count, html_file, xls_ws):
        row = None
        # Create row
        if generateHTML:
            row = html_file.new_tag("tr")

        if generateXLS:
            xls_col_count = 0

        # Get artifact's attributes
        attributes = artifact.getAttributes()
        for attribute in attributes:
            # Create a cell and add attribute value as content
            if generateHTML:
                cell = html_file.new_tag("td")
                cell.string = attribute.getValueString()

                # Append cell to the row
                row.append(cell)

            if generateXLS:
                xls_ws.write(xls_row_count, xls_col_count, attribute.getValueString())
                xls_col_count += 1

        # Update progress bar every 10 artifacts
        if art_count % 10 == 0:
            progressBar.increment()

        return row

    # The 'baseReportDir' object being passed in is a string with the directory that reports are being stored in.   Report should go into baseReportDir + getRelativeFilePath().
    # The 'progressBar' object is of type ReportProgressPanel.
    #   See: http://sleuthkit.org/autopsy/docs/api-docs/4.4/classorg_1_1sleuthkit_1_1autopsy_1_1report_1_1_report_progress_panel.html
    def generateReport(self, baseReportDir, progressBar):

        # Configure progress bar for 2 tasks
        progressBar.setIndeterminate(False)
        progressBar.start()
        progressBar.updateStatusLabel("Getting files and counting")

        # Get file counts
        skCase = Case.getCurrentCase().getSleuthkitCase()
        files_wer = skCase.findAllFilesWhere("name like '%.wer'")
        files_wer_count = len(files_wer)
        files_log = skCase.findAllFilesWhere("name like '%.log'")
        files_log_count = len(files_log)

        # Get artifact lists
        art_list_reported_progs = skCase.getBlackboardArtifacts("TSK_LFA_REPORTED_PROGRAMS")
        art_list_installed_progs = skCase.getBlackboardArtifacts("TSK_INSTALLED_PROG")
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

        # First additional step here
        progressBar.increment()
        progressBar.updateStatusLabel("Creating report(s)")

        html_programs = None
        html_ips = None

        # Init reports
        if generateHTML:
            # Get html_file_name
            html_file_name = os.path.join(baseReportDir, self.getRelativeFilePath())
            html_file_name_ips = os.path.join(baseReportDir, self.getRelativeFilePathIPs())
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
            # TODO: Format Excel and add headers
            xls_file_name = os.path.join(baseReportDir, self.getRelativeFilePathXLS())

            # Create a workbook and add a worksheet.
            report_xls_wb = xlsxwriter.Workbook(xls_file_name)
            xls_ws_reported = report_xls_wb.add_worksheet()
            xls_ws_logged_ips = report_xls_wb.add_worksheet()

        # Create counter to operate Excel
        # Start row at 1 because of headers
        xls_row_count = 1


        # Second additional step here
        progressBar.increment()
        progressBar.updateStatusLabel("Going through artifacts now...")

        # Get Attribute types
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

        # Create a table row for each attribute
        for artifact in art_list_reported_progs:
            art_count += 1
            # Function returns an HTML row in case we're doing a HTML report
            # So that we can add more info to that row reference if required
            # Not required for Excel because it can be done with coordinates
            row = self.write_artifact_to_report(progressBar, art_count, generateHTML, generateXLS, artifact, xls_row_count, html_programs, xls_ws_reported)

            # Check if the reported program is installed
            # Create the cell
            default_is_installed = "Recent Activity was not run" if len(art_list_installed_progs) == 0 else "No"
            if generateHTML:
                is_installed_cell = html_programs.new_tag("td")
                # Default value is No
                is_installed_cell.string = default_is_installed

            if generateXLS:
                # Is installed header is the last one
                xls_ws_reported.write(xls_row_count, XLS_REPORTED_HEADER_COUNT-1, default_is_installed)
                xls_row_count += 1
            
            # Search through installed programs...
            # Get reported app name
            reported_app_path = artifact.getAttribute(att_reported_app_path).getValueString()
            # Take drive off path (ex: C:)
            reported_app_path = reported_app_path[3:]
            # Invert slashes
            reported_app_path = reported_app_path.replace('\\', '/').encode('utf-8').split('/')[-1].replace('\r','').replace('\t','').replace('\n','')

            
            data_source = artifact.getDataSource()
            services = Services(skCase)
            file_manager = services.getFileManager()
            files_found = file_manager.findFiles(data_source, reported_app_path)

            #debug = html_programs.select('#debug')[0]
            #debug.string += "\\\\" + reported_app_path + " / " + teste + str(files_found)

            if files_found:
                if generateHTML:
                    is_installed_cell.string = "Yes"
                if generateXLS:
                    xls_ws_reported.write(xls_row_count-1,XLS_REPORTED_HEADER_COUNT-1, "Yes")

            
            if generateHTML:
                # Append row to table
                row.append(is_installed_cell)

                # Select tag with ID reportedinstalls - 0 because report_html.select returns an array
                table = html_programs.select("#reportedinstalls")[0]
                table.append(row)

        # Add number of artifacts to table info panel
        # Need to turn one of the ints into float so the division works
        percentage = round((float(art_count)/files_wer_count)*100,2) if files_wer_count != 0 else 0
        files_info_str = str(art_count) + " artifacts out of " + str(files_wer_count) + " files ("+ str(percentage) + "%)"

        if generateHTML:
            # Select tag '<p>' with ID tableinfo - 0 because report_html.select returns an array
            info = html_programs.select("p#tableinfo")[0]
            info.string = files_info_str

        if generateXLS:
            # Start table at cell 0,0 and finish at row counter-1 (because it was incremented) and 5 (amount of headers - 1)
            xls_ws_reported.add_table(0,0,xls_row_count-1,XLS_REPORTED_HEADER_COUNT-1, 
                                            {'columns':[
                                                {'header': 'Program name'},
                                                {'header': 'Event'},
                                                {'header': 'Time of report'},
                                                {'header': 'Path to program'},
                                                {'header': 'Dump files'},
                                                {'header': 'Is installed'}
                                            ]})
            xls_ws_reported.write(xls_row_count+1, 0, files_info_str)

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

        # Reset counters
        art_count = 0
        xls_row_count = 1

        for art_logged_ip in art_list_logged_ips:
            art_count += 1
            row = self.write_artifact_to_report(progressBar, art_count, generateHTML, generateXLS, art_logged_ip, xls_row_count, html_ips, xls_ws_logged_ips)
            
            if generateXLS:
                xls_row_count += 1
            if generateHTML:
                table = html_ips.select("#loggedipstable")[0]
                table.append(row)

        # Add final info to IP reports
        if generateHTML:
            pass

        if generateXLS:
            # Start table at cell 0,0 and finish at row counter and 5 (amount of headers - 1)
            xls_ws_logged_ips.add_table(0,0,xls_row_count,XLS_IPS_HEADER_COUNT-1, 
                                            {'columns':[
                                                {'header': 'IP Address'},
                                                {'header': 'Occurences'},
                                                {'header': 'Log path'}
                                            ]})
        
        # Third additional step before saving
        progressBar.increment()
        progressBar.updateStatusLabel("Saving to report...")

        if generateHTML:
            # Edit href to link each HTML page
            ip_link = html_programs.select('#loggedipslink')[0]
            ip_link['href'] = self.getRelativeFilePathIPs()

            program_link = html_ips.select('#programslink')[0]
            program_link['href'] = self.getRelativeFilePath()

            with open(html_file_name, "w") as outf:
                outf.write(str(html_programs))

            with open(html_file_name_ips, "w") as outf:
                outf.write(str(html_ips))

            # Add the report to the Case, so it is shown in the tree
            Case.getCurrentCase().addReport(html_file_name, self.moduleName, "LFA HTML Report")

        if generateXLS:
            report_xls_wb.close()
            # Add the report to the Case, so it is shown in the tree
            Case.getCurrentCase().addReport(xls_file_name, self.moduleName, "LFA Excel Report")

        # Call this with ERROR if report was not generated
        progressBar.complete(ReportStatus.COMPLETE)

    def getConfigurationPanel(self):
        self.configPanel = LFA_ConfigPanel()
        return self.configPanel

class LFA_ConfigPanel(JPanel):
    generateXLS = True
    generateHTML = True
    cbGenerateExcel = None
    cbGenerateCSV = None

    def __init__(self):
        self.initComponents()

    def getGenerateHTML(self):
        return self.generateHTML

    def getGenerateXLS(self):
        return self.generateXLS

    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))

        descriptionLabel = JLabel(" LFA - Log Forensics for Autopsy")
        self.add(descriptionLabel)

        self.cbGenerateExcel = JCheckBox("Generate Excel format report", actionPerformed=self.cbGenerateExcelActionPerformed)
        self.cbGenerateExcel.setSelected(True)
        self.add(self.cbGenerateExcel)

        self.cbGenerateHTML = JCheckBox("Generate HTML format report", actionPerformed=self.cbGenerateHTMLActionPerformed)
        self.cbGenerateHTML.setSelected(True)
        self.add(self.cbGenerateHTML)

    def cbGenerateExcelActionPerformed(self, event):
        self.generateXLS = event.getSource().isSelected()

    def cbGenerateHTMLActionPerformed(self, event):
        self.generateHTML = event.getSource().isSelected()