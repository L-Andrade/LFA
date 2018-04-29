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

from math import ceil
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.report import GeneralReportModuleAdapter
from org.sleuthkit.autopsy.report.ReportProgressPanel import ReportStatus

from javax.swing import JPanel
from javax.swing import JCheckBox
from javax.swing import JLabel
from javax.swing import BoxLayout

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

    def getRelativeFilePathXLS(self):
        return "LFA_" + Case.getCurrentCase().getName() + ".xlsx"

    # The 'baseReportDir' object being passed in is a string with the directory that reports are being stored in.   Report should go into baseReportDir + getRelativeFilePath().
    # The 'progressBar' object is of type ReportProgressPanel.
    #   See: http://sleuthkit.org/autopsy/docs/api-docs/4.4/classorg_1_1sleuthkit_1_1autopsy_1_1report_1_1_report_progress_panel.html
    def generateReport(self, baseReportDir, progressBar):

        # Configure progress bar for 2 tasks
        progressBar.setIndeterminate(False)
        progressBar.start()
        progressBar.updateStatusLabel("Getting files and counting")

        # Query the database for files that meet our criteria
        skCase = Case.getCurrentCase().getSleuthkitCase()
        files = skCase.findAllFilesWhere("name like '%.wer'")

        file_count = 0
        for file in files:
            file_count += 1

        # Dividing by ten because progress bar shouldn't be updated too frequently
        # So we'll update it every 10 artifacts
        # Plus 3 for 3 additional steps
        max_progress = (ceil(file_count / 10) + 3)
        progressBar.setMaximumProgress(int(max_progress))

        # Get what reports the user wants
        generateHTML = self.configPanel.getGenerateHTML()
        generateXLS = self.configPanel.getGenerateXLS()

        # First additional step here
        progressBar.increment()
        progressBar.updateStatusLabel("Creating report(s)")

        # Init reports
        if generateHTML:
            # Get html_file_name
            html_file_name = os.path.join(baseReportDir, self.getRelativeFilePath())
            # Get template path
            template_name = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report_template.html")
            
            # Open template HTML
            # The template has a table and a basic interface to show results
            with open(template_name) as inf:
                txt = inf.read()
                report_html = bs4.BeautifulSoup(txt)

        if generateXLS:
            # Get xls_file_name
            # TODO: Format Excel and add headers
            xls_file_name = os.path.join(baseReportDir, self.getRelativeFilePathXLS())

            # Create a workbook and add a worksheet.
            report_xls_wb = xlsxwriter.Workbook(xls_file_name)
            report_xls_ws = report_xls_wb.add_worksheet()
            xls_row_count = 0
            xls_col_count = 0

        # Second additional step here
        progressBar.increment()
        progressBar.updateStatusLabel("Going through artifacts now...")

        # Get artifact lists
        art_list_reported_progs = skCase.getBlackboardArtifacts("TSK_LFA_REPORTED_PROGRAMS")
        art_list_installed_progs = skCase.getBlackboardArtifacts("TSK_INSTALLED_PROG")

        # Get Attribute types
        att_installed_prog_name = skCase.getAttributeType("TSK_PROG_NAME")
        att_reported_app_name = skCase.getAttributeType("TSK_LFA_APP_NAME")

        art_count = 0

        # Create a table row for each artifact
        for artifact in art_list_reported_progs:
            art_count+=1
            # Create row
            if generateHTML:
                row = report_html.new_tag("tr")

            if generateXLS:
                xls_col_count = 0

            # Get artifact's attributes
            attributes = artifact.getAttributes()
            for attribute in attributes:
                # Create a cell and add attribute value as content
                if generateHTML:
                    cell = report_html.new_tag("td")
                    cell.string = attribute.getValueString()

                    # Append cell to the row
                    row.append(cell)

                if generateXLS:
                    report_xls_ws.write(xls_row_count, xls_col_count, attribute.getValueString())
                    xls_col_count += 1

            # Check if the reported program is installed
            # Create the cell
            if generateHTML:
                is_installed_cell = report_html.new_tag("td")
                # Default value is No
                is_installed_cell.string = "No"

            if generateXLS:
                report_xls_ws.write(xls_row_count, xls_col_count, "No")
            
            # Search through installed programs...
            # Get reported app name
            reported_app_name = artifact.getAttribute(att_reported_app_name).getValueString().lower()
            for art_installed_prog in art_list_installed_progs:
                installed_prog_name = art_installed_prog.getAttribute(att_installed_prog_name).getValueString().lower()
                if (installed_prog_name).find((reported_app_name)) is not -1:
                    # Change is installed to Yes and break cycle
                    if generateHTML:
                        is_installed_cell.string = "Yes"
                    if generateXLS:
                        report_xls_ws.write(xls_row_count, xls_col_count, "Yes")
                    break
            
            if generateHTML:
                # Append row to table
                row.append(is_installed_cell)

                # Select tag with ID reportedinstalls - 0 because report_html.select returns an array
                table = report_html.select("#reportedinstalls")[0]
                table.append(row)
            
            if generateXLS:
                xls_row_count += 1

            # Update progress bar every 10 seconds
            if art_count % 10 == 0:
                progressBar.increment()

        # Add number of artifacts to table info panel
        # Need to turn one of the ints into float so the division works
        percentage = round((float(art_count)/file_count)*100,2) if file_count != 0 else 0
        files_info_str = str(art_count) + " artifacts out of " + str(file_count) + " files ("+ str(percentage) + "%)"

        # Third additional step before saving
        progressBar.increment()
        progressBar.updateStatusLabel("Saving to report...")

        if generateHTML:
            # Select tag '<p>' with ID tableinfo - 0 because report_html.select returns an array
            info = report_html.select("p#tableinfo")[0]
            info.string = files_info_str

            with open(html_file_name, "w") as outf:
                outf.write(str(report_html))

            # Add the report to the Case, so it is shown in the tree
            Case.getCurrentCase().addReport(html_file_name, self.moduleName, "LFA HTML Report")

        if generateXLS:
            report_xls_ws.write(xls_row_count+1, 0, files_info_str)
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