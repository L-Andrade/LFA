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


# Ingest module for Autopsy with GUI
#
# Difference between other modules in this folder is that it has a GUI
# for user options.  This is not needed for very basic modules. If you
# don't need a configuration UI, start with the other sample module.
#
# Search for TODO for the things that you need to change
# See http://sleuthkit.org/autopsy/docs/api-docs/4.4/index.html for documentation


import jarray
import inspect
import os
from java.lang import System
from java.util.logging import Level
from javax.swing import JCheckBox
from javax.swing import BoxLayout
from javax.swing import JLabel
from java.lang import Class
from java.lang import System
from java.io import File
from java.sql import DriverManager, SQLException

from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import IngestModuleGlobalSettingsPanel
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.coreutils import Logger
from java.lang import IllegalArgumentException

# TODO: Rename this to something more specific
class LogForensicsForAutopsyFileIngestModuleWithUIFactory(IngestModuleFactoryAdapter):
    def __init__(self):
        self.settings = None

    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Log Forensics for Autopsy"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "This module searchs for certain log files."

    def getModuleVersionNumber(self):
        return "1.0"

    # TODO: Update class name to one that you create below
    def getDefaultIngestJobSettings(self):
        return LogForensicsForAutopsyFileIngestModuleWithUISettings()

    # TODO: Keep enabled only if you need ingest job-specific settings UI
    def hasIngestJobSettingsPanel(self):
        return True

    # TODO: Update class names to ones that you create below
    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, LogForensicsForAutopsyFileIngestModuleWithUISettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof LogForensicsForAutopsyFileIngestModuleWithUI")
        self.settings = settings
        return LogForensicsForAutopsyFileIngestModuleWithUISettingsPanel(self.settings)


    def isFileIngestModuleFactory(self):
        return True


    # TODO: Update class name to one that you create below
    def createFileIngestModule(self, ingestOptions):
        return LogForensicsForAutopsyFileIngestModuleWithUI(self.settings)


# File-level ingest module.  One gets created per thread.
# TODO: Rename this to something more specific. Could just remove "Factory" from above name.
# Looks at the attributes of the passed in file.
class LogForensicsForAutopsyFileIngestModuleWithUI(FileIngestModule):

    _logger = Logger.getLogger(LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    # Autopsy will pass in the settings from the UI panel
    def __init__(self, settings):
        self.local_settings = settings


    # Where any setup and configuration is done
    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        # For statistics purposes
        self.filesFound = 0

        # Get Sleuthkit case
        skCase = Case.getCurrentCase().getSleuthkitCase()

        # Create new artifact type
        try:
            self.log(Level.INFO, "Begin Create New Artifacts")
            self.art_log_file = skCase.addBlackboardArtifactType( "TSK_LFA_LOG_FILES", "Log files")
        except:     
            self.log(Level.INFO, "Artifacts Creation Error, Log file ==> ")
            self.art_log_file = skCase.getArtifactType("TSK_LFA_LOG_FILES")

        # Create the attribute type Windows log, if it already exists, catch error
        # If Yes, Log is in a Windows directory. If No, Log is in a normal directory
        try:
            self.bb_att_windows_path = skCase.addArtifactAttributeType('TSK_LFA_WINDOWS_PATH',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Windows log")
        except:
            self.log(Level.INFO, "Attributes Creation Error, Prefetch Windows Logs. ==> ")

        # Create the attribute type, if it already exists, catch error
        # Log size shows the size of the file in bytes
        try:
            self.bb_att_log_size = skCase.addArtifactAttributeType('TSK_LFA_LOG_SIZE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Log size (B)")
        except:
            self.log(Level.INFO, "Attributes Creation Error, Prefetch Log size. ==> ")

        self.log(Level.INFO, "Get Artifacts after they were created.")

        # Get Attributes after they are created
        self.bb_att_windows_path = skCase.getAttributeType("TSK_LFA_WINDOWS_PATH")
        self.bb_att_log_size = skCase.getAttributeType("TSK_LFA_LOG_SIZE")


        # if self.local_settings.getCheckWER():
        #     self.log(Level.INFO, "Looking for WER")
        # else:
        #     self.log(Level.INFO, "Not looking for WER")

        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")

    # Where the analysis is done.  Each file will be passed into here.
    # TODO: Add your analysis code in here.
    def process(self, file):

        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
            (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
            (file.isFile() == False)):
            return IngestModule.ProcessResult.OK

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        # For an example, we will flag files with .txt in the name and make a blackboard artifact.
        # Actually getting .dmp files...
        if (file.getName().lower().endswith(".etl") and self.local_settings.getCheckETL()) or (file.getName().lower().endswith(".wer") and self.local_settings.getCheckWER()) or (file.getName().lower().endswith(".dmp") and self.local_settings.getCheckDmp()) or (file.getName().lower().endswith(".evtx") and self.local_settings.getCheckEVTx()) or (file.getName().lower().endswith(".log") and self.local_settings.getCheckLog()):
                           
            self.filesFound+=1

            
            # Make an artifact on the blackboard and create attributes array
            
            art = file.newArtifact(self.art_log_file.getTypeID())
            str_windows = "N/A"
            if "windows" in file.getParentPath().lower():
                str_windows = "Yes"
            else:
                str_windows = "No"

            att = BlackboardAttribute(self.bb_att_windows_path, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str_windows)
            art.addAttribute(att)

            # Register log file size
            
            inputStream = ReadContentInputStream(file)
            buffer = jarray.zeros(1024, "b")
            totLen = 0
            len = inputStream.read(buffer)
            while (len != -1):
                    totLen = totLen + len
                    len = inputStream.read(buffer)

            att = BlackboardAttribute(self.bb_att_log_size, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(totLen))
            art.addAttribute(att)


            try:
                # index the artifact for keyword search
                blackboard.indexArtifact(art)
            except Blackboard.BlackboardException as e:
                self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

            # Fire an event to notify the UI and others that there is a new artifact
            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName,
                    self.art_log_file, None))


        return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here.
    def shutDown(self):
        # Inform user of number of files found
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName,
                str(self.filesFound) + " total files found.")

        ingestServices = IngestServices.getInstance().postMessage(message)

# Stores the settings that can be changed for each ingest job
# All fields in here must be serializable.  It will be written to disk.
# TODO: Rename this class
class LogForensicsForAutopsyFileIngestModuleWithUISettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        pass

    def getVersionNumber(self):
        return serialVersionUID

    def getCheckWER(self):
        return self.checkWER

    def setCheckWER(self, checkWER):
        self.checkWER = checkWER

    def getCheckETL(self):
        return self.checkETL

    def setCheckETL(self, checkETL):
        self.checkETL = checkETL

    def getCheckLog(self):
        return self.checkLog

    def setCheckLog(self, checkLog):
        self.checkLog = checkLog

    def getCheckDmp(self):
        return self.checkDmp

    def setCheckDmp(self, checkDmp):
        self.checkDmp = checkDmp

    def getCheckEVTx(self):
        return self.checkEVTx

    def setCheckEVTx(self, checkEVTx):
        self.checkEVTx = checkEVTx

# UI that is shown to user for each ingest job so they can configure the job.
# TODO: Rename this
class LogForensicsForAutopsyFileIngestModuleWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
    # Note, we can't use a self.settings instance variable.
    # Rather, self.local_settings is used.
    # https://wiki.python.org/jython/UserGuide#javabean-properties
    # Jython Introspector generates a property - 'settings' on the basis
    # of getSettings() defined in this class. Since only getter function
    # is present, it creates a read-only 'settings' property. This auto-
    # generated read-only property overshadows the instance-variable -
    # 'settings'

    # We get passed in a previous version of the settings so that we can
    # prepopulate the UI
    # TODO: Update this for your UI
    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()
        self.customizeComponents()

    def checkBoxEventWER(self, event):
        self.local_settings.setCheckWER(self.checkboxWER.isSelected())
        self.saveFlagSetting("checkWER", self.checkboxWER.isSelected())

    def checkBoxEventETL(self, event):
        self.local_settings.setCheckETL(self.checkboxETL.isSelected())
        self.saveFlagSetting("checkETL", self.checkboxETL.isSelected())

    def checkBoxEventLog(self, event):
        self.local_settings.setCheckLog(self.checkboxLog.isSelected())
        self.saveFlagSetting("checkLog", self.checkboxLog.isSelected())

    def checkBoxEventDmp(self, event):
        self.local_settings.setCheckDmp(self.checkboxDmp.isSelected())
        self.saveFlagSetting("checkDmp", self.checkboxDmp.isSelected())

    def checkBoxEventEVTx(self, event):
        self.local_settings.setCheckEVTx(self.checkboxEVTx.isSelected())
        self.saveFlagSetting("checkEVTx", self.checkboxEVTx.isSelected())

    # TODO: Update this for your UI
    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))

        self.labelCheckText = JLabel("Check for type files: ")
        self.labelCheckText.setEnabled(True)
        self.errorMessageLabel = JLabel(" ")
        self.errorMessageLabel.setEnabled(True)

        self.checkboxWER = JCheckBox("WER", actionPerformed=self.checkBoxEventWER)
        self.checkboxETL = JCheckBox("ETL", actionPerformed=self.checkBoxEventETL)
        self.checkboxLog = JCheckBox("Log", actionPerformed=self.checkBoxEventLog)
        self.checkboxEVTx = JCheckBox("EVTx", actionPerformed=self.checkBoxEventEVTx)
        self.checkboxDmp = JCheckBox("Dmp", actionPerformed=self.checkBoxEventDmp)

        self.add(self.labelCheckText)
        self.add(self.checkboxWER)
        self.add(self.checkboxETL)
        self.add(self.checkboxLog)
        self.add(self.checkboxDmp)
        self.add(self.checkboxEVTx)
        self.add(self.errorMessageLabel)

    # TODO: Update this for your UI
    def customizeComponents(self):
        self.checkDatabaseEntries()

    # Return the settings used
    def getSettings(self):
        return self.local_settings

    # Check database for log type flags
    def checkDatabaseEntries(self):
        head, tail = os.path.split(os.path.abspath(__file__)) 
        settings_db = head + "\\guiSettings.db"
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % settings_db)
        except SQLException as e:
            self.errorMessageLabel.setText("Error opening database!")
 
        try:
            stmt = dbConn.createStatement()
            query = 'SELECT * FROM settings WHERE id = 1;' 
            resultSet = stmt.executeQuery(query)
            while resultSet.next():
                self.local_settings.setCheckWER((resultSet.getInt("checkWER")>0))
                self.checkboxWER.setSelected((resultSet.getInt("checkWER")>0))
                self.local_settings.setCheckETL((resultSet.getInt("checkETL")>0))
                self.checkboxETL.setSelected((resultSet.getInt("checkETL")>0))
                self.local_settings.setCheckDmp((resultSet.getInt("checkDmp")>0))
                self.checkboxDmp.setSelected((resultSet.getInt("checkDmp")>0))
                self.local_settings.setCheckEVTx((resultSet.getInt("checkEVTx")>0))
                self.checkboxEVTx.setSelected((resultSet.getInt("checkEVTx")>0))
                self.local_settings.setCheckLog((resultSet.getInt("checkLog")>0))
                self.checkboxLog.setSelected((resultSet.getInt("checkLog")>0))
            self.errorMessageLabel.setText("Settings read successfully!")
        except SQLException as e:
            self.errorMessageLabel.setText("Could not read settings")

        stmt.close()
        dbConn.close()

    # Save ONE log flag
    def saveFlagSetting(self, flag, value):
        
        head, tail = os.path.split(os.path.abspath(__file__)) 
        settings_db = head + "\\guiSettings.db"
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % settings_db)
        except SQLException as e:
            self.errorMessageLabel.setText("Error opening settings")
        
        if value:
            int_value = 1
        else:
            int_value = 0

        try:
            stmt = dbConn.createStatement()
            query = 'UPDATE settings SET ' + flag + ' = ' + str(int_value) + ' WHERE id = 1;'
           
            stmt.executeUpdate(query)
            self.errorMessageLabel.setText("Saved setting")
        except SQLException as e:
            self.errorMessageLabel.setText("Error saving settings "+str(e))
        stmt.close()
        dbConn.close()
