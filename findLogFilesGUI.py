# See http://sleuthkit.org/autopsy/docs/api-docs/4.4/index.html for documentation

import jarray
import inspect
import os
import re
import logextractor
import MSWExtractor
import netaddr
import time
import socket
import shutil
import threading
import datetime
import sys

from Registry import Registry
from java.lang import System
from java.lang import Class
from java.lang import Exception as JavaException
from java.util.logging import Level
from javax.swing import JCheckBox
from javax.swing import BoxLayout
from java.awt import GridBagLayout
from java.awt import FlowLayout
from java.awt import GridBagConstraints
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JComponent
from javax.swing import JTextField
from javax.swing import JButton
from javax.swing import JList
from javax.swing import JScrollPane
from javax.swing import DefaultListModel
from java.io import File
from java.sql import DriverManager, SQLException

from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import PlatformUtil
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
from org.sleuthkit.datamodel import TskCoreException, TskException
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.datamodel import ContentUtils
from java.lang import IllegalArgumentException

# Constants
WER_FOLDER_PATH = "\\WERs"
LOG_FOLDER_PATH = "\\AdhocLogs"
WSU_FOLDER_PATH = "\\WindowsStartupInfo"
DB_PATH = "\\guiSettings.db"

# Global variables
G_num_files_found = 0
G_one_thread_over = False


class LogForensicsForAutopsyFileIngestModuleWithUIFactory(IngestModuleFactoryAdapter):
    def __init__(self):
        self.settings = None

    moduleName = "Log Forensics for Autopsy"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "This module searchs for certain log files."

    def getModuleVersionNumber(self):
        return "1.4"

    def getDefaultIngestJobSettings(self):
        return LogForensicsForAutopsyFileIngestModuleWithUISettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, LogForensicsForAutopsyFileIngestModuleWithUISettings):
            raise IllegalArgumentException(
                "Expected settings argument to be instanceof LogForensicsForAutopsyFileIngestModuleWithUI")
        self.settings = settings
        return LogForensicsForAutopsyFileIngestModuleWithUISettingsPanel(self.settings)

    def isFileIngestModuleFactory(self):
        return True

    def createFileIngestModule(self, ingestOptions):
        return LogForensicsForAutopsyFileIngestModuleWithUI(self.settings)


# File-level ingest module.  One gets created per thread.
# Looks at the attributes of the passed in file.
class LogForensicsForAutopsyFileIngestModuleWithUI(FileIngestModule):

    _logger = Logger.getLogger(
        LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__,
                          inspect.stack()[1][3], msg)

    # Autopsy will pass in the settings from the UI panel
    def __init__(self, settings):
        self.local_settings = settings

    def get_ip_type(self, ip):
        ip_addr = netaddr.IPAddress(ip)
        if ip_addr.is_private():
            return "Private"
        if ip_addr.is_loopback():
            return "Loopback"
        if ip_addr.is_link_local():
            return "Link-local"
        if ip_addr.is_reserved():
            return "Reserved"
        return "Public"

    def create_temp_directory(self, dir):
        try:
            os.mkdir(self.temp_dir + dir)
        except:
            self.log(Level.INFO, "ERROR: " + dir + " directory already exists")

    def index_artifact(self, blackboard, artifact, artifact_type):
        try:
            # Index the artifact for keyword search
            blackboard.indexArtifact(artifact)
        except Blackboard.BlackboardException as e:
            self.log(Level.SEVERE, "Error indexing artifact " +
                     artifact.getDisplayName())
        # Fire an event to notify the UI and others that there is a new log artifact
        IngestServices.getInstance().fireModuleDataEvent(
            ModuleDataEvent(LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName,
                            artifact_type, None))

    def create_artifact_type(self, art_name, art_desc, skCase):
        try:
            skCase.addBlackboardArtifactType(art_name, "LFA: " + art_desc)
        except:
            self.log(Level.INFO, "ERROR creating artifact type: " + art_desc)
        art = skCase.getArtifactType(art_name)
        self.art_list.append(art)
        return art

    def create_attribute_type(self, att_name, type, att_desc, skCase):
        try:
            skCase.addArtifactAttributeType(att_name, type, att_desc)
        except:
            self.log(Level.INFO, "ERROR creating attribute type: " + att_desc)
        return skCase.getAttributeType(att_name)

    def create_invalid_wer_artifact(self, blackboard, file, file_path, reason):
        art = file.newArtifact(self.art_invalid_wer_file.getTypeID())

        # Register case file path
        art.addAttribute(BlackboardAttribute(
            self.att_case_file_path, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, file_path))

        # Register reason
        art.addAttribute(BlackboardAttribute(
            self.att_reason_invalid, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, reason))
        # Add artifact to Blackboard
        self.index_artifact(blackboard, art, self.art_invalid_wer_file)

    # Where any setup and configuration is done
    def startUp(self, context):
        # For statistics purposes
        self.filesFound = 0
        self.start_time = time.time()

        # Get Sleuthkit case
        skCase = Case.getCurrentCase().getSleuthkitCase()

        # Get UI settings now and avoid always calling getters
        self.checkWSU = self.local_settings.getCheckWSU()
        self.checkETL = self.local_settings.getCheckETL()
        self.checkWER = self.local_settings.getCheckWER()
        self.checkDmp = self.local_settings.getCheckDmp()
        self.checkEVTx = self.local_settings.getCheckEVTx()
        self.checkLog = self.local_settings.getCheckLog()

        # Create new artifact types
        self.art_list = []
        self.art_log_file = self.create_artifact_type(
            "TSK_LFA_LOG_FILE", "Ad hoc log files", skCase)
        self.art_reported_program = self.create_artifact_type(
            "TSK_LFA_REPORTED_PROGRAMS", "Reported programs", skCase)
        self.art_logged_ip = self.create_artifact_type(
            "TSK_LFA_LOG_FILE_IP", "Logged IP addresses", skCase)
        self.art_etl_file = self.create_artifact_type(
            "TSK_LFA_ETL_FILE", "Event Trace Log files", skCase)
        self.art_dmp_file = self.create_artifact_type(
            "TSK_LFA_DMP_FILE", "Dmp files", skCase)
        self.art_evt_file = self.create_artifact_type(
            "TSK_LFA_EVT_FILE", "EVT/EVTX files", skCase)
        self.art_wer_file = self.create_artifact_type(
            "TSK_LFA_WER_FILE", "WER files", skCase)
        self.art_windows_startup_file = self.create_artifact_type(
            "TSK_LFA_WIN_SU_FILE", "Startup info files", skCase)
        self.art_windows_startup_info = self.create_artifact_type(
            "TSK_LFA_WIN_SU_INFO", "Startup processed info", skCase)
        self.art_invalid_wer_file = self.create_artifact_type(
            "TSK_LFA_INVALID_WER_FILE", "Invalid WER files", skCase)
        self.art_wer_settings = self.create_artifact_type(
            "TSK_LFA_WER_SETTINGS", "WER Registry settings", skCase)

        # Custom RegEx artifacts
        self.art_custom_regex = {}
        for idx, regex in enumerate(self.local_settings.getRegexList().toArray()):
            if regex.active:
                self.art_custom_regex[regex.regex] = self.create_artifact_type(
                    "TSK_LFA_CUSTOM_REGEX_"+str(idx), regex.name, skCase)

        # Create attribute types
        self.att_wer_consent_level = self.create_attribute_type(
           'TSK_LFA_WER_CONSENT_LEVEL', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Consent Level", skCase)

        self.att_wer_state = self.create_attribute_type(
           'TSK_LFA_WER_STATE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "WER system state", skCase)
    
        self.att_log_size = self.create_attribute_type(
            'TSK_LFA_LOG_SIZE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Log size (B)", skCase)

        self.att_access_time = self.create_attribute_type(
            'TSK_LFA_ACCESS_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Last access", skCase)

        self.att_modified_time = self.create_attribute_type(
            'TSK_LFA_MODIFIED_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Last modified", skCase)

        self.att_created_time = self.create_attribute_type(
            'TSK_LFA_CREATED_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Create date", skCase)

        self.att_case_file_path = self.create_attribute_type(
            'TSK_LFA_CASE_FILE_PATH', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File path (case)", skCase)

        self.att_app_path = self.create_attribute_type(
            'TSK_LFA_APP_PATH', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "App path", skCase)

        self.att_app_name = self.create_attribute_type(
            'TSK_LFA_APP_NAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "App name", skCase)

        self.att_event_name = self.create_attribute_type(
            'TSK_LFA_EVENT_NAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event name", skCase)

        self.att_event_time = self.create_attribute_type(
            'TSK_LFA_EVENT_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event time", skCase)

        self.att_dump_files = self.create_attribute_type(
            'TSK_LFA_DUMP_FILES', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Dump files", skCase)

        self.att_ip_address = self.create_attribute_type(
            'TSK_LFA_IP_ADDRESS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IP address", skCase)

        self.att_ip_counter = self.create_attribute_type(
            'TSK_LFA_IP_COUNTER', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Occurrences", skCase)

        self.att_ip_protocol = self.create_attribute_type(
            'TSK_LFA_IP_PROTOCOL', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Protocol", skCase)

        self.att_ip_type = self.create_attribute_type(
            'TSK_LFA_IP_TYPE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Type", skCase)

        self.att_ip_version = self.create_attribute_type(
            'TSK_LFA_IP_VERSION', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Version", skCase)

        self.att_ip_domain = self.create_attribute_type(
            'TSK_LFA_IP_DOMAIN', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Domain", skCase)

        self.att_windows_ver = self.create_attribute_type(
            'TSK_LFA_WINDOWS_VERSION', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Windows version", skCase)

        self.att_custom_match = self.create_attribute_type(
            'TSK_LFA_CUSTOM_MATCH', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Content matched", skCase)

        self.att_wsu_process_name = self.create_attribute_type(
            'TSK_LFA_WSU_PROCESS_NAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Name", skCase)

        self.att_wsu_pid = self.create_attribute_type(
            'TSK_LFA_WSU_PID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "PID", skCase)

        self.att_wsu_sits = self.create_attribute_type(
            'TSK_LFA_WSU_SITS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Started in trace sec", skCase)

        self.att_wsu_start_time = self.create_attribute_type(
            'TSK_LFA_WSU_START_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Start time", skCase)

        self.att_wsu_cmd_line = self.create_attribute_type(
            'TSK_LFA_WSU_CMD_LINE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Command line", skCase)

        self.att_wsu_disk_usage = self.create_attribute_type(
            'TSK_LFA_WSU_DISK_USAGE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Disk usage (B)", skCase)

        self.att_wsu_cpu_usage = self.create_attribute_type(
            'TSK_LFA_WSU_CPU_USAGE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "CPU usage (us)", skCase)

        self.att_wsu_ppid = self.create_attribute_type(
            'TSK_LFA_WSU_PPID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Parent PID", skCase)

        self.att_wsu_parent_start_time = self.create_attribute_type(
            'TSK_LFA_WSU_PARENT_START_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Parent start time", skCase)

        self.att_wsu_parent_name = self.create_attribute_type(
            'TSK_LFA_WSU_PARENT_NAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Parent name", skCase)

        self.att_reason_invalid = self.create_attribute_type(
            'TSK_LFA_INVALID_REASON', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Reason", skCase)

        # Case Temporary directory, where files will be stored
        self.temp_dir = Case.getCurrentCase().getTempDirectory()

        # RegEx pattern to identify WSU files
        self.wsu_patt = re.compile(
            r'.*s-1-5-21-\d+-\d+\-\d+\-\d+_startupinfo\d\.xml')

        self.software_hive_location = "Windows/System32/config/SOFTWARE"
        # Create directories for files
        if self.checkWER:
            self.create_temp_directory(WER_FOLDER_PATH)

        if self.checkLog:
            self.create_temp_directory(LOG_FOLDER_PATH)

        if self.checkWSU:
            self.create_temp_directory(WSU_FOLDER_PATH)

        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")

    # Where the analysis is done.  Each file will be passed into here.
    def process(self, file):

        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
            (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
                (file.isFile() == False)):
            return IngestModule.ProcessResult.OK

        full_path = (file.getParentPath() + file.getName())[1:]

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        file_name = file.getName().lower()

        if full_path == self.software_hive_location and self.checkWER: 
            temp_hive_path = os.path.join(self.temp_dir , "SOFTWARE")
            try:
                ContentUtils.writeToFile(file, File(temp_hive_path))
            except TskCoreException as e:
                self.log(Level.INFO, "TSK ERROR: " + str(e))
                return IngestModule.ProcessResult.OK
            try:            
                hive = Registry.Registry(temp_hive_path) 
                consent_key = hive.open("Microsoft\\Windows\\Windows Error Reporting\\Consent")
                for subkey in consent_key.values():
                    if subkey.name() == "DefaultConsent":
                        if subkey.value() == 1:
                            wer_consent_key = 'Always ask' 
                        elif subkey.value() == 2:
                            wer_consent_key = 'Parameters only'
                        elif subkey.value() == 3:
                            wer_consent_key = 'Parameters and safe data'
                        else:
                            wer_consent_key = 'All data'
                        break
                else:
                        wer_consent_key = 'Always ask' 

                root_key = hive.open("Microsoft\\Windows\\Windows Error Reporting")
                for subkey in root_key.values():  
                    if subkey.name() == "Disabled":
                        wer_state = 'Disabled' if subkey.value() == 1 else 'Enabled'
                        break
                else:
                    wer_state = 'Disabled'

                self.log(Level.INFO, "WER consent level and state " + wer_consent_key + " " + wer_state)

                art = file.newArtifact(self.art_wer_settings.getTypeID())

                art.addAttribute(BlackboardAttribute(self.att_wer_consent_level, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, wer_consent_key))

                art.addAttribute(BlackboardAttribute(self.att_wer_state, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, wer_state))

                self.index_artifact(blackboard, art,self.art_wer_settings)
                os.remove(self.temp_hive_path)
            

            except:
                wer_consent_key = 'N/A'
                wer_state = 'N/A'

        # Is file of certain extension AND is its checkbox checked?
        if ((file_name.endswith(".etl") and self.checkETL) or
            (file_name.endswith(".wer") and self.checkWER) or
            (file_name.endswith(".dmp") and self.checkDmp) or
            (file_name.endswith(".evtx") and self.checkEVTx) or
            (file_name.endswith(".log") and self.checkLog) or
            (self.wsu_patt.match(file_name) is not None and self.checkWSU)):

            # Get all file artifacts
            skCase = Case.getCurrentCase().getSleuthkitCase()

            # Get one list at a time and append them

            if file_name.endswith(".wer"):
                generic_art = self.art_wer_file
                artifact_list = skCase.getBlackboardArtifacts(
                    self.art_wer_file.getTypeID())
            elif file_name.endswith(".log"):
                generic_art = self.art_log_file
                artifact_list = skCase.getBlackboardArtifacts(
                    self.art_log_file.getTypeID())
            elif file_name.endswith(".dmp"):
                generic_art = self.art_dmp_file
                artifact_list = skCase.getBlackboardArtifacts(
                    self.art_dmp_file.getTypeID())
            elif file_name.endswith(".etl"):
                generic_art = self.art_etl_file
                artifact_list = skCase.getBlackboardArtifacts(
                    self.art_etl_file.getTypeID())
            elif file_name.endswith(".evtx"):
                generic_art = self.art_evt_file
                artifact_list = skCase.getBlackboardArtifacts(
                    self.art_evt_file.getTypeID())
            elif self.wsu_patt.match(file_name):
                generic_art = self.art_windows_startup_file
                artifact_list = skCase.getBlackboardArtifacts(
                    self.art_windows_startup_file.getTypeID())

            file_path = file.getUniquePath() + file.getName()

            for artifact in artifact_list:
                # Check if file is already an artifact
                # If the files have the same name and parent path (this path already has the datasource), file is repeated
                if artifact.getAttribute(self.att_case_file_path) != None and artifact.getAttribute(self.att_case_file_path).getValueString() == file_path:
                    self.log(
                        Level.INFO, "File is already in artifact list "+file_path)
                    return IngestModule.ProcessResult.OK

            self.filesFound += 1

            #  Exclusive zone
            lock = threading.Lock()
            lock.acquire()
            global G_num_files_found
            G_num_files_found += 1
            lock.release()

            ########################################################
            #       _ _    __ _ _        _                         #
            #      | | |  / _(_) |      | |                        #
            #  __ _| | | | |_ _| | ___  | |_ _   _ _ __   ___  ___ #
            # / _` | | | |  _| | |/ _ \ | __| | | | '_ \ / _ \/ __|#
            #| (_| | | | | | | | |  __/ | |_| |_| | |_) |  __/\__ \#
            # \__,_|_|_| |_| |_|_|\___|  \__|\__, | .__/ \___||___/#
            #                                 __/ | |              #
            #                                |___/|_|              #
            # ######################################################

            # Make an artifact
            art = file.newArtifact(generic_art.getTypeID())

            # Register log file size
            art.addAttribute(BlackboardAttribute(
                self.att_log_size, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, file.getSize()))

            # Register creation date
            art.addAttribute(BlackboardAttribute(
                self.att_created_time, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, file.getCrtime()))

            # Register modified date
            art.addAttribute(BlackboardAttribute(
                self.att_modified_time, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, file.getMtime()))

            # Register creation date
            art.addAttribute(BlackboardAttribute(
                self.att_access_time, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, file.getAtime()))

            # Register case file path
            art.addAttribute(BlackboardAttribute(
                self.att_case_file_path, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, file_path))

            # Add the file log artifact
            self.index_artifact(blackboard, art, generic_art)

            #####################################################################################################
            #  _____                                                             _    _   __              _     #
            # |  __ \                                               /\          | |  (_) / _|            | |    #
            # | |__) |_ __  ___    __ _  _ __  __ _  _ __ ___      /  \    _ __ | |_  _ | |_  __ _   ___ | |_   #
            # |  ___/| '__|/ _ \  / _` || '__|/ _` || '_ ` _ \    / /\ \  | '__|| __|| ||  _|/ _` | / __|| __|  #
            # | |    | |  | (_) || (_| || |  | (_| || | | | | |  / ____ \ | |   | |_ | || | | (_| || (__ | |_   #
            # |_|    |_|   \___/  \__, ||_|   \__,_||_| |_| |_| /_/    \_\|_|    \__||_||_|  \__,_| \___| \__|  #
            #                      __/ |                                                                        #
            #                     |___/                                                                         #
            #####################################################################################################

            if file_name.endswith(".wer"):
                # Save the file locally in the temp folder and use file id as name to reduce collisions
                self.temp_wer_path = os.path.join(
                    self.temp_dir + WER_FOLDER_PATH, str(file.getId()))
                try:
                    ContentUtils.writeToFile(file, File(self.temp_wer_path))
                except TskCoreException as e:
                    self.log(Level.INFO, "TSK ERROR: " + str(e))
                    return IngestModule.ProcessResult.OK

                # Get the parsed result
                try:
                    # Check if WER file is valid
                    if not MSWExtractor.wer_extractor.is_file_wer(self.temp_wer_path):
                        # Add Invalid WER file artifact
                        self.create_invalid_wer_artifact(
                            blackboard, file, file_path, "Invalid report")
                        return IngestModule.ProcessResult.OK

                    # If valid, get the information
                    wer_info = MSWExtractor.wer_extractor.extract_default_keys(
                        self.temp_wer_path)
                except (Exception, JavaException) as e:
                    # Add Invalid WER file artifact
                    self.log(Level.INFO, "Not parseable WER: " + str(e))
                    self.create_invalid_wer_artifact(
                        blackboard, file, file_path, "Could not parse the report")
                    return IngestModule.ProcessResult.OK

                # Create new program artifact if .wer file is valid
                reported_art = file.newArtifact(
                    self.art_reported_program.getTypeID())

                # Add normal attributes to artifact
                reported_art.addAttribute(BlackboardAttribute(
                    self.att_app_name, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(wer_info['AppName'])))

                reported_art.addAttribute(BlackboardAttribute(
                    self.att_event_name, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(wer_info['FriendlyEventName'])))

                reported_art.addAttribute(BlackboardAttribute(
                    self.att_event_time, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(wer_info['EventTime'])))

                reported_art.addAttribute(BlackboardAttribute(
                    self.att_app_path, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(wer_info['AppPath'])))

                reported_art.addAttribute(BlackboardAttribute(
                    self.att_windows_ver, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(wer_info['WindowsVersion'])))

                # Adding dump file search result
                dmp = MSWExtractor.wer_extractor.find_dmp_files(
                    self.temp_wer_path)

                if not dmp or "Error" in dmp:
                    dmp = "None"
                else:
                    dmp = ', '.join(dmp)

                reported_art.addAttribute(BlackboardAttribute(
                    self.att_dump_files, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, dmp))

                # Add artifact to Blackboard
                self.index_artifact(blackboard, reported_art,
                                    self.art_reported_program)
                os.remove(self.temp_wer_path)

            #################################################
            #     _                  __  _  _               #
            #    | |                / _|(_)| |              #
            #    | |  ___    __ _  | |_  _ | |  ___  ___    #
            #    | | / _ \  / _` | |  _|| || | / _ \/ __|   #
            #  _ | || (_) || (_| | | |  | || ||  __/\__ \   #
            # (_)|_| \___/  \__, | |_|  |_||_| \___||___/   #
            #                __/ |                          #
            #               |___/                           #
            #################################################

            if file_name.endswith(".log"):
                # Save the file locally in the temp folder and use file id as name to reduce collisions
                self.temp_log_path = os.path.join(
                    self.temp_dir + LOG_FOLDER_PATH, str(file.getId()))
                try:
                    ContentUtils.writeToFile(file, File(self.temp_log_path))
                except TskCoreException as e:
                    self.log(Level.INFO, "TSK ERROR: " + str(e))
                    return IngestModule.ProcessResult.OK

                # Search with the custom patterns inserted by the user
                for regex in self.art_custom_regex:
                    # Get the parsed result
                    try:
                        log_info = logextractor.log_extractor.extract_custom_regex(
                            self.temp_log_path, regex)
                    except Exception as e:
                        self.log(Level.INFO, "Python ERROR: " +
                                 str(e) + " at file: " + file.getName())
                        return IngestModule.ProcessResult.OK
                    except JavaException as e:
                        self.log(Level.INFO, "Java ERROR: " +
                                 e.getMessage() + " at file: " + file.getName())
                        return IngestModule.ProcessResult.OK

                    for occurrence, counter in log_info.iteritems():
                        art = file.newArtifact(
                            self.art_custom_regex[regex].getTypeID())

                        art.addAttribute(BlackboardAttribute(
                            self.att_custom_match, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(occurrence)))
                        art.addAttribute(BlackboardAttribute(
                            self.att_ip_counter, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(counter)))
                        art.addAttribute(BlackboardAttribute(
                            self.att_case_file_path, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, file_path))

                        # Add artifact to Blackboard
                        self.index_artifact(
                            blackboard, art, self.art_custom_regex[regex])

                if self.local_settings.getCheckLogIPs():
                    # Get the parsed result
                    try:
                        log_info = logextractor.log_extractor.extract_ip_addresses(
                            self.temp_log_path)
                    except (IOError, StandardError) as e:
                        self.log(Level.INFO, "Python ERROR: " +
                                 str(e) + " at file: " + file.getName())
                        return IngestModule.ProcessResult.OK
                    except JavaException as e:
                        self.log(Level.INFO, "Java ERROR: " +
                                 e.getMessage() + " at file: " + file.getName())
                        return IngestModule.ProcessResult.OK

                    # An ad hoc log can have multiple artifacts
                    # As long as it has more than one IP address registered
                    # So let's iterate over the dictionary
                    for (ip, protocol, counter) in log_info:
                        # Create artifact
                        ip_art = file.newArtifact(
                            self.art_logged_ip.getTypeID())

                        # Add IP type
                        ip_type = self.get_ip_type(ip)
                        ip_art.addAttribute(BlackboardAttribute(
                            self.att_ip_type, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, ip_type))

                        # Add current domain
                        if ip_type == 'Public':
                            try:
                                domain = socket.gethostbyaddr(ip)[0]
                                ip_domain = 'Same as IP' if domain == ip else domain
                            except socket.herror as e:
                                ip_domain = 'Error: ' + e
                        else:
                            ip_domain = 'N/A'
                        ip_art.addAttribute(BlackboardAttribute(
                            self.att_ip_domain, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, ip_domain))
                        # Add IP version
                        ip_version = "IPv" + str(netaddr.IPAddress(ip).version)
                        ip_art.addAttribute(BlackboardAttribute(
                            self.att_ip_version, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, ip_version))

                        # Add IP to artifact
                        ip_art.addAttribute(BlackboardAttribute(
                            self.att_ip_address, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(ip)))

                        # Add protocol to artifact
                        ip_art.addAttribute(BlackboardAttribute(
                            self.att_ip_protocol, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(protocol)))

                        # Add counter to artifact
                        ip_art.addAttribute(BlackboardAttribute(
                            self.att_ip_counter, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(counter)))

                        # Add file path to artifact
                        ip_art.addAttribute(BlackboardAttribute(
                            self.att_case_file_path, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, file_path))

                        # Add artifact to Blackboard
                        self.index_artifact(
                            blackboard, ip_art, self.art_logged_ip)
                os.remove(self.temp_log_path)

            ######################################################################################
            #          _______             _______ _________ _        _______  _______           #
            #|\     /|(  ____ \|\     /|  (  ____ \\__   __/( \      (  ____ \(  ____ \          #
            #| )   ( || (    \/| )   ( |  | (    \/   ) (   | (      | (    \/| (    \/          #
            #| | _ | || (_____ | |   | |  | (__       | |   | |      | (__    | (_____           #
            #| |( )| |(_____  )| |   | |  |  __)      | |   | |      |  __)   (_____  )          #
            #| || || |      ) || |   | |  | (         | |   | |      | (            ) |          #
            #| () () |/\____) || (___) |  | )      ___) (___| (____/\| (____/\/\____) |          #
            #(_______)\_______)(_______)  |/       \_______/(_______/(_______/\_______)          #
            ######################################################################################

            # WSU RegEx and doesn't have -slack on the name
            # Files ending in -slack are not readable in the same way
            if self.wsu_patt.match(file_name) is not None and "-slack" not in file_name:
                self.temp_wsu_path = os.path.join(
                    self.temp_dir + WSU_FOLDER_PATH, str(file.getId()))
                try:
                    ContentUtils.writeToFile(file, File(self.temp_wsu_path))
                except TskCoreException as e:
                    self.log(Level.INFO, "TSK ERROR: " + str(e))
                    return IngestModule.ProcessResult.OK

                try:
                    wsu_info = MSWExtractor.startup_extractor.parse_startup_info(
                        self.temp_wsu_path)
                except Exception as e:
                    self.log(Level.INFO, "WSU Python ERROR: " +
                             str(e) + " at file: " + file.getName())
                    return IngestModule.ProcessResult.OK
                except JavaException as e:
                    self.log(Level.INFO, "WSU Java ERROR: " +
                             e.getMessage() + " at file: " + file.getName())
                    return IngestModule.ProcessResult.OK

                for process in wsu_info:
                    art = file.newArtifact(
                        self.art_windows_startup_info.getTypeID())

                    art.addAttribute(BlackboardAttribute(
                        self.att_wsu_process_name, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(process.process_name)))

                    art.addAttribute(BlackboardAttribute(
                        self.att_wsu_pid, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(process.pid)))

                    art.addAttribute(BlackboardAttribute(
                        self.att_wsu_sits, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(process.started_trace_in_sec)))

                    art.addAttribute(BlackboardAttribute(
                        self.att_wsu_start_time, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(process.start_time)))

                    art.addAttribute(BlackboardAttribute(
                        self.att_wsu_cmd_line, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(process.command_line)))

                    art.addAttribute(BlackboardAttribute(
                        self.att_wsu_disk_usage, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(process.disk_usage)))

                    art.addAttribute(BlackboardAttribute(
                        self.att_wsu_cpu_usage, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(process.cpu_usage)))

                    art.addAttribute(BlackboardAttribute(
                        self.att_wsu_ppid, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(process.parent_PID)))

                    art.addAttribute(BlackboardAttribute(
                        self.att_wsu_parent_start_time, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(process.parent_start_time)))

                    art.addAttribute(BlackboardAttribute(
                        self.att_wsu_parent_name, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(process.parent_name)))

                    art.addAttribute(BlackboardAttribute(
                        self.att_case_file_path, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, file_path))

                    # Add artifact to Blackboard
                    self.index_artifact(
                        blackboard, art, self.art_windows_startup_info)
                os.remove(self.temp_wsu_path)

        return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    def shutDown(self):
        elapsed_time = time.time() - self.start_time
        self.log(Level.INFO, "Thread name: " + threading.current_thread().name)
        self.log(Level.INFO, "This thread lasted: " +
                 str(round(elapsed_time, 1))+"s")
        self.log(Level.INFO, "Files found by this thread: " +
                 str(self.filesFound))

        lock = threading.Lock()
        lock.acquire()

        if G_one_thread_over:
            lock.release()
            return
        global G_one_thread_over 
        G_one_thread_over = True

        skCase = Case.getCurrentCase().getSleuthkitCase()

        for art_type in self.art_list:
            art_count = skCase.getBlackboardArtifactsTypeCount(art_type.getTypeID())
            self.log(Level.INFO, art_type.getDisplayName() + ": " + str(art_count) + " artifacts")

        # Inform user of number of files found and elapsed time
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                              LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName,
                                              str(G_num_files_found) + " total files found. Elapsed time: "+str(round(elapsed_time, 1))+"s")
        ingestServices = IngestServices.getInstance().postMessage(message)

        self.log(Level.INFO, "LFA File Ingest module took "+str(round(elapsed_time, 1)
                                                                )+"s and found " + str(G_num_files_found) + " files")

        self.createStatisticsFile(elapsed_time)

        lock.release()
    
    def createStatisticsFile(self,elapsed_time):
        skCase = Case.getCurrentCase().getSleuthkitCase()
        file_stat_path = os.path.join(Case.getCurrentCase().getCaseDirectory() , "LFA_statistics.txt")
        file_stats = open(file_stat_path,"a")
        file_stats.write("Date and time of execution " + str(datetime.datetime.fromtimestamp(time.time()))+"\n")
        file_stats.write("\tTotal files found: "+str(G_num_files_found)+"\n")        
        for art_type in self.art_list:
            art_count = skCase.getBlackboardArtifactsTypeCount(art_type.getTypeID())
            file_stats.write("\t"+art_type.getDisplayName() + ": " + str(art_count) + " artifacts" + "\n")
        file_stats.write("\tDuration of execution: " + str(elapsed_time)+ "\n\n")
        file_stats.close()
        



# Stores the settings that can be changed for each ingest job
# All fields in here must be serializable.  It will be written to disk.

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

    def getCheckLogIPs(self):
        return self.checkLogIPs

    def setCheckLogIPs(self, checkLogIPs):
        self.checkLogIPs = checkLogIPs

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

    def getRegexList(self):
        return self.regexList

    def setRegexList(self, regex_list):
        self.regexList = regex_list

    def getCheckWSU(self):
        return self.checkWSU

    def setCheckWSU(self, checkWSU):
        self.checkWSU = checkWSU

# UI that is shown to user for each ingest job so they can configure the job.


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
        self.panelAddRegex.setVisible(self.checkboxLog.isSelected())
        self.saveFlagSetting("checkLog", self.checkboxLog.isSelected())

    def checkBoxEventDmp(self, event):
        self.local_settings.setCheckDmp(self.checkboxDmp.isSelected())
        self.saveFlagSetting("checkDmp", self.checkboxDmp.isSelected())

    def checkBoxEventEVTx(self, event):
        self.local_settings.setCheckEVTx(self.checkboxEVTx.isSelected())
        self.saveFlagSetting("checkEVTx", self.checkboxEVTx.isSelected())

    def checkBoxEventLogIPs(self, event):
        self.local_settings.setCheckLogIPs(self.checkboxLogIPs.isSelected())
        self.saveFlagSetting("checkLogIPs", self.checkboxLogIPs.isSelected())

    def checkBoxEventWSU(self, event):
        self.local_settings.setCheckWSU(self.checkboxWSU.isSelected())
        self.saveFlagSetting("checkWSU", self.checkboxWSU.isSelected())

    def updateGlobalRegexList(self):
        self.local_settings.setRegexList(self.regex_list)

    def updateRegexList(self):
        self.listRegex.setListData(self.regex_list)

    def addRegexToList(self, event):
        try:
            p = self.textFieldRegex.getText()
            re.compile(p)

            regex = Regex(self.textFieldRegexName.getText(), p)
            self.regex_list.addElement(regex)
            self.textFieldRegex.setText("")
            self.textFieldRegexName.setText("")
            self.updateGlobalRegexList()
        except re.error:
            self.labelErrorMessage.setText("Could not compile that RegEx.")

    def removeRegexFromList(self, event):
        regex = self.listRegex.getSelectedValue()
        self.regex_list.removeElement(regex)
        self.updateGlobalRegexList()

    def saveRegexesToDB(self, event):
        self.saveRegexes()

    def clearList(self, event):
        self.regex_list.clear()
        self.updateGlobalRegexList()

    def activateRegex(self, event):
        regex = self.listRegex.getSelectedValue()
        regex.active = not regex.active
        self.updateGlobalRegexList()
        # self.updateRegexList()

    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        self.regex_list = DefaultListModel()

        panelFiles = JPanel()
        panelFiles.setLayout(BoxLayout(panelFiles, BoxLayout.X_AXIS))
        panelFiles.setAlignmentX(JComponent.LEFT_ALIGNMENT)

        panelRegexes = JPanel()
        panelRegexes.setLayout(BoxLayout(panelRegexes, BoxLayout.X_AXIS))
        panelRegexes.setAlignmentX(JComponent.LEFT_ALIGNMENT)

        panelRegexesButtons = JPanel()
        panelRegexesButtons.setLayout(
            BoxLayout(panelRegexesButtons, BoxLayout.X_AXIS))
        panelRegexesButtons.setAlignmentX(JComponent.LEFT_ALIGNMENT)

        self.panelAddRegex = JPanel()
        self.panelAddRegex.setLayout(GridBagLayout())
        gbc = GridBagConstraints()
        self.panelAddRegex.setAlignmentX(JComponent.LEFT_ALIGNMENT)

        self.labelCheckText = JLabel("Check for type files: ")
        self.labelAddRegex = JLabel("Add RegEx to .log files: ")
        self.labelAddRegexName = JLabel("Name: ")
        self.labelAddRegexRegex = JLabel(" RegEx: ")
        self.labelErrorMessage = JLabel(" ")
        self.labelInfoMessage = JLabel(
            "Internet access is required for domain lookup (.log IPs)")
        self.labelCheckText.setEnabled(True)
        self.labelInfoMessage.setEnabled(True)
        self.labelErrorMessage.setEnabled(True)
        self.labelAddRegex.setEnabled(True)

        self.checkboxWER = JCheckBox(
            "WER", actionPerformed=self.checkBoxEventWER)
        self.checkboxETL = JCheckBox(
            "ETL", actionPerformed=self.checkBoxEventETL)
        self.checkboxLog = JCheckBox(
            "Log", actionPerformed=self.checkBoxEventLog)
        self.checkboxEVTx = JCheckBox(
            "EVTx", actionPerformed=self.checkBoxEventEVTx)
        self.checkboxDmp = JCheckBox(
            "Dmp", actionPerformed=self.checkBoxEventDmp)
        self.checkboxLogIPs = JCheckBox(
            "Check .log IPs", actionPerformed=self.checkBoxEventLogIPs)
        self.checkboxWSU = JCheckBox(
            "Check Windows Startup XML", actionPerformed=self.checkBoxEventWSU)

        self.buttonAddRegex = JButton(
            "Add", actionPerformed=self.addRegexToList)
        self.buttonRemoveRegex = JButton(
            "Remove", actionPerformed=self.removeRegexFromList)
        self.buttonActivateRegex = JButton(
            "(De) Activate", actionPerformed=self.activateRegex)
        self.buttonClearRegex = JButton(
            "Clear", actionPerformed=self.clearList)
        self.buttonSaveRegexes = JButton(
            "Save", actionPerformed=self.saveRegexesToDB)
        self.buttonAddRegex.setEnabled(True)

        self.textFieldRegex = JTextField(15)
        self.textFieldRegexName = JTextField(5)

        self.listRegex = JList(self.regex_list)
        # self.listRegex.setVisibleRowCount(3)
        self.scrollPaneListRegex = JScrollPane(self.listRegex)

        self.add(self.labelCheckText)
        panelFiles.add(self.checkboxWER)
        panelFiles.add(self.checkboxETL)
        panelFiles.add(self.checkboxLog)
        panelFiles.add(self.checkboxDmp)
        panelFiles.add(self.checkboxEVTx)
        self.add(panelFiles)
        self.add(self.checkboxLogIPs)
        self.add(self.checkboxWSU)
        self.add(self.labelInfoMessage)
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.panelAddRegex.add(self.labelAddRegex, gbc)
        panelRegexes.add(self.labelAddRegexName)
        panelRegexes.add(self.textFieldRegexName)
        panelRegexes.add(self.labelAddRegexRegex)
        panelRegexes.add(self.textFieldRegex)
        panelRegexes.add(self.buttonAddRegex)
        gbc.gridy = 2
        self.panelAddRegex.add(panelRegexes, gbc)
        gbc.gridy = 3
        self.panelAddRegex.add(self.scrollPaneListRegex, gbc)
        panelRegexesButtons.add(self.buttonRemoveRegex)
        panelRegexesButtons.add(self.buttonClearRegex)
        panelRegexesButtons.add(self.buttonSaveRegexes)
        panelRegexesButtons.add(self.buttonActivateRegex)
        gbc.gridy = 4
        self.panelAddRegex.add(panelRegexesButtons, gbc)
        self.add(self.panelAddRegex)

        self.add(self.labelErrorMessage)
        # Get UI values from database
        self.checkDatabaseEntries()
        self.updateGlobalRegexList()
        self.panelAddRegex.setVisible(self.checkboxLog.isSelected())

    def customizeComponents(self):
        # self.checkDatabaseEntries()
        pass

    # Return the settings used
    def getSettings(self):
        return self.local_settings

    # Check database for log type flags
    def checkDatabaseEntries(self):
        head, tail = os.path.split(os.path.abspath(__file__))
        settings_db = head + DB_PATH
        try:
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection(
                "jdbc:sqlite:%s" % settings_db)
        except SQLException as e:
            self.labelErrorMessage.setText("Error opening database!")

        try:
            stmt = dbConn.createStatement()
            query = 'SELECT * FROM settings WHERE id = 2;'
            resultSet = stmt.executeQuery(query)
            while resultSet.next():
                self.local_settings.setCheckWER(
                    (resultSet.getInt("checkWER") > 0))
                self.checkboxWER.setSelected(
                    (resultSet.getInt("checkWER") > 0))
                self.local_settings.setCheckETL(
                    (resultSet.getInt("checkETL") > 0))
                self.checkboxETL.setSelected(
                    (resultSet.getInt("checkETL") > 0))
                self.local_settings.setCheckDmp(
                    (resultSet.getInt("checkDmp") > 0))
                self.checkboxDmp.setSelected(
                    (resultSet.getInt("checkDmp") > 0))
                self.local_settings.setCheckEVTx(
                    (resultSet.getInt("checkEVTx") > 0))
                self.checkboxEVTx.setSelected(
                    (resultSet.getInt("checkEVTx") > 0))
                self.local_settings.setCheckLog(
                    (resultSet.getInt("checkLog") > 0))
                self.checkboxLog.setSelected(
                    (resultSet.getInt("checkLog") > 0))
                self.local_settings.setCheckLogIPs(
                    (resultSet.getInt("checkLogIPs") > 0))
                self.checkboxLogIPs.setSelected(
                    (resultSet.getInt("checkLogIPs") > 0))
                self.local_settings.setCheckWSU(
                    (resultSet.getInt("checkWSU") > 0))
                self.checkboxWSU.setSelected(
                    (resultSet.getInt("checkWSU") > 0))
            query = 'SELECT * FROM regexes;'
            resultSet = stmt.executeQuery(query)
            while resultSet.next():
                regex = Regex(resultSet.getString("name"), resultSet.getString(
                    "regex"), resultSet.getInt("active") > 0)
                self.regex_list.addElement(regex)
            self.labelErrorMessage.setText("Settings read successfully!")
        except SQLException as e:
            self.labelErrorMessage.setText("Could not read settings: "+str(e))

        stmt.close()
        dbConn.close()

    # Save ONE log flag
    def saveFlagSetting(self, flag, value):
        head, tail = os.path.split(os.path.abspath(__file__))
        settings_db = head + DB_PATH
        try:
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection(
                "jdbc:sqlite:%s" % settings_db)
        except SQLException as e:
            self.labelErrorMessage.setText("Error opening settings")

        int_value = 1 if value else 0

        try:
            stmt = dbConn.createStatement()
            query = 'UPDATE settings SET ' + flag + \
                ' = ' + str(int_value) + ' WHERE id = 2;'

            stmt.executeUpdate(query)
            self.labelErrorMessage.setText("Saved setting")
        except SQLException as e:
            self.labelErrorMessage.setText("Error saving settings "+str(e))
        stmt.close()
        dbConn.close()

    def saveRegexes(self):
        head, tail = os.path.split(os.path.abspath(__file__))
        settings_db = head + DB_PATH
        try:
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection(
                "jdbc:sqlite:%s" % settings_db)
        except SQLException as e:
            self.labelErrorMessage.setText("Error opening regexes")

        try:
            stmt = dbConn.createStatement()
            query = 'DELETE FROM regexes;'
            stmt.executeUpdate(query)
        except SQLException as e:
            self.labelErrorMessage.setText("Error saving settings "+str(e))
        try:
            sql = "INSERT INTO regexes (name, regex, active) values (?, ?, ?)"
            preparedStmt = dbConn.prepareStatement(sql)
            for regex in self.regex_list.toArray():
                active = 1 if regex.active else 0
                preparedStmt.setString(1, regex.name)
                preparedStmt.setString(2, regex.regex)
                preparedStmt.setInt(3, active)
                preparedStmt.addBatch()
            preparedStmt.executeBatch()
            self.labelErrorMessage.setText("Saved RegExes")
        except SQLException as e:
            self.labelErrorMessage.setText("Error saving settings "+str(e))

        stmt.close()
        preparedStmt.close()
        dbConn.close()


class Regex(object):
    """Class for a Regex inserted by the user
        regex: The RegEx inserted by the user (string)
        name: Name given by the user (string)
        active: If the RegEx is active (boolean)
    """

    def __init__(self, name, regex, active=True):
        self.regex = regex
        self.name = name
        self.active = active

    def __repr__(self):
        active = 'Active' if self.active else 'Inactive'
        return '['+str(active)+'] '+self.name+': '+self.regex
