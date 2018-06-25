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
# See http://sleuthkit.org/autopsy/docs/api-docs/4.4/index.html for documentation


import jarray
import inspect
import os
import logextractor
import werExtractor
import netaddr
from urllib2 import urlopen
import time
import socket

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
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.datamodel import ContentUtils
from java.lang import IllegalArgumentException

WER_FOLDER_PATH = "\\Wers"
LOG_FOLDER_PATH = "\\StandardLogs"
DB_PATH = "\\guiSettings.db"

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
            raise IllegalArgumentException(
                "Expected settings argument to be instanceof LogForensicsForAutopsyFileIngestModuleWithUI")
        self.settings = settings
        return LogForensicsForAutopsyFileIngestModuleWithUISettingsPanel(self.settings)

    def isFileIngestModuleFactory(self):
        return True

    # TODO: Update class name to one that you create below
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

    def create_artifact(self, logDesc, art_name, art_desc, skCase):
        try:
            self.log(Level.INFO, logDesc)
            return skCase.addBlackboardArtifactType(
                art_name, art_desc)
        except:
            self.log(Level.INFO, "Artifacts creation error, type ==> " + art_desc)
            return skCase.getArtifactType(art_name)

    # Where any setup and configuration is done
    def startUp(self, context):
        # For statistics purposes
        self.filesFound = 0
        self.start_time = time.time()

        # Get Sleuthkit case
        skCase = Case.getCurrentCase().getSleuthkitCase()

        # Create new artifact types
        self.art_log_file = self.create_artifact(
            "Create new Artifact Log File", "TSK_LFA_LOG_FILES", "Ad hoc log files", skCase)
        self.art_reported_program = self.create_artifact(
            "Create new Artifact Reported Programs", "TSK_LFA_REPORTED_PROGRAMS", "Reported programs", skCase)
        self.art_logged_ip = self.create_artifact(
            "Create new Artifact Logged IP", "TSK_LFA_LOG_FILE_IP", "Logged IP addresses", skCase)
        self.art_etl_file = self.create_artifact(
            "Create new Artifact ETL File", "TSK_LFA_ETL_FILES", "Event Trace Log files", skCase)
        self.art_dmp_file = self.create_artifact(
            "Create new Artifact Dmp File", "TSK_LFA_DMP_FILES", "Dmp files", skCase)
        self.art_evt_file = self.create_artifact(
            "Create new Artifact EVT File", "TSK_LFA_EVT_FILES", "EVT/EVTX files", skCase)
        self.art_wer_file = self.create_artifact(
            "Create new Artifact WER File", "TSK_LFA_WER_FILES", "WER files", skCase)

        # Create the attribute type Log size, if it already exists, catch error
        # Log size shows the size of the file in bytes
        try:
            self.att_log_size = skCase.addArtifactAttributeType(
                'TSK_LFA_LOG_SIZE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Log size (B)")
        except:
            self.log(Level.INFO, "Error creating attribute Log size")

        # Create the attribute type Access time, if it already exists, catch error
        try:
            self.att_access_time = skCase.addArtifactAttributeType(
                'TSK_LFA_ACCESS_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Last access")
        except:
            self.log(Level.INFO, "Error creating attribute Access time")

        # Create the attribute type Modified time, if it already exists, catch error
        try:
            self.att_modified_time = skCase.addArtifactAttributeType(
                'TSK_LFA_MODIFIED_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Last modified")
        except:
            self.log(Level.INFO, "Error creating attribute Modified time")

        # Create the attribute type Created time, if it already exists, catch error
        try:
            self.att_created_time = skCase.addArtifactAttributeType(
                'TSK_LFA_CREATED_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Create date")
        except:
            self.log(Level.INFO, "Error creating attribute Created time")

        # Create the attribute type Case file path, if it already exists, catch error
        try:
            self.att_case_file_path = skCase.addArtifactAttributeType(
                'TSK_LFA_CASE_FILE_PATH', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File path (case)")
        except:
            self.log(Level.INFO, "Error creating attribute Case file path")

        # Create the attribute type App path, if it already exists, catch error
        try:
            self.att_app_path = skCase.addArtifactAttributeType(
                'TSK_LFA_APP_PATH', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "App path")
        except:
            self.log(Level.INFO, "Error creating attribute App path")

        # Create the attribute type App name, if it already exists, catch error
        try:
            self.att_app_name = skCase.addArtifactAttributeType(
                'TSK_LFA_APP_NAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "App name")
        except:
            self.log(Level.INFO, "Error creating attribute App name")

        # Create the attribute type Event name, which is the FriendlyEventName in a WER file, if it already exists, catch error
        try:
            self.att_event_name = skCase.addArtifactAttributeType(
                'TSK_LFA_EVENT_NAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event name")
        except:
            self.log(Level.INFO, "Error creating attribute Event name")

        # Create the attribute type Event time, which is a FILETIME from the time the error occurred, if it already exists, catch error
        try:
            self.att_event_time = skCase.addArtifactAttributeType(
                'TSK_LFA_EVENT_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event time")
        except:
            self.log(Level.INFO, "Error creating attribute Event time")

        # Create the attribute type Dump files, which is a list of .dmp files referenced in the .wer file
        try:
            self.att_dump_files = skCase.addArtifactAttributeType(
                'TSK_LFA_DUMP_FILES', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Dump files")
        except:
            self.log(Level.INFO, "Error creating attribute Dump files")

        # Create the attribute type IP, which is an IP address
        try:
            self.att_ip_address = skCase.addArtifactAttributeType(
                'TSK_LFA_IP_ADDRESS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IP address")
        except:
            self.log(Level.INFO, "Error creating attribute IP address")

        # Create the attribute type Occurrences, which means how many times an IP was seen in a file
        try:
            self.att_ip_counter = skCase.addArtifactAttributeType(
                'TSK_LFA_IP_COUNTER', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Occurrences")
        except:
            self.log(Level.INFO, "Error creating attribute IP counter")

        # Create the attribute type IP type, which says if the IP is public or private
        try:
            self.att_ip_type = skCase.addArtifactAttributeType(
                'TSK_LFA_IP_TYPE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Type")
        except:
            self.log(Level.INFO, "Error creating attribute IP type")

        # Create the attribute type IP version, which says if the IP is ipv4 or ipv6
        try:
            self.att_ip_version = skCase.addArtifactAttributeType(
                'TSK_LFA_IP_VERSION', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Version")
        except:
            self.log(Level.INFO, "Error creating attribute IP Version")

        # Create the attribute type IP version, which says if possible the ip's current domain
        try:
            self.att_ip_domain = skCase.addArtifactAttributeType(
                'TSK_LFA_IP_DOMAIN', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Domain")
        except:
            self.log(Level.INFO, "Error creating attribute IP Domain")

        # Get Attributes after they are created
        self.att_log_size = skCase.getAttributeType("TSK_LFA_LOG_SIZE")
        self.att_created_time = skCase.getAttributeType("TSK_LFA_CREATED_TIME")
        self.att_access_time = skCase.getAttributeType("TSK_LFA_ACCESS_TIME")
        self.att_modified_time = skCase.getAttributeType(
            "TSK_LFA_MODIFIED_TIME")
        self.att_case_file_path = skCase.getAttributeType(
            "TSK_LFA_CASE_FILE_PATH")
        self.att_app_path = skCase.getAttributeType("TSK_LFA_APP_PATH")
        self.att_app_name = skCase.getAttributeType("TSK_LFA_APP_NAME")
        self.att_event_name = skCase.getAttributeType("TSK_LFA_EVENT_NAME")
        self.att_event_time = skCase.getAttributeType("TSK_LFA_EVENT_TIME")
        self.att_dump_files = skCase.getAttributeType("TSK_LFA_DUMP_FILES")
        self.att_ip_address = skCase.getAttributeType("TSK_LFA_IP_ADDRESS")
        self.att_ip_counter = skCase.getAttributeType("TSK_LFA_IP_COUNTER")
        self.att_ip_type = skCase.getAttributeType("TSK_LFA_IP_TYPE")
        self.att_ip_version = skCase.getAttributeType("TSK_LFA_IP_VERSION")
        self.att_ip_domain = skCase.getAttributeType("TSK_LFA_IP_DOMAIN")

        self.temp_dir = Case.getCurrentCase().getTempDirectory()

        if self.local_settings.getCheckWER():
            # Create wer directory in temp directory, if it exists then continue on processing
            self.log(Level.INFO, "Create .wer directory " + self.temp_dir)
            try:
                os.mkdir(self.temp_dir + WER_FOLDER_PATH)
            except:
                self.log(
                    Level.INFO, "Wers directory already exists " + self.temp_dir)

        if self.local_settings.getCheckLog():
            self.log(Level.INFO, "Create .log directory " + self.temp_dir)
            try:
                os.mkdir(self.temp_dir + LOG_FOLDER_PATH)
            except:
                self.log(
                    Level.INFO, "Logs directory already exists " + self.temp_dir)

        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")

    # Where the analysis is done.  Each file will be passed into here.
    def process(self, file):

        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
            (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
                (file.isFile() == False)):
            return IngestModule.ProcessResult.OK

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        file_name = file.getName().lower()
        # Is file of certain extension AND its checkbox is checked?
        if ((file_name.endswith(".etl") and self.local_settings.getCheckETL()) or
            ((file_name.endswith(".wer")) and self.local_settings.getCheckWER()) or
            (file_name.endswith(".dmp") and self.local_settings.getCheckDmp()) or
            (file_name.endswith(".evtx") and self.local_settings.getCheckEVTx()) or
                (file_name.endswith(".log") and self.local_settings.getCheckLog())):

            # Get all file artifacts 
            skCase = Case.getCurrentCase().getSleuthkitCase()
            #get one list at a time and append them 
            werList = skCase.getBlackboardArtifacts(self.art_wer_file.getTypeID()) if skCase.getBlackboardArtifacts(self.art_wer_file.getTypeID()) is not None else []
            dmpList = skCase.getBlackboardArtifacts(self.art_dmp_file.getTypeID()) if skCase.getBlackboardArtifacts(self.art_dmp_file.getTypeID()) is not None else []
            evtList = skCase.getBlackboardArtifacts(self.art_evt_file.getTypeID()) if skCase.getBlackboardArtifacts(self.art_evt_file.getTypeID()) is not None else []
            logList = skCase.getBlackboardArtifacts(self.art_log_file.getTypeID()) if skCase.getBlackboardArtifacts(self.art_log_file.getTypeID()) is not None else []
            etlList = skCase.getBlackboardArtifacts(self.art_etl_file.getTypeID()) if skCase.getBlackboardArtifacts(self.art_etl_file.getTypeID()) is not None else []
            werList.extend(dmpList)
            werList.extend(evtList)
            werList.extend(logList)
            werList.extend(etlList)
            artifact_list = werList

            file_path = file.getDataSource().getName() + file.getParentPath() + file.getName()
            for artifact in artifact_list:
                # Check if file is already an artifact
                # If the files have the same name and parent path (this path already has the datasource), file is repeated
                if artifact.getAttribute(self.att_case_file_path) != None and artifact.getAttribute(self.att_case_file_path).getValueString() == file_path:
                    self.log(Level.INFO, "File is already in artifact list")
                    return IngestModule.ProcessResult.OK

            self.filesFound += 1
            
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
            
            # workaround to sort in which artifact to be insterted
            if(file_name.endswith(".wer")):
                generic_art = self.art_wer_file
            elif(file_name.endswith(".log")):
                generic_art = self.art_log_file
            elif(file_name.endswith(".dmp")):
                generic_art = self.art_dmp_file
            elif(file_name.endswith(".etl")):
                generic_art = self.art_etl_file
            elif(file_name.endswith(".evtx")):
                generic_art = self.art_evt_file

            # Make an artifact
            art = file.newArtifact(generic_art.getTypeID())

            # Register log file size
            art.addAttribute(BlackboardAttribute(
                self.att_log_size, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(file.getSize())))

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
            try:
                # index the artifact for keyword search
                blackboard.indexArtifact(art)
            except Blackboard.BlackboardException as e:
                self.log(Level.SEVERE, "Error indexing artifact " +
                         art.getDisplayName())

            # Fire an event to notify the UI and others that there is a new log artifact
            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName,
                                generic_art, None))

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
                ContentUtils.writeToFile(file, File(self.temp_wer_path))
                self.log(Level.INFO, "Copying .wer file of id " +
                         str(file.getId()))

                # Get the parsed result
                wer_info = werExtractor.wer_extractor.extract_default_keys(
                    self.temp_wer_path)
                self.log(
                    Level.INFO, "Extracted .wer file of id " + str(file.getId()))

                # Check if any error occurred
                if wer_info.get('Error'):
                    self.log(
                        Level.INFO, "Could not parse .wer file of id: " + str(file.getId()))
                    return IngestModule.ProcessResult.OK

                # Create new program artifact if .wer file is valid
                reported_art = file.newArtifact(
                    self.art_reported_program.getTypeID())
                self.log(
                    Level.INFO, "Created new artifact of type art_reported_program for file of id " + str(file.getId()))

                # Add normal attributes to artifact
                reported_art.addAttribute(BlackboardAttribute(
                    self.att_app_name, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(wer_info['AppName'])))
                self.log(
                    Level.INFO, "Copying 1st att for .wer file of id " + str(file.getId()))

                reported_art.addAttribute(BlackboardAttribute(
                    self.att_event_name, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(wer_info['FriendlyEventName'])))
                self.log(
                    Level.INFO, "Copying 2nd att for .wer file of id " + str(file.getId()))

                reported_art.addAttribute(BlackboardAttribute(
                    self.att_event_time, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(wer_info['EventTime'])))
                self.log(
                    Level.INFO, "Copying 3rd att for .wer file of id " + str(file.getId()))

                reported_art.addAttribute(BlackboardAttribute(
                    self.att_app_path, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(wer_info['AppPath'])))
                self.log(
                    Level.INFO, "Copying 4th att for .wer file of id " + str(file.getId()))

                # adding dump file search result

                dmp = werExtractor.wer_extractor.find_dmp_files(
                    self.temp_wer_path)
                self.log(
                    Level.INFO, "Extracted dump files names from .wer file of id " + str(file.getId()))

                if not dmp or "Error" in dmp:
                    dmp = "None"
                else:
                    dmp = ', '.join(dmp)

                reported_art.addAttribute(BlackboardAttribute(
                    self.att_dump_files, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, dmp))
                self.log(
                    Level.INFO, "Copying 4th att for .wer file of id " + str(file.getId()))

                # Add artifact to Blackboard
                try:
                    # Index the artifact for keyword search
                    blackboard.indexArtifact(reported_art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " +
                             reported_art.getDisplayName())
                self.log(
                    Level.INFO, "Added artifact to blackboard for file of id " + str(file.getId()))

                # Fire an event to notify the UI and others that there is a new log artifact
                IngestServices.getInstance().fireModuleDataEvent(
                    ModuleDataEvent(LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName,
                                    self.art_reported_program, None))
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
                ContentUtils.writeToFile(file, File(self.temp_log_path))
                self.log(Level.INFO, "Copying .log file of id " +
                         str(file.getId()))

                # Get the parsed result
                log_info = logextractor.log_extractor.extract_ip_addresses(
                    self.temp_log_path)
                self.log(
                    Level.INFO, "Extracted .log file of id " + str(file.getId()))
                self.log(Level.INFO, "Log info size: " + str(len(log_info)))

                # Check if any error occurred
                error = log_info.get('Error')
                if error:
                    self.log(
                        Level.INFO, "ERROR: " + error + " at file of id: " + str(file.getId()))
                    return IngestModule.ProcessResult.OK

                # A standard log can have multiple artifacts
                # As long as it has more than one IP address registered
                # So let's iterate over the dictionary
                for (ip, counter) in log_info.iteritems():
                    # Create artifact
                    ip_art = file.newArtifact(self.art_logged_ip.getTypeID())
                    self.log(
                        Level.INFO, "Created new artifact of type art_logged_ip for file of id " + str(file.getId()))

                    # Add IP type
                    ip_type = self.get_ip_type(ip)
                    ip_art.addAttribute(BlackboardAttribute(
                        self.att_ip_type, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, ip_type))

                    # Add current domain
                    if(ip_type == 'Public'):
                        try:
                            ip_domain  = socket.gethostbyaddr(ip)[0]
                        except socket.herror as e:
                            ip_domain = 'Error: ' + str(e)
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

                    # Add counter to artifact
                    ip_art.addAttribute(BlackboardAttribute(
                        self.att_ip_counter, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, str(counter)))

                    # Add file path to artifact
                    ip_art.addAttribute(BlackboardAttribute(
                        self.att_case_file_path, LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName, file.getParentPath() + file.getName()))

                    # Add artifact to Blackboard
                    try:
                        # Index the artifact for keyword search
                        blackboard.indexArtifact(ip_art)
                    except Blackboard.BlackboardException as e:
                        self.log(Level.SEVERE, "Error indexing artifact " +
                                 ip_art.getDisplayName())
                    self.log(
                        Level.INFO, "Added artifact to blackboard for file of id " + str(file.getId()))

                    # Fire an event to notify the UI and others that there is a new log artifact
                    IngestServices.getInstance().fireModuleDataEvent(
                        ModuleDataEvent(LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName,
                                        self.art_logged_ip, None))

        return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    def shutDown(self):
        elapsed_time = time.time() - self.start_time
        self.log(Level.INFO, "LFA execution time: "+str(elapsed_time))
        # Inform user of number of files found
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                              LogForensicsForAutopsyFileIngestModuleWithUIFactory.moduleName,
                                              str(self.filesFound) + " total files found.")
        ingestServices = IngestServices.getInstance().postMessage(message)

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
        self.saveFlagSetting("checkLog", self.checkboxLog.isSelected())

    def checkBoxEventDmp(self, event):
        self.local_settings.setCheckDmp(self.checkboxDmp.isSelected())
        self.saveFlagSetting("checkDmp", self.checkboxDmp.isSelected())

    def checkBoxEventEVTx(self, event):
        self.local_settings.setCheckEVTx(self.checkboxEVTx.isSelected())
        self.saveFlagSetting("checkEVTx", self.checkboxEVTx.isSelected())

    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))

        self.labelCheckText = JLabel("Check for type files: ")
        self.labelCheckText.setEnabled(True)
        self.errorMessageLabel = JLabel(" ")
        self.infoMessageLabel = JLabel("Checking for domain needs internet access (.log IP addresses)")
        self.infoMessageLabel.setEnabled(True)
        self.errorMessageLabel.setEnabled(True)

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

        self.add(self.labelCheckText)
        self.add(self.checkboxWER)
        self.add(self.checkboxETL)
        self.add(self.checkboxLog)
        self.add(self.checkboxDmp)
        self.add(self.checkboxEVTx)
        self.add(self.errorMessageLabel)
        self.add(self.infoMessageLabel)

    def customizeComponents(self):
        self.checkDatabaseEntries()

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
            self.errorMessageLabel.setText("Error opening database!")

        try:
            stmt = dbConn.createStatement()
            query = 'SELECT * FROM settings WHERE id = 1;'
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
            self.errorMessageLabel.setText("Settings read successfully!")
        except SQLException as e:
            self.errorMessageLabel.setText("Could not read settings")

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
            self.errorMessageLabel.setText("Error opening settings")

        int_value = 1 if value else 0

        try:
            stmt = dbConn.createStatement()
            query = 'UPDATE settings SET ' + flag + \
                ' = ' + str(int_value) + ' WHERE id = 1;'

            stmt.executeUpdate(query)
            self.errorMessageLabel.setText("Saved setting")
        except SQLException as e:
            self.errorMessageLabel.setText("Error saving settings "+str(e))
        stmt.close()
        dbConn.close()
