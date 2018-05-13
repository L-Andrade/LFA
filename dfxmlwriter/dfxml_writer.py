# Simple and generic dfxml generator based on https://github.com/simsong/dfxml
# quite incomplete, for now it is done specifically for LFA

import sys
import os
import time
import traceback
import datetime
import platform
import time

import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom


class DFXMLWriter:
    ''' 
    constructor:
    receives metadata_desc which is the description of what info this file will contain
    '''

    def prettify(self,elem):
        """Return a pretty-printed XML string for the Element.
        """
        rough_string = ET.tostring(elem, 'utf-8')
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="\t")

    def __init__(self, metadata_desc):
        # time intialization for timestamping purposes
        self.t0 = time.time()
        self.tlast = time.time()
        # creates xml and dfxml elemt
        self.dfxml = ET.Element('dfxml')
        # creates metadata subEle
        ET.SubElement(self.dfxml, 'metadata').text = metadata_desc
        # documentation for this further in the class
        self.generateCreator()

    '''
    this function generates the 'source' sub-ele with the mandatory paramenter being the name of the data source
    '''

    def generateSource(self, image_filename):
        exSrc=self.dfxml.find('source')
        if (exSrc is not None):
            if(image_filename not in exSrc.findtext('image_filename')):
                ET.SubElement(exSrc, 'image_filename').text = image_filename    
            return exSrc
        src = ET.SubElement(self.dfxml, 'source')
        ET.SubElement(src, 'image_filename').text = image_filename
        return src

    '''
    generic addition of a sub-ele into another element
    PARAMS:
        node - the parent node which the child node will be created 
        name - name of the child node to be created
        val - value of the created node
        attribute - when passed, will create the node with the passed attribute. format ['attribute name','attribute value']

    '''

    def addParamsToNode(self, node, name, val, attribute=None):
        if attribute:
            newNode = ET.SubElement(
                node, name, {attribute[0]: attribute[1]}).text = val  # only works with one attribute for now, modify if more is needed
        else:
            newNode = ET.SubElement(node, name).text = val
        return newNode

    '''
    generates a new 'volume' node, byte-offset mandatory
    '''

    def generateVolume(self, offset):
        
        for vol in self.dfxml.findall('volume'):
            if(vol.get('offset') == offset):
                return vol
        return ET.SubElement(self.dfxml, 'volume', {'offset': offset})

    '''
    generates the Creator node, which contains information about the machine used to make the analysis
    '''

    def generateCreator(self):
        creator = ET.SubElement(self.dfxml, 'creator')

        ET.SubElement(creator, 'program').text = 'SleuthKit Autospy Module LFA'
        ET.SubElement(
            creator, 'version').text = 'TODO: when used on module, put versions here'  # TODO

        # what was used to run the code
        be = ET.SubElement(creator, 'build_environment')
        ET.SubElement(be, 'compiler').text = platform.python_compiler()
        ET.SubElement(be, 'build').text = 'Python '+platform.python_build()[0]

        # environment in which the info was processed
        ee = ET.SubElement(creator, 'execution_enviornment')
        uname = platform.uname()
        uname_fields = ['os_sysname', 'host',
                        'os_release', 'os_version', 'arch']
        for i in range(len(uname_fields)):
            ET.SubElement(ee, uname_fields[i]).text = uname[i]
        # ET.SubElement(ee, 'uid').text = self.__getUid()
        ET.SubElement(ee, 'username').text = os.getenv('username')
        ET.SubElement(
            ee, 'start_time').text = datetime.datetime.now().isoformat()

    '''
    creates a 'fileobject' node in the specified parent node and its sub-element according to what was passed through params_dict 
    params_dict should be a dictionary, the key is the name of the element, the value is the value the element, multiple pairs may be added 
    
    '''

    def newFileObject(self, params_dict, parent):
        fileO = ET.SubElement(parent, 'fileobject')
        for name, val in params_dict.iteritems():
            ET.SubElement(fileO, name).text = val
        return fileO

    '''
    creates new hashdigest sub-element into specified fileobject node

    TODO:FURTHER VALIDATION, FOR NOW THIS IS SAME AS addParamsToNode
    '''

    def addHashDigestToFO(self, fo, hash_info):
        ET.SubElement(fo, 'hashdigest', {
                      'type': hash_info[0]}).text = hash_info[1]

    '''
    writes timestamp values into the xml
    it can be named, it will have the total time and the delta between the last timestamp
    '''

    def timestamp(self, name):
        now = time.time()
        ET.SubElement(self.dfxml, 'timestamp', {'name': name,
                                                'delta': str(now - self.tlast),
                                                'total': str(now - self.t0)})
        self.tlast = now

    '''
    adds a comment into the xml
    '''

    def comment(self, s):
        self.dfxml.insert(len(list(self.dfxml)), ET.Comment(s))

    # helper function, should not be called directly
    def asString(self):
        return self.prettify(self.dfxml)

    # helper function, should not be called directly
    def write(self, f):
        f.write(self.asString())

    '''
    writes the contents of the xml into a file, fname can be an absolute or a relative path
    '''

    def writeToFile(self, fname):
        self.timestamp('totalDuration')
        self.write(open(fname, "w"))

    # helper function do not call directly
    # some trickier stuff to get the user SID on windows systems or UID on *nix systems
    def __getUid(self):
        # nt means it is a windows system
        if os.name == 'nt':
            import codecs
            os.system("wmic useraccount where name='{}' get sid > sid.txt".format(
                os.getenv('username')))
            f = codecs.open('sid.txt', 'r', encoding='utf-16-le').readlines()
            if os.path.isfile('sid.txt'):
                os.remove('sid.txt')
            return f[1].encode('utf-8').replace('\n', '').replace('\r', '').replace('\t', '').replace(' ', '')

        elif os.name == 'posix':
            return os.getuid()

        else:
            raise RuntimeError, "Unsupported operating system for this module: %s" % (
                os.name,)
