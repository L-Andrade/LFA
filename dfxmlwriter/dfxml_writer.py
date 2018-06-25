# Simple and generic dfxml generator based on https://github.com/simsong/dfxml
# quite incomplete, for now it is done specifically for LFA

import sys
import os
import time
import traceback
import datetime
import platform
import time
import codecs

import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom


class DFXMLWriter:
    """
   constants are used to validate the amount of bounded subelements of an element and the orders to be followed
    """
    VOLUME_BOUNDED_ELEMENTS = ["partition_offset", "sector_size", "block_size", "ftype",
                               "ftype_str", "block_count", "first_block", "last_block", "allocated_only", "volume", "error"]

    FILEOBJECT_BOUNDED_ELEMENTS = ["parent_object", "error", "partition", "id", "name_type", "filesize", "unalloc", "alloc", "alloc_inode", "alloc_name", "used", "unused",
        "orphan", "compressed", "inode", "meta_type", "mode", "nlink", "uid", "gid", "mtime", "ctime", "atime", "crtime", "seq", "dtime", "bkup_time", "link_target", "libmagic"]

    MAIN_LIMITED = ["metadata","creator","source","fileobject","rusage"]
    MAIN_UNBOUNDED =["diskimageobject","partitionsystemobject","partitionobject","volume"]
    '''
    constructor:
    receives metadata_desc which is the description of what info this file will contain
    '''
    def __getCorrectPlacementIndex(self,node_tag):
        cNodes = list(self.dfxml)
        if(node_tag == 'source'):
            return cNodes.index(self.dfxml.findall('creator')[-1]) + 1
        if(node_tag in self.MAIN_UNBOUNDED and self.dfxml.findall(node_tag)):
            return cNodes.index(self.dfxml.findall(node_tag)[-1]) + 1 
        if(node_tag == 'rusage'):
            return cNodes.index(self.dfxml.findall('fileobject')[-1]) + 1
        if(node_tag =='premeta'):
            return 0
        if(node_tag == 'preinfo'):
            if(self.dfxml.find('source')):
                return cNodes.index(self.dfxml.findall('source')[-1]) + 1            
            return cNodes.index(self.dfxml.findall('creator')[-1]) + 1
        if(node_tag == 'postrusage'):
            if(self.dfxml.find('rusage')):
                return cNodes.index(self.dfxml.findall('rusage')[-1]) + 1
            return cNodes.index(self.dfxml.findall('fileobject')[-1]) + 1 
        if(node_tag == 'fileobject'):
            return cNodes.index(self.dfxml.findall('fileobject')[-1]) +1


    def prettify(self, elem):
        """Return a pretty-printed XML string for the Element.
        """
        rough_string = ET.tostring(elem, 'utf-8')
        reparsed = minidom.parseString(rough_string)
        return reparsed.toxml()

    def __init__(self, metadata_desc, programName=None, programVersion=None):
        # time intialization for timestamping purposes
        self.t0 = time.time()
        self.tlast = time.time()
        # creates xml and dfxml elemt
        self.dfxml = ET.Element('dfxml',{"version":"1.2.0", "xmlns":"http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML", "xmlns:dc":"http://purl.org/dc/elements/1.1/", "xmlns:dfxmlext":"http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML#extensions"})
        # creates metadata subEle
        meta = ET.SubElement(self.dfxml, 'metadata')
        ET.SubElement(meta,'description').text = metadata_desc
        # documentation for this further in the class
        self.__generateCreator(programName, programVersion)
        ET.SubElement(self.dfxml, 'diskimageobject').text = 'POSITION_HOLDING_NODE'
        ET.SubElement(self.dfxml, 'partitionsystemobject').text = 'POSITION_HOLDING_NODE'
        ET.SubElement(self.dfxml, 'partitionobject').text = 'POSITION_HOLDING_NODE'
        ET.SubElement(self.dfxml, 'volume').text = 'POSITION_HOLDING_NODE'
        ET.SubElement(self.dfxml, 'fileobject').text = 'POSITION_HOLDING_NODE'

    '''
    this function generates the 'source' sub-ele with the mandatory paramenter being the name of the data source
    '''

    def generateSource(self, image_filename,attribute = None):
        exSrc = self.dfxml.find('source')
        if (exSrc is not None):
            if(image_filename not in exSrc.findtext('image_filename')):
                ET.SubElement(exSrc, 'image_filename').text = image_filename
            return exSrc
        
        index = self.__getCorrectPlacementIndex('source')
        if(attribute is not None):
            src =ET.Element('source',attribute) 
            self.dfxml.insert(index,src)
        else:    
            src = ET.Element('source')
            self.dfxml.insert(index,src)
        ET.SubElement(src, 'image_filename').text = image_filename
        return src

    def generateRusage(self, rusageTuple):
        exRusage = self.dfxml.find('rusage')
        if (exRusage is not None):
            return exRusage
        rusage = ET.SubElement(self.dfxml, 'rusage')
        ET.SubElement(rusage, 'utime').text = rusageTuple['ru_utime']
        ET.SubElement(rusage, 'stime').text = rusageTuple['ru_stime']
        ET.SubElement(rusage, 'maxrss').text = rusageTuple['ru_maxrss']
        ET.SubElement(rusage, 'minflt').text = rusageTuple['ru_minflt']
        ET.SubElement(rusage, 'majflt').text = rusageTuple['ru_majflt']
        ET.SubElement(rusage, 'nswap').text = rusageTuple['ru_nswap']
        ET.SubElement(rusage, 'inblock').text = rusageTuple['ru_inblock']
        ET.SubElement(rusage, 'oublock').text = rusageTuple['ru_oublock']
        return rusage

        
    '''
    generates a new 'volume' node, byte-offset mandatory
    '''

    def generateVolume(self, offset,node =None):
        if(node is None):
            for vol in self.dfxml.findall('volume'):
                if(vol.get('offset') == offset):
                    return vol
            index = self.__getCorrectPlacementIndex('volume')
            vol = ET.Element('volume',{"offset":offset})
            self.dfxml.insert(index,vol)
            return vol        

    def generateDiskimageobject(self,node,attribute=None):
        if(node is None):
            index = self.__getCorrectPlacementIndex('diskimageobject')
            if(attribute is not None):
                dio = ET.Element('diskimageobject',attribute)
            else:
                dio = ET.Element('diskimageobject')
            self.dfxml.insert(index,dio)
            return dio        

    def generatePartitionsystemobject(self,node,attribute=None):
        if(node is None):
            index = self.__getCorrectPlacementIndex('partitionsystemobject')
            if(attribute is not None):
                pso = ET.Element('partitionsystemobject',attribute)
            else:
                pso = ET.Element('partitionsystemobject')
            self.dfxml.insert(index,pso)
            return pso        
    
    def generatePartitionobject(self,node,attribute=None):
        if(node is None):
            index = self.__getCorrectPlacementIndex('partitionobject')
            if(attribute is not None):
                po = ET.Element('partitionobject',attribute)
            else:
                po = ET.Element('partitionobject')
            self.dfxml.insert(index,po)
            return po        
        
        


    '''
    generic addition of a sub-ele into another element
    PARAMS:
        node - the parent node which the child node will be created
        name - name of the child node to be created
        val - value of the created node
        attribute - when passed, will create the node with the passed attribute. format ['attribute name','attribute value']

    '''

    def addParamsToNode(self, node, name, val, attribute=None):
        switcher = {
            "volume": self.__addElementToVolume,
            "fileobject": self.__addElementToFileObj,
            "source": self.__addElementToSource
        }
        # Get the function from switcher dictionary
        func = switcher.get(node.tag, self.__addParamsToGenericNode)
        print node.tag
        # Execute the function
        return func(node, name, val, attribute)



    def __addParamsToGenericNode(self, node, name, val, attribute=None):    
        if attribute is not None:
            newNode = ET.SubElement(node, name, attribute).text = val  # only works with one attribute for now, modify if more is needed
        else:
            newNode = ET.SubElement(node, name).text = val
        return newNode


    def __addElementToVolume(self, node, name, val, attribute=None):
        if (name in self.VOLUME_BOUNDED_ELEMENTS and node.find(name) is not None):
            raise RuntimeError(
                'The {} element already exists in this volume node and only one of its type is allowed'.format(name))
        return self.__addParamsToGenericNode(node,name,val,attribute)

    def __addElementToFileObj(self, node, name, val, attribute=None):
        if (name in self.FILEOBJECT_BOUNDED_ELEMENTS and node.find(name) is not None):
            raise RuntimeError(
                'The {} element already exists in this fileObject node and only one of its type is allowed'.format(name))
        return self.__addParamsToGenericNode(node,name,val,attribute)

    def __addElementToSource(self, node, name, val, attribute=None):
        if(name != "image_filename"):
            raise RuntimeError('Source element only accepts image_filename elements')
        return self.__addParamsToGenericNode(node,name,val)




            

    '''
    generates the Creator node, which contains information about the environment used to make the analysis
    '''

    def __generateCreator(self, programName, programVersion):
        creator = ET.SubElement(self.dfxml, 'creator')

        if(not (programName is None or programVersion is None)):
            ET.SubElement(creator, 'program').text = programName
            ET.SubElement(
                creator, 'version').text = programVersion

        # what was used to run the code
        be = ET.SubElement(creator, 'build_environment')
        ET.SubElement(be, 'compiler').text = platform.python_compiler()
       

        # environment in which the info was processed
        ee = ET.SubElement(creator, 'execution_environment')
        uname = platform.uname()
        uname_fields = ['os_sysname', 'host',
                        'os_release', 'os_version', 'arch']
        for i in range(len(uname_fields)):
            ET.SubElement(ee, uname_fields[i]).text = uname[i]
        ET.SubElement(ee, 'uid').text = self.__getUid()
        ET.SubElement(ee, 'username').text = os.getenv('username')
        ET.SubElement(
            ee, 'start_time').text = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ%z')

    def addLibraryToCreator(self, name, version, attribute=None):
        creator = self.dfxml.find('creator')
        if (creator is not None):
            if(attribute is not None):
                lib = ET.SubElement(creator, 'library', attribute)
            else:
                lib = ET.SubElement(creator, 'library')
            ET.SubElement(lib, 'name').text = name
            ET.SubElement(lib, 'version').text = version
            return True
        return False
    '''
    creates a 'fileobject' node in the specified parent node and its sub-element according to what was passed through params_dict
    params_dict should be a dictionary, the key is the name of the element, the value is the value the element, multiple pairs may be added

    '''

    def newFileObject(self, params_dict={}, parent=None,attribute =None):
        if(parent is None):
            if(attribute is not None):
                fileO = ET.Element('fileobject',attribute)
            else:
                fileO = ET.Element('fileobject')
            for name, val in params_dict.iteritems():
                if(name in self.FILEOBJECT_BOUNDED_ELEMENTS and name in fileO.keys()):
                    raise RuntimeError(
                        'The {} key was sent more than once'.format(name))
                ET.SubElement(fileO, name).text = val
            i = self.__getCorrectPlacementIndex('fileobject')
            self.dfxml.insert(i,fileO)
            return fileO

        fileO = ET.SubElement(parent, 'fileobject')
        for name in self.FILEOBJECT_BOUNDED_ELEMENTS:
            if(name in params_dict):
                ET.SubElement(fileO, name).text = params_dict[name]
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
        f.close()

    '''
    writes the contents of the xml into a file, fname can be an absolute or a relative path
    '''

    def writeToFile(self, fname):
        #self.timestamp('totalDuration')
        for node in list(self.dfxml):
            if(node.text =='POSITION_HOLDING_NODE'):
                self.dfxml.remove(node)

        self.write(codecs.open(fname, "w","utf-8"))

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
        elif os.name == 'java':
            return 'java'
        else:
            raise RuntimeError, "Unsupported operating system for this module: %s" % (
                os.name,)
