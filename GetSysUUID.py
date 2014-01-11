###############################################################################
## File       :  GetSysUUID.py
## Description:  Pythonic way to extract the SYSUUID from the SMBIOS for 
##            :  OSX, Linux and Windows on both 32 & 64 bit architectures
## Created_On :
##
## License    :  LGPL
##
## (c) Copyright 2012, Rich Smith all rights reserved.
###############################################################################
import sys
import subprocess
import hashlib

if sys.platform == "win32":
    import ctypes
    import ctypes.wintypes
    import struct

class GetSysUUID(object):
    """
    For supported platforms get some notion of a unique ID
    """
    def __init__(self, p_anonymous = False):
        """
        IN : p_anonymous - whether to create a psuedo-anonymous value instead
                           of returning the actuall UUID - Boolean
        """
        
        self.supported_platforms = {
                                    "linux2": self._get_linux_uuid,
                                    "darwin": self._get_darwin_uuid,
                                    "win32" : self._get_win32_uuid
                                   }
        
        self.p_anonymous         = p_anonymous
        

    def __call__(self):
        """
        Call appropriate function to get a platform UUID for the current platform
        
        OUT : UUID - formatted - string
        """
        try:
            self.supported_platforms[sys.platform]()
        except KeyError:
            raise GetUUIDError("Unsupported Platform")
        
        ##Return the actual UUID or a hash of it
        if self.p_anonymous:
            self.uuid = hashlib.md5(self.uuid).hexdigest()
            print "MD5 (UUID): %s"%self.uuid
        else:
            print "UUID: %s"%self.uuid

        return self.uuid
    
    
    def _get_linux_uuid(self):
        """
        Get an ID for a linux system using the dmidecode command
        Need to have root privs for this
        """
        #Check privs ?
        try:
            ret = subprocess.Popen(["dmidecode", "--type", "1"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE).stdout.readlines()
        except:
            raise GetUUIDError("Bad command passed")
        
        uuid = None
        for line in ret:
            if "UUID" in line:
                line      = line.replace(" ","")
                pos       = line.find(":")
                self.uuid = line[pos+1:].strip()
        
        if not self.uuid:
            raise GetUUIDError("Could not find UUID")   
    
    
    def _get_darwin_uuid(self):
        """
        Get an ID for a OS X system using the IO Registry
        and the IOPlatformUUID value
        """
        try:
            ret = subprocess.Popen(["ioreg", "-rd1", "-cIOPlatformExpertDevice"], 
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE).stdout.readlines()
        except:
            raise GetUUIDError("Bad command passed")
        
        for line in ret:
            if "PlatformUUID" in line:
                line      = line.replace(" ","").replace('"',"")
                pos       = line.find("=")
                self.uuid = line[pos+1:].strip()
    
        
    def _get_win32_uuid(self):
        """
        Rather than use WNI which requires the win32 extensions we use
        raw ctypes and call the GetSystemFirmwareTable 
        (http://msdn.microsoft.com/en-us/library/ms724379%28VS.85%29.aspx)
        function and then parse the raw SMBIOS table to the UUID.
        """
        ##1381190978 == 'RSMB'
        FirmwareTableSig = ord('R')
        FirmwareTableSig = FirmwareTableSig << 8 | ord("S")
        FirmwareTableSig = FirmwareTableSig << 8 | ord("M")
        FirmwareTableSig = FirmwareTableSig << 8 | ord("B")
        
        kernel32 = ctypes.windll.kernel32
        if kernel32 == None:
            raise GetUUIDError("cant load kernel32.dll")

        ##The function
        get_fw = kernel32.GetSystemFirmwareTable
        
        ##Get the size of the SMBIOS so we can allocate correctly
        bios_size = get_fw(ctypes.wintypes.DWORD(1381190978), 0, 0, 0)
        
        ##Buffer for BIOS to be written to
        FirmwareTableBuf = ctypes.create_string_buffer("\000"*bios_size)
        
        ##Now actually dump the Raw SMBIOS table
        ret = get_fw(ctypes.wintypes.DWORD(FirmwareTableSig),
                     0, FirmwareTableBuf, 0x1eba) 
        
        if ctypes.GetLastError() != 0: 
            raise GetUUIDError(ctypes.FormatError(ctypes.GetLastError()) )
        
        ##Remove the 8 byte header MS seems to append
        SMBIOSTableData = FirmwareTableBuf.raw[8:]
        
        ##Now parse the SMBIOS table
        parse_bios = ParseSMBIOSTable(SMBIOSTableData)
        parse_bios()
        
        ##Format the UUID into the standard string repr
        raw_uuid  = parse_bios.type1_data["UUID"]
        self.uuid = "%x%x%x%x-%x%x-%x%x-%x%x-%x%x%x%x%x%x"%(raw_uuid[0],
                                                            raw_uuid[1],
                                                            raw_uuid[2],
                                                            raw_uuid[3],
                                                            raw_uuid[4],
                                                            raw_uuid[5],
                                                            raw_uuid[6],
                                                            raw_uuid[7],
                                                            raw_uuid[8],
                                                            raw_uuid[9],
                                                            raw_uuid[10],
                                                            raw_uuid[11],
                                                            raw_uuid[12],
                                                            raw_uuid[13],
                                                            raw_uuid[14],
                                                            raw_uuid[15])
        
        
class ParseSMBIOSTable:
    
    def __init__(self, SMBIOSTableData):
        
        self.table_data = {}
        
        self.SMBIOSTableData = SMBIOSTableData
        
    def __call__(self):
        """
        Walk the raw SMBIOS structure and separate records, then 
        parse standard sections, all as defined in 'System Management BIOS 
        Reference Specification, v2.6.1 DMTF Standard'
        (http://www.dmtf.org/standards/published_documents/DSP0134_2.6.1.pdf)
        """
        self.walk_structure()
        
        ##Now parse out the data into a more usable form
        #ONLY parse the System Information (Type 1) at the moment
        self.parse_type1()
        
    def walk_structure(self):
        """
        Walk the structure and seperate into sub structures
        """
        while 1:
            try:
                formatted_len = struct.unpack("<B", self.SMBIOSTableData[1] )[0]
            except IndexError:
                ##Reached the end of the structure
                break
            
            handle = struct.unpack("<H", self.SMBIOSTableData[2:4] )[0]
            
            unformatted_len = self.SMBIOSTableData[formatted_len:].find(struct.pack("<H", 0)) +2
            
            self.table_data[handle] = self.SMBIOSTableData[: formatted_len + unformatted_len]
            
            self.SMBIOSTableData = self.SMBIOSTableData[formatted_len + unformatted_len:]
        
     
    def parse_type1(self):
        """
        From the System Information (Type 1) structure seperate into component
        data chunks
        """
        raw_data        = self.table_data[1]
        self.type1_data = {}
          
        self.type1_data["Length"]        = struct.unpack("<B",   raw_data[1])[0]
        self.type1_data["Handle"]        = struct.unpack("<H",   raw_data[2:4])[0]
        self.type1_data["Manufacturer"]  = struct.unpack("<B",   raw_data[5])[0]
        self.type1_data["Product Name"]  = struct.unpack("<B",   raw_data[6])[0]
        self.type1_data["Version"]       = struct.unpack("<B",   raw_data[7])[0]
        self.type1_data["Serial Number"] = struct.unpack("<B",   raw_data[8])[0]
        self.type1_data["UUID"]          = struct.unpack("<16B", raw_data[8:24])
        self.type1_data["Wake-up Type"]  = struct.unpack("<B",   raw_data[25])[0]
        try:
            self.type1_data["SKU Number"]    = struct.unpack("<B",   raw_data[26])[0]
            self.type1_data["Family"]        = struct.unpack("<B",   raw_data[27])[0]
        except IndexError:
            pass
            
if __name__ == "__main__":
    
    uuid = GetSysUUID()
    uuid()
        
        