#!/usr/bin/env python

##########
#
#quickEvalOfficeDoc
#Author: Rod Chubb
#Rev: quickEvalOfficeDoc_rev.12042016Final.py
#
##########


from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
import argparse
import hashlib
import os
import re
import string
import sys


#utf-8
reload(sys)
sys.setdefaultencoding('utf-8')


#command line
parser = argparse.ArgumentParser(description='Provides information about an MS Office document. This information can be used to determine if the document in question is of a malicious nature.')
parser.add_argument('inputFile', metavar='input_file', nargs=1,
                    help='Input File(File that is going to be Examined)')

args = parser.parse_args()


#Variables
BLOCKSIZE = 65536
inputFileArgument = args.inputFile #This creates a list, the list item needs to be converted to a string
inputFileName = inputFileArgument[0]
inputFileExtension = os.path.splitext(inputFileName)[1][1:].strip()
nameOfCurrentScript = os.path.basename(__file__)
newMsOfficeFileFormatExtensions = ['docx','docm','dotx','dotm','docb','xlsx','xlsm','xltx','xltm','pptx','pptm','potx','potm','ppam','ppsx','ppsm','sldx','sldm']
newMsOfficeFileFormatSignature = "\x50\x4b\x03\x04\x14\x00\x06\x00"
oldMsOfficeFileFormatExtensions = ['doc','dot','wbk','xls','xlt','xlm','ppt','pot','pps']
oldMsOfficeFileFormatSignature = "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


class scriptBanner():
    #writes the script's banner


    def banner(self):
        print '*'*80
        print nameOfCurrentScript
        print '-'*80




class fileAttributes():
    #used to obtain some of the subject files attributes


    def fileName(self):
        #used to print file name
        print 'File Name: %s' %(inputFileName)


    def md5(self):
        #used to calculate/print the md5 hash
        md5hasher = hashlib.md5()
        with open(inputFileName, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                md5hasher.update(buf)
                buf = afile.read(BLOCKSIZE)
        md5hash = (md5hasher.hexdigest())
        print 'md5 hash: %s' %(md5hash)
        afile.close()


    def sha1(self):
        #used to calculate/print the sha1 hash
        sha1hasher = hashlib.sha1()
        with open(inputFileName, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                sha1hasher.update(buf)
                buf = afile.read(BLOCKSIZE)
        sha1hash = (sha1hasher.hexdigest())
        print 'sha1 hash: %s' %(sha1hash)
        afile.close()


    def sha256(self):
        #used to calculate/print the sha256 hash
        sha256hasher = hashlib.sha256()
        with open(inputFileName, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                sha256hasher.update(buf)
                buf = afile.read(BLOCKSIZE)
        sha256hash = (sha256hasher.hexdigest())
        print 'sha256 hash: %s' %(sha256hash)
        afile.close()




class inputFileId():
    #used to match file extension to magic number


    def fileExtensionInfo(self):
        #prints the file extension
        print 'The file extension is: %s' %(inputFileExtension)


    def signatureExamination(self):
        #locates the file signature, confirms that it is located in the beginning of the file
        with open(inputFileName, 'rb') as afile:

            if inputFileExtension in newMsOfficeFileFormatExtensions:
                regexSignature = re.compile(newMsOfficeFileFormatSignature)
                for match_obj in regexSignature.finditer(afile.read(10)):
                    beginOffset = match_obj.start()
                    endOffset = match_obj.end()
                    print 'Signature begins at hex offset: ' + hex(beginOffset)
                    print 'Signature ends at hex offset: ' + hex(endOffset)
                    print 'The file signature is: ' + newMsOfficeFileFormatSignature.encode("hex") 
                    #The line above needs to be revised so that it opens the file in hex and prints 
                    #the first 2 bytes. Want this to scrape from actual file.
                    print 'The file signature confirms the file extension'
                    afile.close()

            elif inputFileExtension in oldMsOfficeFileFormatExtensions:
                regexSignature = re.compile(oldMsOfficeFileFormatSignature)
                for match_obj in regexSignature.finditer(afile.read(10)):
                    beginOffset = match_obj.start()
                    endOffset = match_obj.end()
                    print 'The file signature is: ' + oldMsOfficeFileFormatSignature.encode("hex")
                    #The line above needs to be revised so that it opens the file in hex and prints 
                    #the first 2 bytes. Want this to scrape from the actual file.
                    print 'The file signature confirms the file extension'
                    afile.close()

            else: 
                print '\nThe submitted file is not an MS Office Document or the signature and file extension do not match.\nPlease investigate using manual methods.'
                afile.close()




class oletoolsProcessing():
    #class used to access oletools

    def olevbaProcessing(self):
        count = 0
        inputFileNameFileData = open(inputFileName, 'rb').read()
        vbaparser = VBA_Parser(inputFileName, data=inputFileNameFileData)
        if vbaparser.detect_vba_macros():
            print '*'*80
            print '[+] VBA Macros found'
            print '-'*80
            for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_all_macros():
                count += 1
                if count == 1:
                    print 'Macro#%d\n' %(count)
                    print 'Filename: ', filename
                    print 'OLE Stream: ', stream_path
                    print 'VBA Filename: ', vba_filename
                    print '-'*10
                    print vba_code
                else:
                    print '-'*80
                    print 'Macro#%d\n' %(count)
                    print 'Filename: ', filename
                    print 'OLE Stream: ', stream_path
                    print 'VBA Filename: ', vba_filename
                    print '-'*10
                    print vba_code
                    print '*'*80
        else:
            print '*'*80
            print '[-] No VBA Macros were found'
            print '*'*80




class stringProcessing():
    #class used to acess strings

    def stringExtraction(self):
        print '[+] Strings'
        print '-'*80
        chars = r"A-Za-z0-9/\-:.,_$%'()[\]<>!@?+=*&^#{}|;~` "
        shortest_run = 4
        
        regexp = '[%s]{%d,}' % (chars, shortest_run)
        pattern = re.compile(regexp)
        
        data = open(inputFileName, 'rb').read()
        strings = pattern.findall(data)
        for string in strings:
            print string
        print '*'*80




#builds the report
scriptBanner().banner()

fileAttributes().fileName()
fileAttributes().md5()
fileAttributes().sha1()
fileAttributes().sha256()

inputFileId().fileExtensionInfo()
inputFileId().signatureExamination()

oletoolsProcessing().olevbaProcessing()

stringProcessing().stringExtraction()
