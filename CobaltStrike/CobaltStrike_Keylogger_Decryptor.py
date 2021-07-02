import dpkt
import optparse
import sys
import os
import zipfile
import binascii
import random
import gzip
import collections
import glob
import textwrap
import re
import struct
import string
import math
import fnmatch
import json
import time
import csv
import hashlib
import hmac
import Crypto.Cipher.AES

__description__ = 'Extract key from Cobalt Strike beacon process dump and decrypt keylogger output'
__author__ = 'Didier Stevens modified Insikt (Justin Grosfelt)'
__version__ = '0.0.2'
__date__ = '2021/06/22'

FCH_FILENAME = 0
FCH_DATA = 1
FCH_ERROR = 2

DEFAULT_SEPARATOR = ','
QUOTE = '"'

CS_FIXED_IV = b'abcdefghijklmnop'


# CIC: Call If Callable
def CIC(expression):
    if callable(expression):
        return expression()
    else:
        return expression

# IFF: IF Function
def IFF(expression, valueTrue, valueFalse):
    if expression:
        return CIC(valueTrue)
    else:
        return CIC(valueFalse)

def CutData(stream, cutArgument):
    if cutArgument == '':
        return [stream, None, None]

    typeLeft, valueLeft, typeRight, valueRight = ParseCutArgument(cutArgument)

    if typeLeft == None:
        return [stream, None, None]

    if typeLeft == CUTTERM_NOTHING:
        positionBegin = 0
    elif typeLeft == CUTTERM_POSITION:
        positionBegin = valueLeft
    elif typeLeft == CUTTERM_FIND:
        positionBegin = Find(stream, valueLeft[0], valueLeft[1])
        if positionBegin == -1:
            return ['', None, None]
        positionBegin += valueLeft[2]
    else:
        raise Exception("Unknown value typeLeft")

    if typeRight == CUTTERM_NOTHING:
        positionEnd = len(stream)
    elif typeRight == CUTTERM_POSITION and valueRight < 0:
        positionEnd = len(stream) + valueRight
    elif typeRight == CUTTERM_POSITION:
        positionEnd = valueRight + 1
    elif typeRight == CUTTERM_LENGTH:
        positionEnd = positionBegin + valueRight
    elif typeRight == CUTTERM_FIND:
        positionEnd = Find(stream, valueRight[0], valueRight[1], positionBegin)
        if positionEnd == -1:
            return ['', None, None]
        else:
            positionEnd += len(valueRight[0])
        positionEnd += valueRight[2]
    else:
        raise Exception("Unknown value typeRight")

    return [stream[positionBegin:positionEnd], positionBegin, positionEnd]

def FilenameCheckHash(filename, literalfilename):
    if literalfilename:
        return FCH_FILENAME, filename
    elif filename.startswith('#h#'):
        result = Hex2Bytes(filename[3:].replace(' ', ''))
        if result == None:
            return FCH_ERROR, 'hexadecimal'
        else:
            return FCH_DATA, result
    elif filename.startswith('#b#'):
        try:
            return FCH_DATA, binascii.a2b_base64(filename[3:])
        except:
            return FCH_ERROR, 'base64'
    elif filename.startswith('#e#'):
        result = Interpret(filename[3:])
        if result == None:
            return FCH_ERROR, 'expression'
        else:
            return FCH_DATA, C2BIP3(result)
    elif filename.startswith('#p#'):
        result = ParsePackExpression(filename[3:])
        if result == None:
            return FCH_ERROR, 'pack'
        else:
            return FCH_DATA, result
    elif filename.startswith('#'):
        return FCH_DATA, C2BIP3(filename[1:])
    else:
        return FCH_FILENAME, filename

def PrintError(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def ProcessAt(argument):
    if argument.startswith('@'):
        strings = File2Strings(argument[1:])
        if strings == None:
            raise Exception('Error reading %s' % argument)
        else:
            return strings
    else:
        return [argument]

class cBinaryFile:
    def __init__(self, filename, zippassword='infected', noextraction=False, literalfilename=False):
        self.filename = filename
        self.zippassword = zippassword
        self.noextraction = noextraction
        self.literalfilename = literalfilename
        self.oZipfile = None
        self.extracted = False
        self.fIn = None

        fch, data = FilenameCheckHash(self.filename, self.literalfilename)
        if fch == FCH_ERROR:
            line = 'Error %s parsing filename: %s' % (data, self.filename)
            raise Exception(line)

        try:
            if self.filename == '':
                if sys.platform == 'win32':
                    import msvcrt
                    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
                self.fIn = sys.stdin
            elif fch == FCH_DATA:
                self.fIn = DataIO(data)
            elif not self.noextraction and self.filename.lower().endswith('.zip'):
                self.oZipfile = zipfile.ZipFile(self.filename, 'r')
                if len(self.oZipfile.infolist()) == 1:
                    self.fIn = self.oZipfile.open(self.oZipfile.infolist()[0], 'r', self.zippassword)
                    self.extracted = True
                else:
                    self.oZipfile.close()
                    self.oZipfile = None
                    self.fIn = open(self.filename, 'rb')
            elif not self.noextraction and self.filename.lower().endswith('.gz'):
                self.fIn = gzip.GzipFile(self.filename, 'rb')
                self.extracted = True
            else:
                self.fIn = open(self.filename, 'rb')
        except:
            AnalyzeFileError(self.filename)
            raise

    def close(self):
        if self.fIn != sys.stdin and self.fIn != None:
            self.fIn.close()
        if self.oZipfile != None:
            self.oZipfile.close()

    def read(self, size=None):
        try:
            fRead = self.fIn.buffer
        except:
            fRead = self.fIn
        if size == None:
            return fRead.read()
        else:
            return fRead.read(size)

    def Data(self):
        data = self.read()
        self.close()
        return data


class cExpandFilenameArguments():
    def __init__(self, filenames, literalfilenames=False, recursedir=False, checkfilenames=False, expressionprefix=None, flagprefix=None):
        self.containsUnixShellStyleWildcards = False
        self.warning = False
        self.message = ''
        self.filenameexpressionsflags = []
        self.expressionprefix = expressionprefix
        self.flagprefix = flagprefix
        self.literalfilenames = literalfilenames

        expression = ''
        flag = ''
        if len(filenames) == 0:
            self.filenameexpressionsflags = [['', '', '']]
        elif literalfilenames:
            self.filenameexpressionsflags = [[filename, '', ''] for filename in filenames]
        elif recursedir:
            for dirwildcard in filenames:
                if expressionprefix != None and dirwildcard.startswith(expressionprefix):
                    expression = dirwildcard[len(expressionprefix):]
                elif flagprefix != None and dirwildcard.startswith(flagprefix):
                    flag = dirwildcard[len(flagprefix):]
                else:
                    if dirwildcard.startswith('@'):
                        for filename in ProcessAt(dirwildcard):
                            self.filenameexpressionsflags.append([filename, expression, flag])
                    elif os.path.isfile(dirwildcard):
                        self.filenameexpressionsflags.append([dirwildcard, expression, flag])
                    else:
                        if os.path.isdir(dirwildcard):
                            dirname = dirwildcard
                            basename = '*'
                        else:
                            dirname, basename = os.path.split(dirwildcard)
                            if dirname == '':
                                dirname = '.'
                        for path, dirs, files in os.walk(dirname):
                            for filename in fnmatch.filter(files, basename):
                                self.filenameexpressionsflags.append([os.path.join(path, filename), expression, flag])
        else:
            for filename in list(collections.OrderedDict.fromkeys(sum(map(self.Glob, sum(map(ProcessAt, filenames), [])), []))):
                if expressionprefix != None and filename.startswith(expressionprefix):
                    expression = filename[len(expressionprefix):]
                elif flagprefix != None and filename.startswith(flagprefix):
                    flag = filename[len(flagprefix):]
                else:
                    self.filenameexpressionsflags.append([filename, expression, flag])
            self.warning = self.containsUnixShellStyleWildcards and len(self.filenameexpressionsflags) == 0
            if self.warning:
                self.message = "Your filename argument(s) contain Unix shell-style wildcards, but no files were matched.\nCheck your wildcard patterns or use option literalfilenames if you don't want wildcard pattern matching."
                return
        if self.filenameexpressionsflags == [] and (expression != '' or flag != ''):
            self.filenameexpressionsflags = [['', expression, flag]]
        if checkfilenames:
            self.CheckIfFilesAreValid()

    def Glob(self, filename):
        if not ('?' in filename or '*' in filename or ('[' in filename and ']' in filename)):
            return [filename]
        self.containsUnixShellStyleWildcards = True
        return glob.glob(filename)

    def CheckIfFilesAreValid(self):
        valid = []
        doesnotexist = []
        isnotafile = []
        for filename, expression, flag in self.filenameexpressionsflags:
            hashfile = False
            try:
                hashfile = FilenameCheckHash(filename, self.literalfilenames)[0] == FCH_DATA
            except:
                pass
            if filename == '' or hashfile:
                valid.append([filename, expression, flag])
            elif not os.path.exists(filename):
                doesnotexist.append(filename)
            elif not os.path.isfile(filename):
                isnotafile.append(filename)
            else:
                valid.append([filename, expression, flag])
        self.filenameexpressionsflags = valid
        if len(doesnotexist) > 0:
            self.warning = True
            self.message += 'The following files do not exist and will be skipped: ' + ' '.join(doesnotexist) + '\n'
        if len(isnotafile) > 0:
            self.warning = True
            self.message += 'The following files are not regular files and will be skipped: ' + ' '.join(isnotafile) + '\n'

    def Filenames(self):
        if self.expressionprefix == None:
            return [filename for filename, expression, flag in self.filenameexpressionsflags]
        else:
            return self.filenameexpressionsflags

class cLogfile():
    def __init__(self, keyword, comment):
        self.starttime = time.time()
        self.errors = 0
        if keyword == '':
            self.oOutput = None
        else:
            self.oOutput = cOutput('%s-%s-%s.log' % (os.path.splitext(os.path.basename(sys.argv[0]))[0], keyword, self.FormatTime()))
        self.Line('Start')
        self.Line('UTC', '%04d%02d%02d-%02d%02d%02d' % time.gmtime(time.time())[0:6])
        self.Line('Comment', comment)
        self.Line('Args', repr(sys.argv))
        self.Line('Version', __version__)
        self.Line('Python', repr(sys.version_info))
        self.Line('Platform', sys.platform)
        self.Line('CWD', repr(os.getcwd()))

    @staticmethod
    def FormatTime(epoch=None):
        if epoch == None:
            epoch = time.time()
        return '%04d%02d%02d-%02d%02d%02d' % time.localtime(epoch)[0:6]

    def Line(self, *line):
        if self.oOutput != None:
            self.oOutput.Line(MakeCSVLine((self.FormatTime(), ) + line, DEFAULT_SEPARATOR, QUOTE))

    def LineError(self, *line):
        self.Line('Error', *line)
        self.errors += 1

    def Close(self):
        if self.oOutput != None:
            self.Line('Finish', '%d error(s)' % self.errors, '%d second(s)' % (time.time() - self.starttime))
            self.oOutput.Close()

class cOutput():
    def __init__(self, filenameOption=None, binary=False):
        self.starttime = time.time()
        self.filenameOption = filenameOption
        self.separateFiles = False
        self.progress = False
        self.console = False
        self.head = False
        self.headCounter = 0
        self.tail = False
        self.tailQueue = []
        self.fOut = None
        self.oCsvWriter = None
        self.rootFilenames = {}
        self.binary = binary
        if self.binary:
            self.fileoptions = 'wb'
        else:
            self.fileoptions = 'w'
        if self.filenameOption:
            if self.ParseHash(self.filenameOption):
                if not self.separateFiles and self.filename != '':
                    self.fOut = open(self.filename, self.fileoptions)
            elif self.filenameOption != '':
                self.fOut = open(self.filenameOption, self.fileoptions)

    def ParseHash(self, option):
        if option.startswith('#'):
            position = self.filenameOption.find('#', 1)
            if position > 1:
                switches = self.filenameOption[1:position]
                self.filename = self.filenameOption[position + 1:]
                for switch in switches:
                    if switch == 's':
                        self.separateFiles = True
                    elif switch == 'p':
                        self.progress = True
                    elif switch == 'c':
                        self.console = True
                    elif switch == 'l':
                        pass
                    elif switch == 'g':
                        if self.filename != '':
                            extra = self.filename + '-'
                        else:
                            extra = ''
                        self.filename = '%s-%s%s.txt' % (os.path.splitext(os.path.basename(sys.argv[0]))[0], extra, self.FormatTime())
                    elif switch == 'h':
                        self.head = True
                    elif switch == 't':
                        self.tail = True
                    else:
                        return False
                return True
        return False

    @staticmethod
    def FormatTime(epoch=None):
        if epoch == None:
            epoch = time.time()
        return '%04d%02d%02d-%02d%02d%02d' % time.localtime(epoch)[0:6]

    def RootUnique(self, root):
        if not root in self.rootFilenames:
            self.rootFilenames[root] = None
            return root
        iter = 1
        while True:
            newroot = '%s_%04d' % (root, iter)
            if not newroot in self.rootFilenames:
                self.rootFilenames[newroot] = None
                return newroot
            iter += 1

    def LineSub(self, line, eol):
        if self.fOut == None or self.console:
            try:
                print(line, end=eol)
            except UnicodeEncodeError:
                encoding = sys.stdout.encoding
                print(line.encode(encoding, errors='backslashreplace').decode(encoding), end=eol)
#            sys.stdout.flush()
        if self.fOut != None:
            self.fOut.write(line + '\n')
            self.fOut.flush()

    def Line(self, line, eol='\n'):
        if self.head:
            if self.headCounter < 10:
                self.LineSub(line, eol)
            elif self.tail:
                self.tailQueue = self.tailQueue[-9:] + [[line, eol]]
            self.headCounter += 1
        elif self.tail:
            self.tailQueue = self.tailQueue[-9:] + [[line, eol]]
        else:
            self.LineSub(line, eol)

    def LineTimestamped(self, line):
        self.Line('%s: %s' % (self.FormatTime(), line))

    def WriteBinary(self, data):
        if self.fOut != None:
            self.fOut.write(data)
            self.fOut.flush()
        else:
            IfWIN32SetBinary(sys.stdout)
            StdoutWriteChunked(data)

    def CSVWriteRow(self, row):
        if self.oCsvWriter == None:
            self.StringIOCSV = StringIO()
#            self.oCsvWriter = csv.writer(self.fOut)
            self.oCsvWriter = csv.writer(self.StringIOCSV)
        self.oCsvWriter.writerow(row)
        self.Line(self.StringIOCSV.getvalue(), '')
        self.StringIOCSV.truncate(0)
        self.StringIOCSV.seek(0)

    def Filename(self, filename, index, total):
        self.separateFilename = filename
        if self.progress:
            if index == 0:
                eta = ''
            else:
                seconds = int(float((time.time() - self.starttime) / float(index)) * float(total - index))
                eta = 'estimation %d seconds left, finished %s ' % (seconds, self.FormatTime(time.time() + seconds))
            PrintError('%d/%d %s%s' % (index + 1, total, eta, self.separateFilename))
        if self.separateFiles and self.filename != '':
            oFilenameVariables = cVariables()
            oFilenameVariables.SetVariable('f', self.separateFilename)
            basename = os.path.basename(self.separateFilename)
            oFilenameVariables.SetVariable('b', basename)
            oFilenameVariables.SetVariable('d', os.path.dirname(self.separateFilename))
            root, extension = os.path.splitext(basename)
            oFilenameVariables.SetVariable('r', root)
            oFilenameVariables.SetVariable('ru', self.RootUnique(root))
            oFilenameVariables.SetVariable('e', extension)

            self.Close()
            self.fOut = open(oFilenameVariables.Instantiate(self.filename), self.fileoptions)

    def Close(self):
        if self.head and self.tail and len(self.tailQueue) > 0:
            self.LineSub('...', '\n')

        for line, eol in self.tailQueue:
            self.LineSub(line, eol)

        self.headCounter = 0
        self.tailQueue = []

        if self.fOut != None:
            self.fOut.close()
            self.fOut = None

#Insikt: Parses the supplied PCAP for the encrypted callbacks (specifically "submit.php?id=")
def getPayload(pcap):
    uri = None
    body = []
    with open (pcap, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
    
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data
            if tcp.dport == 80 and len(tcp.data) > 0:
                try:
                    http = dpkt.http.Request(tcp.data)
                    uri = http.uri
                    if "submit.php?id=" in uri:
                        body.append(http.body.hex())
                except dpkt.dpkt.NeedData:
                    continue
                except dpkt.dpkt.UnpackError:
                    continue
    return body

#Insikt:Decrypts encrypted callback information and displays   
def decryptKeylogger(callback,aeskey):
    print("----------Decrypted Output----------\n") 
    for cb in callback:
        encryptedCallbackData = ExtractEncryptedCallback(binascii.a2b_hex(cb))
        encryptedData = encryptedCallbackData[:-16]    
        cypher = Crypto.Cipher.AES.new(aeskey, Crypto.Cipher.AES.MODE_CBC, CS_FIXED_IV)
        decryptedData = cypher.decrypt(encryptedData)
        decrypt2string=decryptedData.decode("windows-1252")
        keylog=(' '.join(filter(lambda x: x in string.printable,decrypt2string)))
        keylog=keylog.replace("   ",str(b'\xff'))
        keylog=keylog.replace(' ','')
        keylog=keylog.replace(str(b'\xff'),' ')
        print("%s\n" % keylog)

    
def ExtractEncryptedCallback(data):
    length = struct.unpack('>I', data[:4])[0]
    return data[4:4 + length]

#Insikt: Modifed sections of this to extract payloads from pcap and decrypt the encrypted callbacks
def ProcessBinaryFile(filename, content, cutexpression, flag, oOutput, oLogfile, options, oParserFlag):
    if content == None:
        try:
            oBinaryFile = cBinaryFile(filename)

        except:
            print('Opening file %s %s' % (filename, repr(sys.exc_info()[1])))
            oLogfile.LineError('Opening file %s %s' % (filename, repr(sys.exc_info()[1])))
            return
        oLogfile.Line('Success', 'Opening file %s' % filename)
        try:
            data = oBinaryFile.read()
        except:
            oLogfile.LineError('Reading file %s %s' % (filename, repr(sys.exc_info()[1])))
            return
        data = CutData(data, cutexpression)[0]
        oBinaryFile.close()
    else:
        data = content

    (flagoptions, flagargs) = oParserFlag.parse_args(flag.split(' '))

    try:
        # ----- Put your data processing code here -----
        callback = getPayload(options.callback)
        if len(callback) > 0:
            oOutput.Line('File: %s%s' % (filename, IFF(oBinaryFile.extracted, ' (extracted)', '')))
            
            if flagoptions.length:
                oOutput.Line('%s len(data) = %d' % (filename, len(data)))
        
            encryptedCallbackData = ExtractEncryptedCallback(binascii.a2b_hex(callback[0]))
            encryptedData = encryptedCallbackData[:-16]
            hmacSignatureMessage = encryptedCallbackData[-16:]
            aeskey = None
            hmackey = None
            
            for iter in range(len(data) - 16):
                key = data[iter:iter + 16]
                hmacsSgnatureCalculated = hmac.new(key, encryptedData, hashlib.sha256).digest()[:16]
                if hmacSignatureMessage == hmacsSgnatureCalculated:
                    oOutput.Line('HMAC Key: %s' % binascii.b2a_hex(key).decode())
                    hmackey = key
    
                cypher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, CS_FIXED_IV)
                decryptedData = cypher.decrypt(encryptedData)
                counter = struct.unpack('>I', decryptedData[:4])[0]
                
                if counter < 5:
                    oOutput.Line('AES Key:  %s' % binascii.b2a_hex(key).decode())
                    aeskey = key
            decryptKeylogger(callback,aeskey)
    
            if hmackey != None and aeskey != None:
                for iter in range(len(data) - 16):
                    key = data[iter:iter + 16]
                    sha256 = hashlib.sha256(key).digest()
                    if aeskey == sha256[:16] and hmackey == sha256[16:]:
                        oOutput.Line('Raw key position: 0x%08x' % iter)
                        oOutput.Line('Raw Key:  %s' % binascii.b2a_hex(key).decode())
                
            

    # ----------------------------------------------
    except:
        oLogfile.LineError('Processing file %s %s' % (filename, repr(sys.exc_info()[1])))
        if not options.ignoreprocessingerrors:
            raise


def InstantiateCOutput(options):
    filenameOption = None
    if options.output != '':
        filenameOption = options.output
    return cOutput(filenameOption)

def ProcessBinaryFiles(filenames, oLogfile, options, oParserFlag):
    oOutput = InstantiateCOutput(options)
    index = 0

    for filename, cutexpression, flag in filenames:
        oOutput.Filename(filename, index, len(filenames))
        index += 1
        ProcessBinaryFile(filename, None, cutexpression, flag, oOutput, oLogfile, options, oParserFlag)


def Main():
    moredesc = '''

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParserFlag = optparse.OptionParser(usage='\nFlag arguments start with #f#:')
    oParserFlag.add_option('-l', '--length', action='store_true', default=False, help='Print length of files')

    oParser = optparse.OptionParser(usage='usage: %prog [options] [[@]file|cut-expression|flag-expression ...]\n' + __description__ + moredesc, version='%prog ' + __version__, epilog='This tool also accepts flag arguments (#f#), read the man page (-m) for more info.')
    oParser.add_option('-c', '--callback', type=str, default='', help='pcap containing malicious callbacks to decrypt')
    oParser.add_option('-o', '--output', type=str, default='', help='Output to file (# supported)')
    oParser.add_option('-p', '--password', default='infected', help='The ZIP password to be used (default infected)')
    oParser.add_option('-n', '--noextraction', action='store_true', default=False, help='Do not extract from archive file')
    oParser.add_option('-l', '--literalfilenames', action='store_true', default=False, help='Do not interpret filenames')
    oParser.add_option('-r', '--recursedir', action='store_true', default=False, help='Recurse directories (wildcards and here files (@...) allowed)')
    oParser.add_option('--checkfilenames', action='store_true', default=False, help='Perform check if files exist prior to file processing')
    oParser.add_option('--logfile', type=str, default='', help='Create logfile with given keyword')
    oParser.add_option('--logcomment', type=str, default='', help='A string with comments to be included in the log file')
    oParser.add_option('--ignoreprocessingerrors', action='store_true', default=False, help='Ignore errors during file processing')
    (options, args) = oParser.parse_args()

   
    oLogfile = cLogfile(options.logfile, options.logcomment)
    oExpandFilenameArguments = cExpandFilenameArguments(args, options.literalfilenames, options.recursedir, options.checkfilenames, '#c#', '#f#')

    if oExpandFilenameArguments.warning:
        PrintError('\nWarning:')
        PrintError(oExpandFilenameArguments.message)
        oLogfile.Line('Warning', repr(oExpandFilenameArguments.message))
        
    ProcessBinaryFiles(oExpandFilenameArguments.Filenames(), oLogfile, options, oParserFlag)

    if oLogfile.errors > 0:
        PrintError('Number of errors: %d' % oLogfile.errors)
    oLogfile.Close()

if __name__ == '__main__':
    Main()
