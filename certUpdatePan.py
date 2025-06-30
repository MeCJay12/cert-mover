#!/bin/python3
# pip3 install pyopenssl ruamel_yaml requests

import re
import sys
import time
import string
import getopt
import random
import urllib3
import logging
import requests
from pathlib import Path
from OpenSSL import crypto
from datetime import datetime
from ruamel.yaml import YAML
from ruamel.yaml.constructor import DuplicateKeyError
from xml.etree import ElementTree as ET

# Constants and default logging profile
FILE_PATH = type(Path())
logging.basicConfig(
    format='%(asctime)s: %(levelname)s: %(message)s',
    datefmt='%0y/%0m/%0d-%0H:%0M:%0S',
    level=logging.WARNING
    )
logger = logging.getLogger('logger')

# Parent class to other object classes to provide shared functions
class General(object):
    name = "general"
    objType = "settings"
    verify = True
    force = False
    
    # Better than built in capitalization fucntion
    @staticmethod
    def capitalize(string):
        return str(string[0].upper() + string[1:])

    # Parses file paths to do substitution and validation
    def parseFilePath(self, filePath, fileDesc):
        if self.objType == 'device':
            filePath = Path(str(filePath).replace('%hostname', self.name))
        elif self.objType == 'cert':
            filePath = Path(str(filePath).replace('%name', self.name))
            filePath = Path(str(filePath).replace('%hostname', self.devices[0].name))
        
        if not filePath.is_absolute() and self.defaultPath:
            filePath = self.defaultPath.joinpath(filePath)
        if not filePath.is_file():
            logger.error(f"{General.capitalize(self.objType)} {fileDesc} file not found at '{filePath}'. {self.objType.capitalize()} will be skipped.")
            self.unload()
            return None, 'fileNotFound'
        logger.debug(f"{General.capitalize(fileDesc)} for {self.objType} '{self.name}' will be loaded from '{filePath}'.")
        return filePath, None
        
    def strToBool(self, key, value):
        if type(value) == bool:
            return value
        if type(value) == str:
            if value.lower() == 'true':
                return True
            elif value.lower() == 'false':
                return False
        logger.warning(f"{General.capitalize(self.objType)} {self.name}: Unrecognized config: {key}:{str(value)}.")
        return None

class Cluster(General):
    all = dict()
    __create = object()
    objType = 'cluster'

    # Can only be called by create(). Creates new cluster object.    
    def __init__(self, create, name):
        if not create == Cluster.__create:
            logger.critical("Clusters must be created using Cluster.create()")
            quit()
        self.name = name
        self.devices = []
        self.skip = None
        Cluster.all[self.name] = self
        logger.debug(f"Created new cluster: '{name}'")
        
    # Protects __init__ by checking for cluster before creating new
    @classmethod
    def create(cls, name):
        if name in Cluster.all:
            logger.debug(f"Found cluster '{name}'.")
            return Cluster.all[name]
        else:
            return Cluster(cls.__create, name)
        
    # Validates cluster has required configs
    def validate(self):
        if self.skip is True: return
        if len(self.devices) < 2:
            self.unload()
            logger.error(f"Cluster '{self.name}' does not have enough devices. Skipping Cluster.")
            return True
        self.skip = False
        
    # Adds device to cluster and cluster to device
    def addDevice(self, devices, quite = False):
        for device in devices:
            if type(device) == str:
                device = Device.create(device)
            if not device in self.devices:
                self.devices.append(device)
                device.addToCluster(self, True)
                if not quite:
                    logger.debug(f"Added device '{device.name}' to cluster '{self.name}'.")
                    
    # Removes invalid devices from certs, clusters, and other further processing
    def unload(self):
        self.skip = True
        for device in self.devices:
            device.cluster = None
            device.validate()
        del Cluster.all[self.name]

class Device(General):
    all = dict()
    defaultPath = None
    __create = object()
    objType = 'device'
    
    # Can only be called by create(). Creates new device object.
    def __init__(self, create, name):
        if not create == Device.__create:
            logger.critical("Devices must be created using Device.create()")
            quit()
        self.name = name
        self.certs = []
        self.cluster = None
        self.apiKey = None
        self.skip = None
        self.url = None
        self.commitID = None
        self.commitTime = None
        self.force = False
        Device.all[self.name] = self

    # Protects __init__ by checking for device before creating new  
    @classmethod
    def create(cls, name):
        if name in Device.all:
            logger.debug(f"Found device '{name}'.")
            return Device.all[name]
        else:
            logger.debug(f"Created new device: '{name}'")
            return Device(cls.__create, name)

    # Read configs for one device section 
    @staticmethod
    def populateDevice(name, sectionData):
        device = Device.create(name)
        
        for oKey in sectionData.copy().keys():
            key = oKey.lower()
            value = sectionData[oKey]
            
            if value is None:
                logger.debug(f"No value passed for '{oKey}' in device '{name}'.")
            elif key == 'type':
                # Already checked to get to this function
                pass
            elif key == 'certs' and type(value) == list:
                device.addCert(value)
            elif key == 'certs':
                device.addCert([value])
            elif key == 'cluster':
                device.addToCluster(str(value))
            elif key == 'apikeypath':
                device.addApiKey(value)
            elif key == 'forcepush':
                value = device.strToBool(oKey, value)
                if value is True:
                    logger.debug(f"Forcing config push to device '{device.name}'.")
                    device.force = value
            else:
                logger.warning(f"{name}: Unrecognized device config: {oKey}:{str(value)}.")
        
    # Validates device has required configs
    def validate(self):
        if self.skip is True: return
        if not self.certs:
            self.unload()
            logger.error(f"Device '{self.name}' has no certs. Device will be skipped.")
            return True
        if not self.apiKey:
            self.unload()
            logger.error(f"Device '{self.name}' has no API key. Device will be skipped.")
            return True
        if self.skip is None: self.url = f'https://{self.name}/api/'
        self.skip = False
            
    # Called by Cert class to add a cert to a device
    def addCert(self, certs, quite = False):
        for cert in certs:
            if type(cert) == str:
                cert = Cert.create(cert, [self])
            if not cert in self.certs:
                self.certs.append(cert)
                if not quite:
                    logger.debug(f"Added cert '{cert.name}' to device '{self.name}'.")
        
    # Finds/creates cluster object from string and adds self/device to cluster
    def addToCluster(self, cluster, quite = False):
        if type(cluster) == str:
            cluster = Cluster.create(cluster)
        if self.cluster and cluster != self.cluster:
            logger.warning(f"Cannot assign device '{self.name}' to cluster '{cluster.name}' because device is already a member of cluster '{self.cluster.name}'!")
        else:
            self.cluster = cluster
            cluster.addDevice([self], True)
            if not quite:
                logger.debug(f"Added device '{self.name}' to cluster '{cluster.name}'.")
        
    # Parses, validates, and loads API key from file
    def addApiKey(self, filePath):
        filePath, error = self.parseFilePath(filePath, 'API key')
        if error:
            if error == 'fileNotFound':
                logger.info(f"If the file hasn't been created yet, run to create it: curl -k -X GET 'https://{device.name}/api/?type=keygen&user=<username>&password=<password>' > {filePath}")
            return
        
        file = open(filePath, 'r')
        apiKey = file.read()
        file.close()
            
        if "response status = 'error'" in apiKey:
            logger.error(f"API key file for device '{self.name}' contains error responce from firewall. Skipping device '{self.name}'")
            del Device.all[self.name]
        elif "response status = 'success'" in apiKey:
            logger.info(f"Trimming API responce in '{filePath}' down to just key.")
            apiKey = apiKey.split('<key>')[1]
            apiKey = apiKey.split('</key>')[0]
            file = open(filePath, 'w')
            file.write(apiKey)
            file.close()
        self.apiKey = apiKey
        
    # Removes invalid devices from certs, clusters, and other further processing
    def unload(self):
        self.skip = True
        for cert in self.certs:
            cert.devices.remove(self)
            cert.validate()
        if self.cluster:
            self.cluster.devices.remove(self)
            self.cluster.validate()
        del Device.all[self.name]
        
    # Uploads one cert to one device
    def uploadCert(self, cert):
        force = self.checkForce(cert)
        if not force:
            # Checks if cert already on device and gets experation date
            params = {
                'type': 'op',
                'cmd': f'<request><certificate><show><certificate-name>{cert.pushName}</certificate-name></show></certificate></request>',
                'key': self.apiKey
            }
            data = self.connect(params)
            dateOnDevice = None
            if data is None:
                logger.error(f"Connection error. Unable to check expiration of cert '{cert.name}' on device '{self.name}'.")
                return False
            elif data.attrib['status'] == 'success':
                dateOnDevice = data.find('.//not-valid-after').text
                dateOnDevice = datetime.strptime(dateOnDevice, '%b %d %H:%M:%S %Y %Z')
                logger.debug(f"Cert '{cert.name}' on device '{self.name}' set to expire at {dateOnDevice}")
            elif data.find('.//line').text == 'Command succeeded with no output':
                logger.debug(f"Cert '{cert.name}' not found on device Cert '{cert.name}'.")
        
        # Load certificate from file and check if newer
        chain = []
        if cert.certPath.suffix == '.pem':
            certFile = open(cert.certPath, 'rb').read()
            keyFile = open(cert.privPath, 'rb').read()
            certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certFile)
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, keyFile)
            pkcs = crypto.PKCS12()
            pkcs.set_certificate(certificate)
            pkcs.set_privatekey(key)
            for path in cert.chainPath:
                chainFile = open(path, 'rb').read()
                chain.append(crypto.load_certificate(crypto.FILETYPE_PEM, chainFile))
            if chain: pkcs.set_ca_certificates(chain)
            files = {'file': pkcs.export(passphrase=cert.password.encode('ASCII'))}
        elif cert.certPath.suffix == '.pfx':
            certFile = open(cert.certPath, 'rb').read()
            certificate = crypto.load_pkcs12(certFile, cert.password)
            files = {'file': certFile}
        if force or dateOnDevice:
            dateOnFile = datetime.strptime(certificate.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
            logger.debug(f"Cert '{cert.name}' file set to expire at {dateOnFile}.")
            if not force and dateOnDevice >= dateOnFile:
                logger.debug(f"Cert '{cert.name}' file is not newer than cert on device '{self.name}'. Skipping push.")
                return False
            
        # Push certificate if needed
        params = {
            'type': 'import',
            'category': 'keypair',
            'format': 'pkcs12',
            'certificate-name': cert.pushName,
            'key': self.apiKey,
            'passphrase': cert.password
        }
        data = self.connect(params, files)
        if data is None:
            logger.error(f"Connection error. Unable to push cert '{cert.name}' to device '{self.name}'.")
            return False
        elif data.attrib['status'] == 'success':
            return True
        else:
            logger.error(f"Something went wrong sending cert '{cert.name}' to device '{device.name}'.")
            print(response.text)
            return False
            
    # Runs commit on device, returns job id
    def commit(self):
        params = {
            'type': 'commit',
            'cmd': '<commit></commit>',
            'key': self.apiKey
        }
        data = self.connect(params)
        if data is None:
            logger.error(f"Connection error. Unable to commit on device '{self.name}'.")
            return
        elif data.attrib['status'] == 'success':
            logger.debug(f"Commiting on device '{self.name}'.")
            self.commitID = data.find('.//job').text
            self.commitTime = datetime.now()
            logger.debug(f"Commit processing: Job ID {self.commitID}.")
        elif data.find('.msg').text == 'There are no changes to commit.':
            logger.error(f"Something went wrong pushing certs to device '{self.name}'.")
        else:
            logger.error(f"Something went wrong committing on device '{device.name}'.")
            print(response.text)
            
    def checkForce(self, cert):
        if General.force:
            return True
        if self.force:
            return True
        if cert.force:
            return True
        return False
            
    def waitForCluster(self):
        # Wait for local commit to complete
        while True:
            time.sleep(30)
            if self.checkCompleteJob(self.commitID): break
                
        # Wait for HA-Sync jobs to complete
        for device in self.cluster.devices:
            if device == self: continue
            syncID = None
            retry = False
            failCount = 0
            while True:
                if retry: time.sleep(30)
                # Monitor HA-Sync job if known
                if syncID:
                    if device.checkCompleteJob(syncID): break
                    retry = True
                elif failCount >= 3:
                    logger.warning(f"Unable to find sync job on device '{device.name}'. Skipping check.")
                    break
                # Find HA-Sync job ID if unknown
                else:
                    params = {
                        'type': 'op',
                        'cmd': '<show><jobs><all></all></jobs></show>',
                        'key': self.apiKey
                    }
                    data = self.connect(params)
                    if data is None or data.attrib['status'] != 'success':
                        logger.error(f"Something went wrong checking jobs on device '{device.name}'.")
                        retry = True
                        continue
                    for job in data.findall('.//job'):
                        syncTime = datetime.strptime(job.find('tenq').text, '%Y/%m/%d %H:%M:%S')
                        if syncTime < self.commitTime:
                            logger.debug(f"HA-Sync job not found on device '{device.name}'. Rechecking.")
                            failCount += 1
                            retry = True
                            break
                        if job.find('type').text == 'HA-Sync':
                            syncID = job.find('id').text
                            logger.debug(f"HA-Sync ID on device '{device.name}': {syncID}")
                            retry = False
                            break
                        retry = True
               
    # Returns true if given job (based on ID) is complete
    def checkCompleteJob(self, jobID):
        params = {
            'type': 'op',
            'cmd': f'<show><jobs><id>{jobID}</id></jobs></show>',
            'key': self.apiKey
        }
        data = self.connect(params)
        if data is None or data.attrib['status'] != 'success':
            logger.error(f"Something went wrong checking job on device '{self.name}'.")
        elif data.find('.//status').text == 'FIN':
            logger.debug(f"Job completed on device '{self.name}'.")
            return True
        return False
        
    # Connects to devices and returns Element Tree. Handles connections errors.
    def connect(self, params, files=None):
        verify = True
        if not General.verify:
            verify = False
        elif not self.verify:
            verify = False
    
        try:
            if files:
                response = requests.post(self.url, data=params, files=files, timeout=5, verify=verify)
            else:
                response = requests.get(self.url, params=params, timeout=5, verify=verify)
            return ET.fromstring(response.content)
        except requests.exceptions.ReadTimeout as error:
            logger.error(f"HTTPS connection error when connecting to device '{self.name}'.")
            print(error)
        except requests.exceptions.SSLError as error:
            logger.error(f"SSL error when connecting to device '{self.name}'.")
            print(error)
            return None

class Cert(General):
    all = dict()
    defaultPath = None
    __create = object()
    objType = 'cert'
    
    # Can only be called by create(). Creates new cert object.
    def __init__(self, create, name):
        if not create == Cert.__create:
            logger.critical("Certs must be created using Cert.create()")
            quit()
        self.name = name
        self.devices = []
        self.certPath = None
        self.chainPath = []
        self.privPath = None
        self.password = None
        self.pushName = None
        self.force = False
        self.skip = None
        Cert.all[name] = self
        
    # Protects __init__ by checking for cert before creating new 
    @classmethod
    def create(cls, name):
        if name in Cert.all:
            logger.debug(f"Found cert '{name}'")
            return Cert.all[name]
        else:
            logger.debug(f"Creating cert: '{name}'")
            return Cert(cls.__create, name)
    
    # Read configs for one cert section
    @staticmethod
    def populateCert(name, sectionData):
        cert = Cert.create(name)
        
        for oKey in sectionData:
            key = oKey.lower()
            value = sectionData[oKey]
            
            if value is None:
                logger.debug(f"No value passed for '{oKey}' in device '{name}'.")
            elif key == 'type':
                # Already checked to get to this function
                pass
            elif key == 'devices' and type(value) == list:
                cert.addToDevice(value)
            elif key == 'devices':
                cert.addToDevice([value])
            elif key == 'pushname':
                cert.pushName = value
                logger.debug(f"Cert '{name}' will be pushed to devices under the name '{value}'.")
            elif key == 'certpath':
                cert.certPath = Path(value)
            elif key == 'chainpath':
                cert.chainPath.append(Path(value))
            elif key == 'privpath':
                cert.privPath = Path(value)
            elif key == 'password':
                cert.password = value
            elif key == 'forcepush':
                value = cert.strToBool(oKey, value)
                if value is True:
                    logger.debug(f"Forcing push of cert '{cert.name}'.")
                    cert.force = value
            else:
                logger.warning(f"{name}: Unrecognized cert config: {oKey}:{str(value)}")
                 
    # Validates cert has required configs
    def validate(self):
        if self.skip is True: return
        if not self.devices:
            self.unload()
            logger.error(f"Cert '{self.name}' has no devices. Skipping cert.")
            return True
        if self.skip is None:
            if not self.certPath:
                self.unload()
                logger.error(f"Cert '{self.name}' has no certificate file. Skipping cert.")
                return True
            if str(self.certPath).endswith('%letsencrypt'):
                if self.privPath: logger.info(f"When loading cert file for '{self.name}', '%letsencrypt' will override privPath ('{self.privPath}').")
                self.privPath = Path(str(self.certPath).replace('%letsencrypt', 'privkey.pem'))
                self.chainPath = [Path(str(self.certPath).replace('%letsencrypt', 'chain.pem'))]
                self.certPath = Path(str(self.certPath).replace('%letsencrypt', 'cert.pem'))
            self.certPath, error = self.parseFilePath(self.certPath, 'certificate')
            if error: return True
            if not self.certPath.suffix in ['.pem', '.pfx']:
                self.unload()
                logger.error(f"Certificate file for '{self.name}' unrecognized. Skipping cert.")
                return True
            if not self.privPath and self.certPath.suffix == '.pem':
                self.unload()
                logger.error(f"Cert '{self.name}' has no private key file. Skipping cert.")
                return True
            for i in range(len(self.chainPath)):
                self.chainPath[i], error = self.parseFilePath(self.chainPath[i], 'certificate chain')
                if error: return True
            if self.privPath:
                self.privPath, error = self.parseFilePath(self.privPath, 'private key')
                if error: return True
            if not self.password and self.certPath.suffix == '.pfx':
                self.unload()
                logger.error(f"Cert '{self.name}' has no private key file. Skipping cert.")
                return True
            if not self.password:
                self.password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(16))
            if not self.pushName: self.pushName = self.name
        self.skip = False

    # Adds device opbjects to cert from list
    def addToDevice(self, devices, quite = False):
        for device in devices:
            if type(device) == str:
                device = Device.create(device)
            if not device in self.devices:
                self.devices.append(device)
                device.addCert([self], True)
                if not quite:
                    logger.debug(f"Added cert '{self.name}' to device '{device.name}'.")
         
    # Removes invalid certs from devices and other further processing       
    def unload(self):
        self.skip = True
        for device in self.devices:
            device.certs.remove(self)
            device.validate()
        del Cert.all[self.name]
        
def populateGeneralSettings(data):
    # Iterate through data for log level first
    for key in data.copy().keys():
        value = data[key]
        
        if key.lower() == 'loglevel':
            try:
                logger.setLevel(value.upper())
                logger.debug(f"Log level set to {logging.getLevelName(logger.level)}.")
            except:
                logger.warning(f"Log level '{value}' not recognized. Log level will not be changed.")
            del data[key]
            
    # Iterate through data for everything else
    for oKey in data.keys():
        key = oKey.lower()
        value = data[oKey]
        
        if value is None:
            logger.debug(f"No value passed for '{oKey}' in General.")
        elif key == 'defaultcertpath':
            Cert.defaultPath = Path(value)
            logger.debug(f"Setting default file path for certs to '{value}'.")
        elif key == 'defaultapikeypath':
            Device.defaultPath = Path(value)
            logger.debug(f"Setting default file path for API keys to '{value}'.")
        elif key == 'verifyssl':
            value = General.strToBool(oKey, value)
            if value is False:
                    logger.debug(f"Ignoring certificate errors.")
                    General.verify = False
        elif key == 'forcepush':
            value = General.strToBool(oKey, value)
            if value is True:
                    logger.debug(f"Forcing all config pushes.")
                    General.force = True
        else:
            logger.warning(f"Unrecognized general setting: '{oKey}:{value}'")

def main():
    # Reading command line flags/configs
    configFilePath = None
    shortOptions = "c:"
    longOptions = ["configFile="]
    data = sys.argv[1:]
    try:
        keys, values = getopt.getopt(data, shortOptions, longOptions)
        for key, value in keys:
            if key in ("-c", "--configFile"):
                configFilePath = value
            else:
                logger.warning(f"Command line '{key}:{value}' not recognized.")
    except getopt.error as err:
        print(str(err))
    
    # Reading config file for data
    if not configFilePath:
        logger.critical(f"Config file must be specified with '--configFile=<filePath>'.")
        quit()
    configFilePath = Path(configFilePath)
    if not configFilePath.is_file():
        logger.critical(f"Config file '{configFilePath}' not found.")
        quit()
    try:
        yaml = YAML(typ='safe', pure=True)
        data = yaml.load(configFilePath)
        logger.debug(f"Reading config from {configFilePath}.")
    except DuplicateKeyError as error:
        logger.critical(f"Duplicate keys found in config file at '{configFilePath}':")
        print(error)
        quit()
    
    # Parse general settings first
    for sectionName in data.copy().keys():
        if re.match('general', sectionName, re.IGNORECASE):
            populateGeneralSettings(data[sectionName])
            del data[sectionName]
    
    # Iterate through data to populate everything else
    for sectionName in data.copy().keys():
        for key in data[sectionName].copy().keys():
            if key.lower() == 'type':
                sectionData = data[sectionName]
                value = data[sectionName][key].lower()
                
                if value == 'cert':
                    Cert.populateCert(sectionName, sectionData)
                    del data[sectionName]
                elif value == 'device':
                    Device.populateDevice(sectionName, sectionData)
                    del data[sectionName]
                elif value == 'cluster':
                    logger.info(f"Skipping '{sectionName}'. Clusters have no unique data.")
                    del data[sectionName]
                else:
                    logger.warning(f"'{sectionName}' unrecognized type: {value}")
                break
                
    # Recursively validates all objects
    for cert in Cert.all.copy().values():
        cert.validate()
    for device in Device.all.copy().values():
        device.validate()
    for cluster in Cluster.all.copy().values():
        cluster.validate()
        
    for cluster in Cluster.all.values():
        for device in cluster.devices:
            commit = False
            for cert in device.certs:
                if device.uploadCert(cert): commit = True
            if commit:
                device.commit()
                if device != cluster.devices[-1]:
                    device.waitForCluster()
        
    for device in Device.all.values():
        if device.cluster: continue
        commit = False
        for cert in device.certs:
            if device.uploadCert(cert): commit = True
        if commit: device.commit()

if __name__ == "__main__":
    main()