#!/bin/python3
# Purpose: Leverage NPM API and Python requests library to
# programmatically upload custom certificates in NPM
# Programmer: MeCJay12

import os
import csv
import sys
import json
import dotenv
import shutil
import requests
from io import BytesIO
from zipfile import ZipFile
from tempfile import NamedTemporaryFile

if len(sys.argv) > 1:
  dotenv_path = sys.argv[1]
else:
  dotenv_path = dotenv.find_dotenv()

dotenv.load_dotenv(dotenv_path = dotenv_path)

email = os.getenv('EMAIL')
password  = os.getenv('PASSWORD')
filename = os.getenv('CONFIG_FILE')
verify = os.getenv('VERIFY_SSL', default = True)
tempfile = NamedTemporaryFile(mode = 'w', delete=False)

class Server:
  all = {}
  __create = object()
  
  # Do not call Server directly. Call Server.create to ensure no duplicates.
  def __init__(self, create, hostname):
    if not create == Server.__create:
      raise ValueError("Class Server should be called via .create() only")
      quit()
    self.hostname = hostname
    self.schema = "https://"
    self.headers = { "Authorization": f"Bearer " + self.get_api_key() }
    self.certs = {}
    Server.all[self.hostname] = self
    
  # Looks up exisiting object or makes new
  @classmethod
  def create(cls, hostname):
    if hostname in Server.all:
      print(f"Found server: {hostname}")
      server = Server.all[hostname]
      return server
    elif not hostname:
      raise TypeError("No server specified")
    else:
      print(f"Creating new server: {hostname}")
      return Server(cls.__create, hostname)
    
  def get_api_key(self):
    # Constructing URL for proxy host creation
    url = f"{self.schema}{self.hostname}/api/tokens"
    
    # Data for the API call
    data = {
      "identity": email,
      "secret": password
    }
    
    # Make call to get API key
    try:
      response = requests.post(url, json=data, verify=verify)
      response_json = response.json()

      if response.status_code in (200, 201):
        print(f"Got API key for {self.hostname}")
        return response_json.get('token')
      else:
        print(json.dumps(response.json(), indent=2))
        raise ConnectionError(f"There was an error getting API key from {self.hostname}")
        
    except requests.exceptions.RequestException as e:
      # Falls back to http if https fails
      if self.schema == "https://":
        print(f"Failed to connect to {self.hostname} with https, failling back to http")
        self.schema = "http://"
        return self.get_api_key()
      
      # Re-raises out uncaught errors
      else:
        print(f"Check if the server is redirecting http to https.")
        raise

    # Re-raises out uncaught errors
    except Exception as e:
      print(f"When getting API key for {self.hostname}")
      raise

  # Downloads certificate and extract keys
  def download_cert(self, cert):
    url = f"{self.schema}{self.hostname}/api/nginx/certificates/{cert.id}/download"
    response = requests.get(url, headers=self.headers, verify=verify)

    if response.status_code in (200, 201):
      # Cert is downloaded in the form of a zip file with cert#.pem, chain#.pem, privkey#.pem, and fullchain#.pem
      # Processes that zip without saving anything to disk
      zip = ZipFile(BytesIO(response.content))
      for zipfile in zip.namelist():
        if zipfile.startswith("cert"):
          public = zip.open(zipfile)
          cert.public = public.read().decode('UTF-8')
        elif zipfile.startswith("chain"):
          chain = zip.open(zipfile)
          cert.chain = chain.read().decode('UTF-8')
        elif zipfile.startswith("privkey"):
          private = zip.open(zipfile)
          cert.private = private.read().decode('UTF-8')
      zip.close()
      print(f"Downloaded {cert.id} : {cert.nice_name} from {self.hostname}")

    else:
      print(json.dumps(response.json(), indent=2))
      raise ConnectionError("Could not download certificate")
      
  def update_cert(self, cert):
    url = f"{self.schema}{self.hostname}/api/nginx/certificates/{cert.id}/upload"

    files = {
      "certificate": ("cert.pem", cert.public),
      "certificate_key": ("privekey.pem", cert.private),
      "intermediate_certificate": ("chain.pem", cert.chain)
    }

    response = requests.post(url, headers=self.headers, files=files, verify=verify)

    if response.status_code in (200, 201):
      print(f"Updated {cert.id} : {cert.nice_name} on {self.hostname}")
    else:
      print(f"There was an issue updating {cert.id} : {cert.nice_name} on {self.hostname}")
      print(json.dumps(response.json(), indent=2))

  # Certificate object must be created before keys can be uploaded
  def create_cert(self, cert):
    url = f"{self.schema}{self.hostname}/api/nginx/certificates/"

    data = {
      "provider": "other",
      "nice_name": cert.nice_name
    }

    response = requests.post(url, headers=self.headers, json=data, verify=verify)
    response_json = response.json()

    if response.status_code in (200, 201):
      cert.id = int(response_json.get('id'))
      self.certs[id] = cert
      print(f"Created {cert.id} : {cert.nice_name} on {self.hostname}")
    else:
      print(f"There was an issue creating {cert.nice_name} on {self.hostname}")
      print(json.dumps(response_json, indent=2))

class Cert:
  __create = object()

  def __init__(self, create, server, id):
    if not create == Cert.__create:
      raise ValueError("Class Cert should be called via .create() only")
      quit()
    server.certs[id] = self
    self.server = server
    self.id = id
    self.nice_name = ""
    self.public = ""
    self.chain = ""
    self.private = ""

  @classmethod
  def create(cls, server, id):
    if id.isdecimal():
      if int(id) in server.certs.keys():
        return server.certs[id]
      else:
        return Cert(cls.__create, server, int(id))
    elif id:
      raise TypeError(f"ID is not deciaml: {id}")
    else:
      raise TypeError("No ID Found")
  
  def get_nice_name(self):
    url = f"{self.server.schema}{self.server.hostname}/api/nginx/certificates/{self.id}"
    response = requests.get(url, headers=self.server.headers, verify=verify)
    response_json = response.json()

    if response.status_code in (200, 201):
      self.nice_name = response_json.get('nice_name')
    else:
      print(json.dumps(response_json, indent=2))
      raise ConnectionError("Could not get nice name")

def main():  
  # Read CSV file
  with open(filename, 'r') as csv_file, tempfile:
    csv_reader = csv.reader(csv_file)
    csv_writer = csv.writer(tempfile, lineterminator='\n')
    data = list(csv_reader)

    for row in data:
      # Skip commented rows
      if row[0][0] == "#": continue
      else: row_name = row[0]
      dst_certs = []
      src_server = object()
      id = None

      # Get source server hostname
      try: src_server = Server.create(row[1])
      except Exception as e:
        print(f"{row_name}: Source Server: {e}") 
        continue

      # Get source certificate id
      try: src_cert = Cert.create(src_server, row[2])
      except Exception as e:
        print(f"{row_name}: Source Certificate: {e}") 
        continue

      # Source certificate must have discrete ID
      if src_cert.id < 1:
        print(f"{row_name}: Source Certificate: ID cannot be less than 1")
        continue

      # Get nice name from source server to set on destination servers
      try: src_cert.get_nice_name()
      except Exception as e:
        print(f"{row_name}: Source Certificate: {e}")
        continue

      # Read in destination information in pairs
      # Bails out and retrying on next item if there's a problem
      i = 3
      while i < len(row):
        try: server = Server.create(row[i])
        except Exception as e:
          print(f"{row_name}: Destination Server {row[i]}: {e}")
          i += 1
          continue
        finally:
          i += 1

        try: cert = Cert.create(server, row[i])
        except Exception as e:
          print(f"{row_name}: Certificate on Destination Server {server.hostname}: {e}")
          continue
        finally:
          i += 1

        # Create certificate on dst
        if cert.id == 0:
          try:
            cert.nice_name = src_cert.nice_name
            server.create_cert(cert)
            row[i-1] = cert.id
          except Exception as e:
            print(f"{row_name}: Certificate on Destination Server {server.hostname}: {e}")
            continue

        dst_certs.append(cert)

      # If no certificates made it past validation, skip row
      if len(dst_certs) == 0:
        print(f"{row_name}: Not enough destination information provided")
        continue

      # Download keys for source certificate from source server
      try: src_server.download_cert(src_cert)
      except Exception as e:
        print(f"{row_name}: Source Certificate: {e}")
        continue

      # Certificate object must exist on destination server before keys can be uploaded
      for dst_cert in dst_certs:
        dst_cert.public, dst_cert.chain, dst_cert.private = src_cert.public, src_cert.chain, src_cert.private
        dst_cert.nice_name = src_cert.nice_name
        dst_cert.server.update_cert(dst_cert)

    csv_writer.writerows(data)
    tempfile.close()
    shutil.move(tempfile.name, filename)

main()