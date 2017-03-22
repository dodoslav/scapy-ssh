#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
# http://www.secdev.org/projects/scapy/doc/build_dissect.html
#https://tools.ietf.org/html/rfc4253
from scapy.packet import Packet, bind_layers
from scapy.fields import *
from scapy.layers.inet import TCP, Raw
import os, time, hashlib
import util
    
class StrCustomTerminatorField(StrField):
    def __init__(self, name, default, fmt="H", remain=0,terminator="\x00\x00", consume_terminator=True):
        StrField.__init__(self,name,default,fmt,remain)
        self.terminator=terminator
        self.consume_terminator=consume_terminator
    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)+self.terminator
    def getfield(self, pkt, s):
        l = s.find(self.terminator)
        if l < 0:
            #XXX terminator not found
            return "",s
        if self.consume_terminator:
            return s[l+len(self.terminator):],self.m2i(pkt, s[:l])
        return s[l:],self.m2i(pkt, s[:l])
    def randval(self):
        return RandTermString(RandNum(0,1200),self.terminator)
  
class HintField(StrField):
    def __init__(self, name, default, fmt="H", remain=0):
        StrField.__init__(self,name,default,fmt,remain)
    def i2len(self, pkt, i):
        return 0
    def i2m(self, pkt, x):
        return ''
class DynamicStrField(Field):
    def __init__(self, name, default, fmt="H", remain=0, adjust=lambda pkt,x:x):
        Field.__init__(self,name,default,fmt)
        self.remain = remain        
        self.adjust = adjust
    def i2len(self, pkt, i):
        return len(i)
    def i2m(self, pkt, x):
        if x is None:
            x = ""
        elif type(x) is not str:
            x=str(x)
            
        x=self.adjust(pkt,x)
        return x
    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)
    def getfield(self, pkt, s):
        if self.remain == 0:
            return "",self.m2i(pkt, s)
        else:
            return s[-self.remain:],self.m2i(pkt, s[:-self.remain])
    def randval(self):
        return RandBin(RandNum(0,1200))

class BLenField(LenField):
    def __init__(self, name, default, fmt = "I", adjust=lambda pkt,x:x, numbytes=None, length_of=None, count_of=None):
        self.name = name
        self.adjust=adjust
        self.numbytes=numbytes
        self.length_of= length_of
        self.count_of = count_of
        LenField.__init__(self, name, default, fmt)

        if fmt[0] in "@=<>!":
            self.fmt = fmt
        else:
            self.fmt = "!"+fmt
        self.default = self.any2i(None,default)
        self.sz = struct.calcsize(self.fmt) if not numbytes else numbytes
        self.owners = []
        
    def addfield(self, pkt, s, val):
        """Add an internal value  to a string"""
        pack = struct.pack(self.fmt, self.i2m(pkt,val))
        if self.numbytes:
            pack=pack[len(pack)-self.numbytes:]
        return s+pack
    def getfield(self, pkt, s):
        """Extract an internal value from a string"""
        upack_data = s[:self.sz]
        # prepend struct.calcsize()-len(data) bytes to satisfy struct.unpack
        upack_data = '\x00'*(struct.calcsize(self.fmt)-self.sz) + upack_data
            
        return  s[self.sz:], self.m2i(pkt, struct.unpack(self.fmt, upack_data)[0])
    
    def i2m(self, pkt, x):
        if x is None:
            if not (self.length_of or self.count_of):
                 x = len(pkt.payload)
                 x = self.adjust(pkt,x)
                 return x
             
            if self.length_of is not None:
                fld,fval = pkt.getfield_and_val(self.length_of)
                f = fld.i2len(pkt, fval)
            else:
                fld,fval = pkt.getfield_and_val(self.count_of)
                f = fld.i2count(pkt, fval)
            x = self.adjust(pkt,f)
        return x

class XBLenField(BLenField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))
    
class XLenField(LenField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))
    
class XFieldLenField(FieldLenField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))    



SSH_MESSAGE_TYPES = {   0x01:"disconnect",
                        0x14:"kex_init",
                        0x15:"new_keys",
                        0x1f:"key_exchange_reply ",
                        0x20:"gex_init",
                        0x21:"gex_reply",
                        0x22:"gex_request",
                        0xff:"unknown"}
SSH_TYPE_BOOL = {0x00:True,
                 0xff:False}

SSH_ALGO_CIPHERS = "none,3des-cbc,arcfour".split(",")
SSH_ALGO_HMACS = "none,hmac-md5-96".split(",")
SSH_ALGO_KEX = "diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1".split(",")
SSH_ALGO_COMPRESSION = "none".split(",")
SSH_ALGO_HOSTKEY = "ssh-rsa,ssh-dss".split(",")


def padding_fix(p):
    padd= 8-len(p)%8
    if p.haslayer(Raw):
        p[Raw].load += 'P'*padd
    else:
        p=p/('P'*padd)
    return p

def ssh_name_list(name, fmt="!I",numbytes=None, default=''):
    return [ XBLenField("%s_length"%name,None, length_of="%s"%name, fmt=fmt, numbytes=numbytes),
             StrLenField("%s"%name,default,length_from=lambda x:getattr(x,"%s_length"%name)),]

class SSHIdent(Packet):
    name = "SSH Ident"
    fields_desc = [ 
                   StrField("ident","SSH-2.0-ScapySSHLayer\r\n"),
                   ]
    
def ssh_calculate_mac(pkt, x):
    if len(x):
        return x
    if not pkt.mac in ('md5','sha-1'):
        return x
    return getattr(hashlib,pkt.mac)(pkt.data).digest()
    
class SSHEncryptedPacket(Packet):
    name = "SSH Encrypted Packet"
    fields_desc = [
                   StrField("data",None),
                   DynamicStrField("mac",None,adjust=ssh_calculate_mac),
                   #HintField("encryption",None),
                   #HintField("mac",'md5'),
                   #HintField("compression",None),
                   ]


class SSHMessage(Packet):
    name = "SSH Message"
    fields_desc = [
                   XBLenField("length",None, fmt="!I", adjust=lambda pkt,x: x+2 if pkt.lastlayer().haslayer(Raw) else x+2),
                   XBLenField("padding_length",None, fmt="!B", adjust=lambda pkt,x: len(pkt.lastlayer()) if pkt.lastlayer().haslayer(Raw) else 0),
                   ByteEnumField("type", 0xff, SSH_MESSAGE_TYPES),
                   ]

    
class SSHKexInit(Packet): 
    name = "SSH Key Exchange Init"
    fields_desc = [ StrFixedLenField("cookie",os.urandom(16),16),] \
                     + ssh_name_list("kex_algorithms",default=",".join(SSH_ALGO_KEX)) \
                     + ssh_name_list("server_host_key_algorithms",default=",".join(SSH_ALGO_HOSTKEY)) \
                     + ssh_name_list("encryption_algorithms_client_to_server",default=",".join(SSH_ALGO_CIPHERS)) \
                     + ssh_name_list("encryption_algorithms_server_to_client",default=",".join(SSH_ALGO_CIPHERS)) \
                     + ssh_name_list("mac_algorithms_client_to_server",default=",".join(SSH_ALGO_HMACS)) \
                     + ssh_name_list("mac_algorithms_server_to_client",default=",".join(SSH_ALGO_HMACS)) \
                     + ssh_name_list("compression_algorithms_client_to_server",default=",".join(SSH_ALGO_COMPRESSION)) \
                     + ssh_name_list("compression_algorithms_server_to_client",default=",".join(SSH_ALGO_COMPRESSION)) \
                     + ssh_name_list("languages_client_to_server") \
                     + ssh_name_list("languages_server_to_client") \
                     + [
                       ByteEnumField("kex_first_packet_follows", 0x00, SSH_TYPE_BOOL),
                       IntField("reserved", 0x00),
                    ]
          
SSH_DISCONNECT_REASONS={  1:'HOST_NOT_ALLOWED_TO_CONNECT',
                          2:'PROTOCOL_ERROR',
                          3:'KEY_EXCHANGE_FAILED',
                          4:'RESERVED',
                          5:'MAC_ERROR',
                          6:'COMPRESSION_ERROR',
                          7:'SERVICE_NOT_AVAILABLE',
                          8:'PROTOCOL_VERSION_NOT_SUPPORTED',
                          9:'HOST_KEY_NOT_VERIFIABLE',
                          10:'CONNECTION_LOST',
                          11:'BY_APPLICATION',             
                          12:'TOO_MANY_CONNECTIONS',            
                          13:'AUTH_CANCELLED_BY_USER',      
                          14:'NO_MORE_AUTH_METHODS_AVAILABLE',  
                          15:'ILLEGAL_USER_NAME',
                        }

# from paramiko kex_gex.py source file
def generateX(self):
    # generate an "x" (1 < x < (p-1)/2).
    q = (self.p - 1) // 2
    qnorm = util.deflate_long(q, 0)
    qhbyte = byte_ord(qnorm[0])
    byte_count = len(qnorm)
    qmask = 0xff
    while not (qhbyte & 0x80):
        qhbyte <<= 1
        qmask >>= 1
    while True:
        x_bytes = os.urandom(byte_count)
        x_bytes = byte_mask(x_bytes[0], qmask) + x_bytes[1:]
        x = util.inflate_long(x_bytes, 1)
        if (x > 1) and (x < q):
            break
    self.x = x


class SSHGexRequest(Packet):
    name = "Diffie-Hellman GEX Request"
    fields_desc = [
            StrField("Group size (min/prefer/max)", "\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x20\x00")
            ]

class SSHKeyExchangeReply(Packet):
    name = "Diffie-Hellman GEX Response"
    fields_desc = [
            StrField("Group size (min/prefer/max)", "\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x20\x00")
            ]

class SSHDisconnect(Packet):
    name = "SSH Disconnect"
    fields_desc = [
                   IntEnumField("reason", 0xff, SSH_DISCONNECT_REASONS),
                   StrCustomTerminatorField("description","",terminator="\x00\x00\x00\x00"),
                   StrCustomTerminatorField("language","",terminator="\x00",consume_terminator=False),
                   ]
       
class SSH(Packet): 
    name = "SSH"
    
    
    def is_ascii(s):
        return all(ord(c) < 128 for c in s)

    def guess_payload_class(self, payload):
        
        try:
            if payload.startswith("SSH-"):
                return SSHIdent
            
            dummy = SSHMessage(payload,_internal=1)
            if len(payload)<=dummy.length+4:
                return SSHMessage
            
        except:
            pass
        return SSHEncryptedPacket
        


# bind magic

bind_layers(TCP, SSH, dport=22)
bind_layers(TCP, SSH, sport=22)

bind_layers(SSH, SSHMessage)
bind_layers(SSHMessage, SSHKexInit, {'type':0x14})
bind_layers(SSHMessage, SSHGexRequest, {'type':0x22})
bind_layers(SSHMessage, SSHKeyExchangeReply, {'type':0x1f})
bind_layers(SSHMessage, SSHGexInit, {'type':0x20})
bind_layers(SSHMessage, SSHGexResponse, {'type':0x21})
bind_layers(SSHMessage, SSHDisconnect, {'type':0x01})
bind_layers(SSH, SSHEncryptedPacket)
