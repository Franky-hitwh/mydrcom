#!/usr/bin/env python

import random
import logging
import socket
import struct
import time
import sys
import re
from hashlib import md5

SERVER = "172.25.8.4"
MAC = 0x3c970ed2550e
HOST = socket.gethostname()
HOST_OS = "8089D"
HOST_IP = '172.29.153.127'
SRC_PORT = 61440
DST_PORT = 61440

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', SRC_PORT))
s.settimeout(3)


def md5sum(string):
    m = md5()
    m.update(string)
    return m.digest()


def dump(n):
    temp = '%x' % n  # convet n to str&hex
    if len(temp) & 1:  # judge odd or even.only even_length string can be decoded
        temp = '0' + temp
    return temp.decode('hex')
    #  That is to say, the dump() pack_id content to return a big-endian


def checksum(string):
    ret = 1234
    for i in re.findall('....', string):
        ret ^= int(i[::-1].encode('hex'), 16)
    ret = (1968 * ret) & 0xffffffff
    return struct.pack('<I', ret)


def challenge(ran):
    t = struct.pack("<H", int(ran) % (0xFFFF))
    s.sendto("\x01\x02" + t + "\x09" + "\x00" * 15, (SERVER, 61440))
    try:
        data, address = s.recvfrom(1024)
        if data[0] != "\x02":
            # print 'challenge request failed.'
            logging.info('challenge request failed.')
            sys.exit()
    except Exception as e:
        print e

    # print "[challenge] challenge packet sent."
    logging.info('[challenge] challenge packet sent.')
    return data[4:8]


def keep_alive():

    pack_id = 0
    signal = '\x00' * 4
    num = 1
    while True:
        signal, num = send_alive_pack(pack_id, signal, num)
        pack_id = (pack_id + 1) % 0xFF
        num = (ord(num) % 4) + 1
        if pack_id == 39:
            return
        if pack_id % 4 == 0:
            time.sleep(20)


def send_alive_pack(pack_id, signal, num):

    data = '\x07'
    data += chr(pack_id)
    data += '\x28\x00\x0b'
    data += chr(num)
    data += '\x1f\x00'
    data += '\x00' * 8
    data += signal
    if num == 3:
        data += socket.inet_aton(HOST_IP)
    else:
        data += '\x00' * 4
    data += '\x00' * 16
    s.sendto(data, (SERVER, DST_PORT))
    # print '%d packet sent' % (pack_id, )
    logging.info('%d packet sent' % (pack_id, ))
    try:
        recvpack, address = s.recvfrom(1024)
        # print 'receive from server %s' % SERVER
        logging.info('receive from server %s' % SERVER)
    except Exception, e:
        print e
        sys.exit()
    return (recvpack[16:20], recvpack[5])


def mkpkt(salt, usr, pwd):
    data = '\x03\x01\x00' + chr(30)  # len+20=30:'\x1e', the first three char may be arranged before.
    data += md5sum('\x03\x01' + salt + pwd)
    data += usr.ljust(36, '\x00')  # 36 bytes' username. using '\x00' fills the blank
    data += '\x20\x02'
    data += dump(int(data[4:10].encode('hex'), 16) ^ MAC).rjust(6, '\x00')  # first :int(MAC) xor md5 second: change the result to big-endian
    data += md5sum("\x01" + pwd + salt + '\x00' * 4)
    data += '\x01'
    data += socket.inet_aton(HOST_IP)
    data += '\x00' * 12
    data += md5sum(data + '\x14\x00\x07\x0b')[:8]  # md53
    data += '\x01'  # ipdog
    data += '\x00' * 4  # delimeter
    data += HOST.ljust(32, '\x00')

    data += '\x72\x72\x72\x72'  # primary dns: 114.114.114.114
    data += '\x0a\xff\x00\xc5'  # DHCP SERVER
    data += '\x08\x08\x08\x08'  # secondary dns:8.8.8.8
    data += '\x00' * 8  # delimeter
    data += '\x94\x00\x00\x00'  # unknow
    data += '\x05\x00\x00\x00'  # os major
    data += '\x01\x00\x00\x00'  # os minor
    data += '\x28\x0a\x00\x00'  # OS build
    data += '\x02\x00\x00\x00'  # os unknown

    data += '\x01' + HOST_OS.ljust(32, '\x00')
    data += '\x00' * 96
    # data += '\x6d\x00\x00'+chr(len(pwd))
    # data += ror(md5sum('\x03\x01'+salt+pwd), pwd)
    data += '\x23\x00'
    data += '\x02\x0c'
    data += checksum(data + '\x01\x26\x07\x11\x00\x00' + dump(MAC))
    data += "\x00\x00"  # delimeter
    data += dump(MAC)
    data += '\x00'  # auto logout / default: False
    data += '\x00'  # broadcast mode / default : False
    data += '\xe8\x90'  # unknown
    return data


def login(username, passwd):

    salt = challenge(time.time() + random.randint(0xF, 0xFF))
    packet = mkpkt(salt, username, passwd)
    try:
        s.sendto(packet, (SERVER, DST_PORT))
        data, address = s.recvfrom(1024)
        # print '[login] packet sent'
        logging.info('receive from server %s' % SERVER)
    except Exception, e:
        print e

    if data[0] == '\x04':
        #print '[login] success'
        logging.info('[login] success')
    else:
        # print '[login] failed'
        logging.info('[login] failed')
        sys.exit()


def log():

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
        datefmt='%a, %d %b %Y %H:%M:%S',
        filename='drcom.log',
        filemode='w')

    console = logging.StreamHandler()
    console.setLevel(logging.WARN)
    formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

    return logging


def main(argv):

    username = argv['user']
    password = argv['password']
    logging = log()
    while True:

        login(username, password)

        keep_alive()


if __name__ == '__main__':

    main()
