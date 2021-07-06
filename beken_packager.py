#!/usr/bin/env python3
# 

import sys
import platform
import traceback
import os
import termios
import stat
import time
import datetime
import subprocess
import shlex
import shutil
import json

img_name = 'all.bin'

def load_config_file(file):
    with open(file) as (json_file):
        data = json.load(json_file)
        return data


class Partition:
    magic = (None, )
    version = (None, )
    key = None
    iv = None
    count = (None, )
    section = (None, )

    def __init__(self, firmware=None, version=None, partition=None, start_addr=None, size=None):
        self.firmware = firmware
        self.version = version
        self.partition = partition
        self.start_addr = start_addr
        self.size = size

    def load_config(self, file='config.json'):
        config = load_config_file(file)
        Partition.magic = config['magic']
        Partition.version = config['version']
        Partition.count = config['count']
        Partition.section = config['section']
        section = self.section
        for index in range(len(section)):
            if 'k' in section[index]['size'] or 'K' in section[index]['size']:
                section[index]['size'] = int(section[index]['size'][0:-1]) * 1024
            else:
                section[index]['size'] = int(section[index]['size'])
            if 'x' in section[index]['start_addr'] or 'X' in section[index]['start_addr']:
                section[index]['start_addr'] = int(section[index]['start_addr'], 16)
            else:
                section[index]['start_addr'] = int(section[index]['start_addr'])
            if 'flash_name' in section[index]:
                if section[index]['flash_name'] not in ('beken_onchip', 'beken_onchip_crc'):
                    print('partition: %s flash_name: %s error!' % (section[index]['partition'], section[index]['flash_name']))
                    sys.exit(-1)
            else:
                section[index]['flash_name'] = 'beken_onchip_crc'

    def print_partition(self):
        print('')
        print('partition    flash_name       phy addr   size       logic addr size       file')
        print('------------ ---------------- ---------- ---------- ---------- ---------- ----------------')
        partition_format = '%-12.12s '
        size_format = '%-10.10s '
        section = Partition.section
        for index in range(len(section)):
            phy_addr = section[index]['start_addr']
            phy_size = section[index]['size']
            logic_addr = phy_addr / 34 * 32
            logic_size = phy_size / 34 * 32
            if phy_size % 1024 == 0:
                phy_size_str = '%dK' % (phy_size / 1024)
            else:
                phy_size_str = str(int(phy_size))
            if logic_size % 1024 == 0:
                logic_size_str = '%dK' % (logic_size / 1024)
            else:
                logic_size_str = str(int(logic_size))
            line_str = ''
            line_str += partition_format % section[index]['partition']
            line_str += '%-16.16s ' % section[index]['flash_name']
            line_str += '0x%08X ' % phy_addr
            line_str += size_format % phy_size_str
            line_str += '0x%08X ' % int(logic_addr)
            line_str += size_format % logic_size_str
            line_str += section[index]['firmware']
            print(line_str)


def execute_command(cmdstring, cwd=None, timeout=None, shell=True):
    if shell:
        cmdstring_list = cmdstring
    else:
        cmdstring_list = shlex.split(cmdstring)
    sub = subprocess.Popen(cmdstring_list, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=shell, bufsize=4096)
    stdout_str = ''
    while sub.poll() is None:
        stdout_str += str(sub.stdout.read())
        time.sleep(0.1)
        if timeout and end_time <= datetime.datetime.now():
            raise Exception('Timeout：%s' % cmdstring)

    return stdout_str


def get_path():
    path = sys.path[0]
    if path.endswith('base_library.zip'):
        path = os.path.dirname(path)
    return path


def pack_rbl(input_file, output_file, version, partition, compress=None, securty=None, iv=None, key=None):
    cwd = os.getcwd()
    if 'Windows' in platform.platform():
        cmd = 'ota_tools.exe -f %s -v %s -p %s -o %s' % (input_file, version, partition, output_file)
    else:
        cmd = 'ota_tools -f %s -v %s -p %s -o %s' % (input_file, version, partition, output_file)
    compress = None
    securty = None
    if compress:
        cmd = cmd + ' -c %s' % compress
    if securty:
        cmd = cmd + ' -s %s -i %s -k %s' % (securty, iv, key)
    cmd = os.path.join(get_path(), cmd)
    execute_command(cmd, cwd)


def crc_file(input_file, output_file):
    cwd = os.getcwd()
    if 'Windows' in platform.platform():
        cmd = 'encrypt.exe %s %s' % (input_file, output_file)
    else:
        cmd = 'encrypt %s 0 0 0 0' % input_file
    cmd = os.path.join(get_path(), cmd)
    execute_command(cmd, cwd)


def load_rbl_info(input_file, output_file):
    with open(input_file, 'rb') as (rbl_file):
        rbl_file.seek(0, 0)
        data = rbl_file.read(96)
        with open(output_file, 'wb+') as (hdr):
            hdr.seek(0, 0)
            hdr.write(data)
            hdr.close()
        rbl_file.close()


def pack_firmware(in_file, out_file, start_addr, size, version, partition, compress=None, securty=None, iv=None, key=None):
    input_file = in_file
    output_file = in_file[0:-4] + '_crc.bin'
    crc_file(input_file, output_file)
    input_file = in_file
    output_file = in_file[0:-4] + '.rbl'
    pack_rbl(input_file, output_file, version, partition, 'quicklz')
    input_file = output_file
    output_file = input_file[0:-4] + '_hdr.bin'
    load_rbl_info(input_file, output_file)
    input_file = output_file
    output_file = input_file[0:-4] + '_crc.bin'
    crc_file(input_file, output_file)
    offset = size - 102
    img = open(out_file, 'wb+')
    img.seek(0, 0)
    img.write(b'\xff' * size)
    body = open(in_file[0:-4] + '_crc.bin', 'rb')
    body.seek(0, 0)
    body_size = os.path.getsize(in_file[0:-4] + '_crc.bin')
    body_data = body.read(body_size)
    img.seek(0, 0)
    img.write(body_data)
    body.close()
    hdr = open(in_file[0:-4] + '_hdr_crc.bin', 'rb')
    hdr.seek(0, 0)
    hdr_size = os.path.getsize(in_file[0:-4] + '_hdr_crc.bin')
    hdr_data = hdr.read(hdr_size)
    img.seek(offset, 0)
    img.write(hdr_data)
    hdr.close()
    img.close()


def remove_file(in_file):
    file = in_file[0:-4] + '_crc.bin'
    os.remove(file)
    file = in_file[0:-4] + '.rbl'
    os.remove(file)
    file = in_file[0:-4] + '_hdr.bin'
    os.remove(file)
    file = in_file[0:-4] + '_hdr_crc.bin'
    os.remove(file)
    file = in_file[0:-4] + '.out'
    os.remove(file)
    file = in_file[0:-4] + '_hdr.out'
    os.remove(file)


POLYNOMIAL = 32773
INITIAL_REMAINDER = 65535
FINAL_XOR_VALUE = 0
WIDTH = 16
TOPBIT = 1 << WIDTH - 1
crcTable = {}

def crcInit():
    SHIFT = WIDTH - 8
    for step in range(0, 256):
        remainder = step << SHIFT
        for bit in range(8, 0, -1):
            if remainder & TOPBIT:
                remainder = remainder << 1 & 65535 ^ POLYNOMIAL
            else:
                remainder = remainder << 1

        crcTable[step] = remainder


def crcFast(message, nBytes):
    crcInit()
    remainder = 65535
    data = 0
    byte = 0
    while byte < nBytes:
        data = ord(chr(message[byte])) ^ remainder >> WIDTH - 8
        remainder = crcTable[data] ^ remainder << 8 & 65535
        byte = byte + 1

    return remainder


def file_crc_check(in_file):
    with open(in_file, 'rb') as (file):
        file.seek(0, 0)
        data = file.read(32)
        crc_read = file.read(2)
        file.close()
    calculate = crcFast(data, 32)
    original = 65535 & (ord(chr(crc_read[0])) << 8 | ord(chr(crc_read[1])))
    if original == calculate:
        return True
    else:
        return False


def press_any_key_exit(msg):
    fd = sys.stdin.fileno()
    old_ttyinfo = termios.tcgetattr(fd)
    new_ttyinfo = old_ttyinfo[:]
    new_ttyinfo[3] &= ~termios.ICANON
    new_ttyinfo[3] &= ~termios.ECHO
    sys.stdout.write(msg)
    sys.stdout.flush()
    termios.tcsetattr(fd, termios.TCSANOW, new_ttyinfo)
    os.read(fd, 7)
    termios.tcsetattr(fd, termios.TCSANOW, old_ttyinfo)


if __name__ == '__main__':
    try:
        time_start = time.time()
        print('beken packager V2.1.0')
        print('Shanghai Real-Thread Electronic Technology Co.,Ltd')
        print(platform.platform())
        partition = Partition()
        config_fn = 'config.json'
        if len(sys.argv) == 2:
            config_fn = sys.argv[1]
        print('\nload_config: %s' % config_fn)
        partition.load_config(config_fn)
        partition.print_partition()
        section = partition.section
        for index in range(len(section)):
            if section[index]['flash_name'] == 'beken_onchip_crc':
                firmware_size = os.path.getsize(section[index]['firmware'])
                partition_size = section[index]['size']
                crc_size = (firmware_size + 31) / 32 * 34
                partition_body = partition_size - 102.0
                if crc_size > partition_body:
                    print('\n[Error]: partition [%s] overflow, %d ==> %d > %d!' % (section[index]['partition'], firmware_size, crc_size, partition_body))
                    sys.exit(-1)
            else:
                firmware_size = os.path.getsize(section[index]['firmware'])
                partition_size = section[index]['size']
                partition_body = partition_size - 96
                if firmware_size > partition_body:
                    print('\n[Error]: partition [%s] overflow, %d > %d!' % (section[index]['partition'], firmware_size, partition_body))
                    sys.exit(-1)

        for index in range(len(section)):
            if section[index]['flash_name'] == 'beken_onchip_crc':
                result = file_crc_check(section[index]['firmware'])
                if result:
                    print('\n[Error]: %s please input a file without crc' % section[index]['firmware'])
                    sys.exit(-1)

        addr_list = []
        for index in range(len(section)):
            addr_list.append(section[index]['start_addr'])

        index = addr_list.index(max(addr_list))
        size = int(section[index]['size'])
        firmware_size = addr_list[index] + size
        if firmware_size % 1024 == 0:
            print('\nimage size: %d KB' % (firmware_size / 1024))
        else:
            print('\nimage size: %d Byte' % firmware_size)
        for index in range(len(section)):
            if section[index]['partition'] == 'app':
                img_name = 'all_' + section[index]['version'] + '.bin'

        print('image name: %s' % img_name)
        with open(img_name, 'wb+') as (img):
            img.seek(0, 0)
            img.write(b'\xff' * firmware_size)
        for index in range(len(section)):
            if section[index]['flash_name'] == 'beken_onchip_crc':
                pack_firmware(section[index]['firmware'], 
                              section[index]['partition'] + '_firmware.bin', 
                              section[index]['start_addr'], 
                              int(section[index]['size']), 
                              section[index]['version'], 
                              section[index]['partition'])
                remove_file(section[index]['firmware'])

        with open(img_name, 'rb+') as (img):
            for index in range(len(section)):
                if section[index]['flash_name'] == 'beken_onchip_crc':
                    body_size = os.path.getsize(section[index]['partition'] + '_firmware.bin')
                    body = open(section[index]['partition'] + '_firmware.bin', 'rb')
                    body_data = body.read(body_size)
                    img.seek(section[index]['start_addr'], 0)
                    img.write(body_data)
                    body.close()
                    os.remove(section[index]['partition'] + '_firmware.bin')
                elif section[index]['flash_name'] == 'beken_onchip':
                    body_size = os.path.getsize(section[index]['firmware'])
                    body = open(section[index]['firmware'], 'rb')
                    body_data = body.read(body_size)
                    img.seek(section[index]['start_addr'], 0)
                    img.write(body_data)
                    body.close()
                else:
                    print('partition: %s flash_name: %s error!' % (section[index]['partition'], section[index]['flash_name']))
                    sys.exit(-1)

            img.close()
        for index in range(len(section)):
            if section[index]['partition'] == 'app':
                path = section[index]['firmware']
                path = os.path.basename(path)
                path = os.path.splitext(path)[0]
                path = path + '_uart_' + section[index]['version'] + '.bin'
                print('\n' + 'export app partition image: %s' % path)
                with open(img_name, 'rb+') as (img):
                    with open(path, 'wb+') as (img_uart):
                        img.seek(section[index]['start_addr'], 0)
                        data = img.read(section[index]['size'])
                        img_uart.write(data)
                        img_uart.close()
                img.close()

        time_end = time.time()
        print('')
        print('time: %.2fs' % (time_end - time_start))
        print('Good bye!')
    except Exception as e:
        print('')
        traceback.print_exc()
        if 'Windows' in platform.platform():
            os.system('pause')
        else:
            press_any_key_exit('\nPress any key to continue...')
            print('')
        print('Good bye!')
# okay decompiling pydata.dump_extracted/beken_packager.pyc
