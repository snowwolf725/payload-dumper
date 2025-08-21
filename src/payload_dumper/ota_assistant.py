# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: ota_assistant.py
# Bytecode version: 3.11a7e (3495)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import subprocess
import os
import sys
import errno
import argparse
import struct
import hashlib
import update_metadata_pb2 as um

def u32(x):
    return struct.unpack('>I', x)[0]

def u64(x):
    return struct.unpack('>Q', x)[0]

def sha256sum(filename):
    with open(filename, 'rb', buffering=0) as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def check_privileges():
    if not os.environ.get('SUDO_UID'):
        if os.geteuid() != 0:
            raise PermissionError('You need root permission to execute this command')

def exec_cmdline(cmd):
    result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.stderr:
        print(result.stderr)
    else:
        return result.stdout

def dump(plist):
    for key in plist:
        print('Dump:', key)
        exec_cmdline('dd if=' + plist[key] + ' of=out/' + key + '.img')
    print('Finished')

def getPartitionList(dam):
    result = {}
    slot = exec_cmdline('getprop ro.boot.slot_suffix')
    slot = slot.strip()
    for part in dam.partitions:
        pname = part.partition_name
        fullpath = '/dev/block/bootdevice/by-name/' + pname
        fullpath_in_mapper = '/dev/block/mapper/' + pname + slot
        if os.path.exists(fullpath):
            result[pname] = fullpath
        elif os.path.exists(fullpath + slot):
            result[pname] = fullpath + slot
        elif os.path.exists(fullpath_in_mapper):
            result[pname] = fullpath_in_mapper
        else:
            print('partition not found')
    return result

def check(dam, plist, isLocal, isCheckNewPartition):
    for part in dam.partitions:
        pname = part.partition_name
        imgpath = 'out/' + pname + '.img'
        if isLocal:
            imgpath = plist[pname]
        filehash = sha256sum(imgpath)
        partHash = part.old_partition_info.hash.hex()
        if isCheckNewPartition:
            partHash = part.new_partition_info.hash.hex()
        print('Partition:\t', pname)
        print('Size:\t', part.new_partition_info.size)
        print('Hash in payload:', partHash)
        print('Image hash:\t', filehash)
        if filehash == partHash:
            print('Result:\t\t \033[42m<<Pass>>\033[0m')
        else:
            print('Result:\t\t \033[41m<<Fail>>\033[0m')
        print('')
if __name__ == '__main__':
    if not os.path.exists('out'):
        os.makedirs('out')
    parser = argparse.ArgumentParser(description='OTA payload assistant')
    parser.add_argument('payloadfile', type=argparse.FileType('rb'), help='payload file name')
    parser.add_argument('--check', action='store_true', help='Check integrity of partitions')
    parser.add_argument('--imageCheck', action='store_true', help='Check integrity of partition images')
    parser.add_argument('--checkNewPart', action='store_true', help='Check hash of new partition images')
    parser.add_argument('--dump', action='store_true', help='Dump partition images')
    args = parser.parse_args()
    magic = args.payloadfile.read(4)
    assert magic == b'CrAU'
    file_format_version = u64(args.payloadfile.read(8))
    assert file_format_version == 2
    manifest_size = u64(args.payloadfile.read(8))
    metadata_signature_size = 0
    if file_format_version > 1:
        metadata_signature_size = u32(args.payloadfile.read(4))
    manifest = args.payloadfile.read(manifest_size)
    metadata_signature = args.payloadfile.read(metadata_signature_size)
    data_offset = args.payloadfile.tell()
    dam = um.DeltaArchiveManifest()
    dam.ParseFromString(manifest)
    block_size = dam.block_size
    if args.dump:
        check_privileges()
        plist = getPartitionList(dam)
        dump(plist)
    elif args.imageCheck:
        check(dam, {}, False, args.checkNewPart)
    elif args.check:
        check_privileges()
        plist = getPartitionList(dam)
        check(dam, plist, True, args.checkNewPart)
