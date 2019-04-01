#!/usr/bin/env python

import sys
import csv
import ipaddress
import os.path
from os import listdir
from os.path import isfile, join
import random
import hashlib
from array import *
from collections import defaultdict
import time
from random import getrandbits
from ipaddress import IPv4Address, IPv6Address

# Bitcoin Parameters
ADDRMAN_TRIED_BUCKETS_PER_GROUP = 8
ADDRMAN_TRIED_BUCKET_COUNT = 256
ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP = 64
ADDRMAN_NEW_BUCKET_COUNT = 1024
ADDRMAN_BUCKET_SIZE = 64
ADDRMAN_HORIZON_DAYS  = 30
ADDRMAN_RETRIES = 3
ADDRMAN_MAX_FAILURES = 10
ADDRMAN_MIN_FAIL_DAYS = 7
ADDRMAN_NEW_BUCKETS_PER_ADDRESS = 8
ADDRMAN_SET_TRIED_COLLISION_SIZE = 10
ADDRMAN_REPLACEMENT_HOURS = 4
nMaxOutbound = 8
nTimePenalty = 2 * 60 * 60
FEELER_INTERVAL = 120
nIdCount = 0
# nKey = random.getrandbits(256)
nKey = "1313842542810890645741820448452432526161972925574964606024061314128846616260L"
mapInfo = dict()
mapAddr = dict()
vvNew = dict()
vvTried = dict()
m_tried_collisions = []
nNew = 0
nTried = 0
for i in range(ADDRMAN_NEW_BUCKET_COUNT):
    vvNew[i] = dict()
    for j in range(ADDRMAN_BUCKET_SIZE):
        vvNew[i][j] = -1

for i in range(ADDRMAN_TRIED_BUCKET_COUNT):
    vvTried[i] = dict()
    for j in range(ADDRMAN_BUCKET_SIZE):
        vvTried[i][j] = -1

#Erebus Parameters (configurable)

log_file = open("emulation.log", "w+")
addr_filename = "./data/addr-msg.txt"
seed_filename = "./data/dns-seed.txt"
life_cycle_path = "./data/ip-life-cycle"

nStart = 1542584783           # Set the inital timestamp for the emulation to run
victim_age = 30               # unit: day
attack_duration = 50          # unit: day
nAttackStart = nStart + victim_age*24*60*60 # Let the victim run for awhile then attack it
nEnd = nAttackStart + 60*60*24*attack_duration + 1

inbound_legitimate_rate = 0.1  # Rate of legitimate IPs via incoming connections
attack_rate = 20               # Shadow IPs rate compared to legitimate IPs
no_conn_behind = 1             # How many outgoing connections we expect to occupy more?
logAll = False                 # log all message?
isAdaptive = False             # reboot?
nCheckSuccessfulRate = 0       # timestamp to check success probability

addr_msg = dict()              # store legitimate IPs with timestamp
malicious_ips = dict()         # store shadow IPs with timestamp
virtual_ips = dict()           # store shadow and virtual IPs
outbound_peers = []            # current outgoing peers.

nNextFeeler = nStart + FEELER_INTERVAL
nNextOpenOutboundConnection = 9999999999 # Next timestamp to open a new outgoing connection because a connection is being terminated

def log(arr):
    global log_file
    string = ""
    for x in arr:
        if isinstance(x, float):
            string += '%.3f' % x + " "
        else:
            string += str(x) + " "
    log_file.write(string + "\n")

def GetNewBucket(sk, src_ip, ip):
    if '.' in src_ip:
        peer_group = src_ip.split('.')[0]+"."+src_ip.split('.')[1]
    else:
        peer_group = src_ip.split(':')[0]+":"+src_ip.split(':')[1]
    if '.' in ip:
        ip_group = ip.split('.')[0]+"."+ip.split('.')[1]
    else:
        ip_group = ip.split(':')[0]+":"+ip.split(':')[1]
    m1 = hashlib.sha256()
    m1.update(str(sk).encode())
    m1.update(str(ip_group).encode('utf-8'))
    m1.update(str(peer_group).encode('utf-8'))
    hash1 = int.from_bytes(m1.digest()[:8],byteorder='big')
    m2 = hashlib.sha256()
    m2.update(str(sk).encode())
    m2.update(str(peer_group).encode('utf-8'))
    m2.update(str(hash1 % ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP).encode())
    hash2 = int.from_bytes(m2.digest()[:8],byteorder='big')
    return hash2 % ADDRMAN_NEW_BUCKET_COUNT

def GetTriedBucket(sk, ip):    
    if '.' in ip:
        ip_group = ip.split('.')[0]+"."+ip.split('.')[1]
    else:
        ip_group = ip.split(':')[0]+":"+ip.split(':')[1]
    m1 = hashlib.sha256()
    m1.update(str(sk).encode())
    m1.update(str(ip).encode('utf-8'))
    hash1 = int.from_bytes(m1.digest()[:8],byteorder='big')
    m2 = hashlib.sha256()
    m2.update(str(sk).encode())
    m2.update(str(ip_group).encode('utf-8'))
    m2.update(str(hash1 % ADDRMAN_TRIED_BUCKETS_PER_GROUP).encode())
    hash2 = int.from_bytes(m2.digest()[:8],byteorder='big')
    return hash2 % ADDRMAN_TRIED_BUCKET_COUNT


def GetBucketPosition(sk, fNew, nBucket, ip):
    m = hashlib.sha256()
    m.update(str(sk).encode())
    if fNew:
        m.update('N'.encode())
    else:
        m.update('K'.encode())
    m.update(str(nBucket).encode())
    m.update(str(ip).encode('utf-8'))
    h = int.from_bytes(m.digest()[:8],byteorder='big')  
    return h % ADDRMAN_BUCKET_SIZE


def IsTerrible(nNow, info):
    nLastTry = info["nLastTry"]
    nTime = info["nTime"]
    nLastSuccess = info["nLastSuccess"]
    nAttempts = info["nAttempts"]
    if logAll:
        log([nNow, "IsTerrible", info["addr"], "nLastTry:", nLastTry, "nTime:", nTime, "nLastSuccess:", nLastSuccess, "nAttempts:", nAttempts])
    if nLastTry >= nNow - 60:
        return False
    if nTime > nNow + 10 * 60:
        return True
    if nTime == 0 or nNow - nTime > ADDRMAN_HORIZON_DAYS * 24 * 60 * 60:
        return True

    if nLastSuccess == 0 and nAttempts >= ADDRMAN_RETRIES:
        return True;

    if nNow - nLastSuccess > ADDRMAN_MIN_FAIL_DAYS * 24 * 60 * 60 and nAttempts >= ADDRMAN_MAX_FAILURES:
        return True

    return False;

def GetChance(nNow, info):
    nLastTry = info["nLastTry"]
    nAttempts = info["nAttempts"]
    fChance = 1.0
    nSinceLastTry = max(nNow - nLastTry, 0)
    if nSinceLastTry < 60 * 10:
        fChance *= 0.01
    fChance *= pow(0.66, min(nAttempts, 8))
    if logAll:
        log([nNow, "GetChance", info["addr"], info["addr"] in malicious_ips, fChance])
    return fChance

def Create(nTime, src_ip, ip):
    global nIdCount
    nIdCount += 1
    nId = nIdCount
    info = dict()
    info["nTime"] = nTime
    info["addr"] = ip
    info["nRefCount"] = 0
    info["nLastTry"] = 0
    info["nLastSuccess"] = 0
    info["nAttempts"] = 0
    info["addrSource"] = src_ip
    info["fInTried"] = False

    mapInfo[nId] = info
    mapAddr[ip] = nId
    if logAll:
        log([nTime, "Create", "src_ip", src_ip, "ip", ip, "nId", nId])

def Delete(ip): # Completely remove an IP from new table
    if ip not in mapAddr:
        return
    if mapAddr[ip] not in mapInfo:
        return
    info = mapInfo[mapAddr[ip]]
    if "addr" not in info or ("addr" in info and info["addr"] != ip):
        return
    if "fInTried" in info and info["fInTried"]:
        return
    if "nRefCount" in info and info["nRefCount"] > 0:
        return
    if logAll:
        log(["Delete", ip])
    del mapInfo[mapAddr[ip]]
    del mapAddr[ip]
    global nNew
    nNew -= 1

def ClearNew(nUBucket, nUBucketPos):
    if vvNew[nUBucket][nUBucketPos] == -1:
        return
    nIdDelete = vvNew[nUBucket][nUBucketPos]
    if "nRefCount" in mapInfo[nIdDelete] and mapInfo[nIdDelete]["nRefCount"] > 0:
        mapInfo[nIdDelete]["nRefCount"] -= 1
        vvNew[nUBucket][nUBucketPos] = -1
    if mapInfo[nIdDelete]["nRefCount"] == 0:
        Delete(mapInfo[nIdDelete]["addr"])
    if logAll:
        log(["ClearNew", nUBucket, nUBucketPos])


def MakeTried(ip):
    if ip not in mapAddr:
        return
    nId = mapAddr[ip]
    if nId not in mapInfo:
        return
    for bucket in range(ADDRMAN_NEW_BUCKET_COUNT):
        pos = GetBucketPosition(nKey, True, bucket, ip)
        if (vvNew[bucket][pos] == nId):
            vvNew[bucket][pos] = -1
            mapInfo[nId]["nRefCount"] -= 1
    global nNew
    global nTried
    nNew -= 1
    nKBucket = GetTriedBucket(nKey, ip)
    nKBucketPos = GetBucketPosition(nKey, False, nKBucket, ip)

    if (vvTried[nKBucket][nKBucketPos] != -1):
        nIdEvict = vvTried[nKBucket][nKBucketPos]
        mapInfo[nIdEvict]["fInTried"] = False
        vvTried[nKBucket][nKBucketPos] = -1
        nTried -= 1
        nUBucket = GetNewBucket(nKey, mapInfo[nIdEvict]["addrSource"],mapInfo[nIdEvict]["addr"])
        nUBucketPos = GetBucketPosition(nKey, True, nUBucket, ip)
        ClearNew(nUBucket, nUBucketPos)
        mapInfo[nIdEvict]["nRefCount"] = 1
        vvNew[nUBucket, nUBucketPos] = nIdEvict
        nNew += 1

    vvTried[nKBucket][nKBucketPos] = nId
    mapInfo[nId]["fInTried"] = True
    nTried += 1
    if logAll:
        log(["MakeTried", ip, nKBucket, nKBucketPos])

def Good(ip, test_before_evict, nTime):

    if ip not in mapAddr:
        return
    nId = mapAddr[ip]
    if nId not in mapInfo:
        return
    info = mapInfo[nId]
    info["nLastSuccess"] = nTime
    info["nLastTry"] = nTime
    info["nAttempts"] = 0
    mapInfo[nId] = info

    tried_bucket = GetTriedBucket(nKey, ip)
    tried_bucket_pos = GetBucketPosition(nKey, False, tried_bucket, ip)
    if logAll:
        log(["Good", nTime, ip, nId, test_before_evict, tried_bucket, tried_bucket_pos])
    if info["fInTried"]:
        return
    if test_before_evict and vvTried[tried_bucket][tried_bucket_pos] != -1:
        if logAll:
            log([nTime, "Tried collision at ", "bucket=", tried_bucket, "slot=", tried_bucket_pos, "between", ip, mapInfo[vvTried[tried_bucket][tried_bucket_pos]]["addr"]])
        global m_tried_collisions
        if len(m_tried_collisions) < ADDRMAN_SET_TRIED_COLLISION_SIZE:
            m_tried_collisions += [nId]
    else:
        MakeTried(ip)


def Add(nNow, src_ip, ip, nTimePenalty):
    if logAll:
        log([nNow,"Add", src_ip, ip, ip in malicious_ips])
    if ip not in mapAddr:
        Create(nNow, src_ip, ip)
        mapInfo[mapAddr[ip]]["nTime"] = max(0, mapInfo[mapAddr[ip]]["nTime"]-nTimePenalty)
        global nNew
        nNew += 1
        nId = mapAddr[ip]
        pinfo = mapInfo[nId]
    else:
        nId = mapAddr[ip]
        pinfo = mapInfo[nId]
        fCurrentlyOnline = nNow-pinfo["nTime"] < 24*60*60
        nUpdateInterval = 60*60 if fCurrentlyOnline else 24*60*60
        if pinfo["nTime"] < nNow-nUpdateInterval-nTimePenalty:
            if logAll:
                log([nNow,"nTime updated", ip, ip in malicious_ips, pinfo["nTime"]])
            pinfo["nTime"] = max(0, nNow-nTimePenalty)
            mapInfo[nId] = pinfo
        if nNow <= pinfo["nTime"]:
            return
        if "fInTried" in pinfo and pinfo["fInTried"]:
            return
        if pinfo["nRefCount"] >= ADDRMAN_NEW_BUCKETS_PER_ADDRESS:
            return 
        nFactor = pow(2, pinfo["nRefCount"])
        if nFactor > 1 and random.randint(0, nFactor) != 0:
            return

    nUBucket = GetNewBucket(nKey, src_ip, ip)
    nUBucketPos = GetBucketPosition(nKey, True, nUBucket, ip)
    if (vvNew[nUBucket][nUBucketPos] != nId):
        fInsert = vvNew[nUBucket][nUBucketPos] == -1
        if not fInsert:
            infoExisting = mapInfo[vvNew[nUBucket][nUBucketPos]]
            if IsTerrible(nNow, infoExisting) or (infoExisting["nRefCount"] > 1 and pinfo["nRefCount"] == 0):
                if logAll:
                    log([nNow, "New collision at", "bucket=", nUBucket, "slot=", nUBucketPos, "between", ip, ip in malicious_ips, "and", infoExisting["addr"], infoExisting["addr"] in malicious_ips, "existing is terrible"])
                fInsert = True
            else:
                if logAll:
                    log([nNow, "New collision at", "bucket=", nUBucket, "slot=", nUBucketPos, "between", ip, ip in malicious_ips, "and", infoExisting["addr"], infoExisting["addr"] in malicious_ips, "inserting is ignored"])
        if fInsert:
            ClearNew(nUBucket, nUBucketPos)
            pinfo["nRefCount"] += 1
            mapInfo[nId] = pinfo
            vvNew[nUBucket][nUBucketPos] = nId
        else:
            if pinfo["nRefCount"] == 0:
                Delete(pinfo["addr"])
    if logAll:
        log([nNow, "After add", "bucket=", nUBucket, "slot=", nUBucketPos, mapInfo[vvNew[nUBucket][nUBucketPos]]["addr"], mapInfo[vvNew[nUBucket][nUBucketPos]]["addr"] in malicious_ips])

def Select(nNow, newOnly):
    if nNew == 0 and nTried == 0:
        return -1
    if not newOnly and (nTried > 0 and (nNew == 0 or random.randint(0,1) == 0)):
        fChanceFactor = 1.0
        while True:
            nKBucket = random.randint(0, ADDRMAN_TRIED_BUCKET_COUNT-1)
            nKBucketPos = random.randint(0, ADDRMAN_BUCKET_SIZE-1)
            while vvTried[nKBucket][nKBucketPos] == -1:
                nKBucket = (nKBucket + random.randint(0, ADDRMAN_TRIED_BUCKET_COUNT-1)) % ADDRMAN_TRIED_BUCKET_COUNT
                nKBucketPos = (nKBucketPos + random.randint(0, ADDRMAN_BUCKET_SIZE-1)) % ADDRMAN_BUCKET_SIZE
            nId = vvTried[nKBucket][nKBucketPos]
            if nId not in mapInfo:
                continue
            if random.randint(0, pow(2, 30))*1.0 < fChanceFactor * GetChance(nNow, mapInfo[nId]) * pow(2,30):
                return nId
            fChanceFactor *= 1.2
    else:
        fChanceFactor = 1.0
        while True:
            nUBucket = random.randint(0, ADDRMAN_NEW_BUCKET_COUNT-1)
            nUBucketPos = random.randint(0, ADDRMAN_BUCKET_SIZE-1)
            while vvNew[nUBucket][nUBucketPos] == -1:
                nUBucket = (nUBucket + random.randint(0, ADDRMAN_NEW_BUCKET_COUNT-1)) % ADDRMAN_NEW_BUCKET_COUNT
                nUBucketPos = (nUBucketPos + random.randint(0, ADDRMAN_BUCKET_SIZE-1)) % ADDRMAN_BUCKET_SIZE
            nId = vvNew[nUBucket][nUBucketPos]
            if nId not in mapInfo:
                continue
            if random.randint(0, pow(2, 30))*1.0 < fChanceFactor * GetChance(nNow, mapInfo[nId]) * pow(2,30):
                return nId
            fChanceFactor *= 1.2

def ResolveCollisions(nNow):
    if len(m_tried_collisions) <= 0:
        return
    if logAll:
        log([nNow, "ResolveCollisions", m_tried_collisions])
    for nId in m_tried_collisions:
        erase_collision = False
        if nId not in mapInfo:
            erase_collision = True
        else:
            info_new = mapInfo[nId]
            ip = info_new["addr"]
            tried_bucket = GetTriedBucket(nKey, ip)
            tried_bucket_pos = GetBucketPosition(nKey, False, tried_bucket, ip)
            if vvTried[tried_bucket][tried_bucket_pos] == -1:
                Good(ip, False, nNow)
                erase_collision = True
            else:
                info_old = mapInfo[vvTried[tried_bucket][tried_bucket_pos]]
                if nNow - info_old["nLastSuccess"] < ADDRMAN_REPLACEMENT_HOURS*60*60:
                    erase_collision = True
                elif nNow - info_old["nLastTry"] < ADDRMAN_REPLACEMENT_HOURS*60*60:
                    if nNow - info_old["nLastTry"] > 60:
                        Good(ip, False, nNow)
                        erase_collision = True
        if erase_collision:
            if logAll:
                log([nNow, "Tried collision resolved", nId])
            m_tried_collisions.remove(nId)

def SelectTriedCollision(nNow):
    if len(m_tried_collisions) == 0:
        return -1
    id_new = random.sample(m_tried_collisions,1)[0]
    info_new = mapInfo[id_new]
    ip = info_new["addr"]

    tried_bucket = GetTriedBucket(nKey, ip)
    tried_bucket_pos = GetBucketPosition(nKey, False, tried_bucket, ip)
    if logAll:
        log([nNow, "SelectTriedCollision", vvTried[tried_bucket][tried_bucket_pos], mapInfo[vvTried[tried_bucket][tried_bucket_pos]]["addr"]])
    return vvTried[tried_bucket][tried_bucket_pos]

def IsReachable(nNow, ip):
    if ip in malicious_ips and nNow >= nAttackStart:
        return (True, 9999999999)
    filename = life_cycle_path+ip+".txt"
    if not os.path.isfile(filename):
        return (False, 9999999999)
    with open(filename) as f:
        line_list = f.readlines()
    if len(line_list) == 0:
        # print(line_list, ip, filename)
        return (False, 9999999999)
    line = [x.strip() for x in line_list][0]
    line_str = line.split(" ")
    if line_str[0] != ip:
        return (False, 9999999999)
    for i in range(1, len(line_str)):
        ts_period = line_str[i]
        ts_start = int(ts_period.split("-")[0])
        ts_end = int(ts_period.split("-")[1])
        if ts_start <= nNow and nNow <= ts_end:
            return (True, ts_end)
    return (False, 9999999999)

def extract_group(prefix):
    if ':' in prefix:
        ipstr = str(prefix).split('/')[0] if '/' in str(prefix) else str(prefix)
        splt = ipaddress.ip_address(ipstr).exploded.split(':')
        return splt[0] + ':' + splt[1]
    splt = prefix.split('.')
    return splt[0] + '.' + splt[1]

def get_random_ip():
    if random.randint(0,1) == 0:
        bits = random.getrandbits(32)
        addr = IPv4Address(bits)
        return str(addr)
    bits = random.getrandbits(128)
    addr = IPv6Address(bits)
    return addr.compressed

def check_success_rate(nNow):
    cnt_tried = 0
    cnt_new = 0
    mal_new = 0
    mal_tried = 0
    alive_new = 0
    alive_tried = 0
    virtual_new = 0
    virtual_tried = 0

    for i in range(ADDRMAN_NEW_BUCKET_COUNT):
        for j in range(ADDRMAN_BUCKET_SIZE):
            if vvNew[i][j] != -1:
                if mapInfo[vvNew[i][j]]["addr"] in malicious_ips:
                    mal_new += 1
                if mapInfo[vvNew[i][j]]["addr"] in virtual_ips:
                    virtual_new += 1
                (reachable, _) = IsReachable(nNow, mapInfo[vvNew[i][j]]["addr"])
                if reachable:
                    alive_new += 1
                cnt_new += 1

    for i in range(ADDRMAN_TRIED_BUCKET_COUNT):
        for j in range(ADDRMAN_BUCKET_SIZE):
            if vvTried[i][j] != -1:
                if mapInfo[vvTried[i][j]]["addr"] in malicious_ips:
                    mal_tried += 1
                if mapInfo[vvTried[i][j]]["addr"] in virtual_ips:
                    virtual_tried += 1
                (reachable, _) = IsReachable(nNow, mapInfo[vvTried[i][j]]["addr"])
                if reachable:
                    alive_tried += 1
                cnt_tried += 1

    malicious_outbound_peer_cnt = 0
    for outbound_peer in outbound_peers:
        if outbound_peer[0] in malicious_ips:
            malicious_outbound_peer_cnt += 1

    success_rate = (mal_new/alive_new*0.5 + mal_tried/alive_tried*0.5)
    complete_success_rate = pow(success_rate, nMaxOutbound)
    expected_malicious_outbound_peer = nMaxOutbound * success_rate

    log([nNow, "Attack status", nCheckSuccessfulRate, "days: New(virtual/shadow/alive/total)", virtual_new, mal_new, alive_new, cnt_new, "Tried(virtual/shadow/alive/total)", virtual_tried, mal_tried, alive_tried, cnt_tried, success_rate, malicious_outbound_peer_cnt, expected_malicious_outbound_peer])
    if (malicious_outbound_peer_cnt + no_conn_behind < expected_malicious_outbound_peer or complete_success_rate >= 0.15) and malicious_outbound_peer_cnt < nMaxOutbound and isAdaptive:
        log([nNow, "Attack status", "Expect to occupy more", malicious_outbound_peer_cnt, expected_malicious_outbound_peer, complete_success_rate])
        nNextOpenOutboundConnection = 9999999999
        for outbound_peer in outbound_peers[:]:
            addr = outbound_peer[0]
            log([nNow, nCheckSuccessfulRate, "days", "Reboot victim: Disconnecting outbound connection with",addr, addr in malicious_ips])
            outbound_peers.remove(outbound_peer)
    return nCheckSuccessfulRate + 1


def prep_data():

    t1 = time.time()

    with open(addr_filename) as f:
        line_list = f.readlines()
    line_list = [x.strip() for x in line_list]

    for line in line_list:
        line_str = line.split(" ")
        timestamp = int(line_str[0])
        src_ip = line_str[1]
        ip = line_str[2]
        is_shadow = int(line_str[3])
        from_outbound = int(line_str[4])
        if is_shadow == 1:
            malicious_ips[ip] = 1
        if timestamp not in addr_msg:
            addr_msg[timestamp] = [[src_ip, ip, from_outbound]]
        else:
            addr_msg[timestamp] += [[src_ip, ip, from_outbound]]

    with open(seed_filename) as f:
        line_list = f.readlines()
    starter_ips = [x.strip() for x in line_list]
    for ip in starter_ips:
        src_ip = "127.0.1.1"
        nNow = nStart-3*24*60*60-random.randint(0,4)*24*60*60
        Add(nNow, src_ip, ip, 0)

    t2 = time.time()
    print("Preparation done in ", t2-t1)

prep_data()

t1 = time.time()

# MAIN LOOP
for nNow in range(nStart, nEnd):

    # Check success rate every day 
    if nNow >= nAttackStart + nCheckSuccessfulRate*24*60*60:
        nCheckSuccessfulRate = check_success_rate(nNow)

    # It's time to check if any existing outbound connection ends
    if nNow > nNextOpenOutboundConnection:
        for outbound_peer in outbound_peers[:]:
            addr = outbound_peer[0]
            cycle_end = outbound_peer[1]
            if nNow > cycle_end:
                if logAll or True:
                    log([nNow, "Disconnecting outbound connection with", addr, addr in malicious_ips])
                outbound_peers.remove(outbound_peer)

    # Skip no-event timestamps
    nOutbound = len(outbound_peers)
    if nOutbound >= nMaxOutbound and nNow <= nNextFeeler and nNow not in addr_msg:
        continue

    if nNow in addr_msg:
        to_add = []
        if nNow >= nAttackStart:
            legitimate_outbound_peer_cnt = 0
            legitimate_outbound_peers = []
            for outbound_peer in outbound_peers:
                if outbound_peer[0] not in malicious_ips:
                    legitimate_outbound_peer_cnt += 1
                    legitimate_outbound_peers += [outbound_peer[0]]
            leg_cnt = 0
            if nOutbound != 0:
                outbound_legitimate_rate = legitimate_outbound_peer_cnt*1.0/nOutbound
                if nNow in addr_msg:
                    for (src_ip, ip, from_outbound) in addr_msg[nNow]:
                        if from_outbound == 1 and random.randint(0, pow(2, 30))*1.0 <= outbound_legitimate_rate * pow(2,30):
                            src_ip = random.sample(legitimate_outbound_peers,1)[0]
                        elif from_outbound == 0:
                            if ip not in virtual_ips:
                                if random.randint(0, pow(2, 30))*1.0 <= inbound_legitimate_rate * pow(2,30) :
                                    leg_cnt += 1
                                else:
                                    continue
                        to_add += [[src_ip, ip]]

            if logAll or False:
                log([nNow, "Legitimate ADDR",leg_cnt, "Legitimate outbound peers", legitimate_outbound_peer_cnt])

            malicious_ip_cnt = leg_cnt*attack_rate
            if logAll or False:
                log([nNow, "Malicious ADDR",malicious_ip_cnt, "Malicious outbound peers", nOutbound-legitimate_outbound_peer_cnt])

            next_ts = nNow + 30*24*60*60 - random.randint(0,4)*24*60*60
            if next_ts not in addr_msg:
                addr_msg[next_ts] = []
            for cnt in range(malicious_ip_cnt):
                src_ip = get_random_ip()
                ip = get_random_ip()
                malicious_ips[ip] = 1
                virtual_ips[ip] = 1
                to_add += [[src_ip, ip]]
                addr_msg[next_ts] += [[src_ip, ip, 0]]
        else:
            for (src_ip, ip, from_outbound) in addr_msg[nNow]:
                if from_outbound == 1 and nOutbound > 0:
                    src_ip = random.sample(outbound_peers,1)[0][0]
                to_add += [[src_ip, ip]]

        random.shuffle(to_add)
        for (src_ip, ip) in to_add:
            Add(nNow, src_ip, ip, nTimePenalty)

        if (nOutbound >= nMaxOutbound and nNow <= nNextFeeler):
            continue

    addrConnect = ""
    fFeeler = False

    if nOutbound >= nMaxOutbound:
        nNextFeeler = nNow + FEELER_INTERVAL
        fFeeler = True

    ResolveCollisions(nNow)

    nTries = 0

    while True:
        nId = SelectTriedCollision(nNow)
        if not fFeeler or nId == -1:
            nId = Select(nNow, fFeeler)
        if nId == -1:
            break
        current_group = []
        for outbound_peer in outbound_peers:
            addr = outbound_peer[0]
            current_group += [extract_group(addr)]
        addr = mapInfo[nId]["addr"]
        if extract_group(addr) in current_group and not fFeeler:
            break
        nTries += 1
        if nTries > 100:
            break
        if (nNow - mapInfo[nId]["nLastTry"] < 600 and nTries < 30):
            continue
        addrConnect = addr
        break

    if addrConnect != "":
        if fFeeler:
            if logAll:
                log([nNow, "Making feeler connection to", addrConnect, nNextFeeler, reachable])
        nId = mapAddr[addrConnect]    
        (reachable, cycle_end) = IsReachable(nNow, addrConnect)
        if reachable:
            Good(addrConnect, True, nNow)
            if not fFeeler:
                current_nNextOpenOutboundConnection = 9999999999
                for outbound_peer in outbound_peers:
                    current_nNextOpenOutboundConnection = min(current_nNextOpenOutboundConnection, outbound_peer[1])
                outbound_peers += [[addrConnect, cycle_end]]
                current_nNextOpenOutboundConnection = min(current_nNextOpenOutboundConnection, cycle_end)
                nNextOpenOutboundConnection = current_nNextOpenOutboundConnection
                if logAll or True:
                    log([nNow,"Making outbound connection to", addrConnect, addrConnect in malicious_ips, cycle_end])
        else:
            mapInfo[nId]["nAttempts"] += 1
            mapInfo[nId]["nLastTry"] = nNow

t2 = time.time()

log(["Emulated", attack_duration, "days in", t2-t1])