#!/usr/bin/env python

import os
import sys
import ipaddress
import random
import hashlib
# from array import *
from collections import defaultdict
import time
# import numpy as np
import gzip
from operator import itemgetter
import gc
import pyasn
import radix

case_num = 'case1'

##################################################################### Countermeasures Flags
ct1_flag = False
ct2_flag = False
ct3_flag = False
ct4_flag = False
ct5_flag = False
ct6_flag = False

# map to legacy defense IDs
def1_flag = ct4_flag
def2_flag = ct5_flag
def3_flag = ct6_flag
def4_flag = ct2_flag
def5_flag = ct3_flag
def6_flag = ct1_flag

##################################################################### Bitcoin Parameters
ADDRMAN_TRIED_BUCKETS_PER_GROUP = 8
if def2_flag:
    ADDRMAN_TRIED_BUCKET_COUNT = round(256 / 4)
else:
    ADDRMAN_TRIED_BUCKET_COUNT = round(256)

ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP = 64
ADDRMAN_NEW_BUCKET_COUNT = round(1024)
ADDRMAN_BUCKET_SIZE = 64
ADDRMAN_HORIZON_DAYS  = 30
ADDRMAN_RETRIES = 3
ADDRMAN_MAX_FAILURES = 10
ADDRMAN_MIN_FAIL_DAYS = 7
ADDRMAN_NEW_BUCKETS_PER_ADDRESS = 8
ADDRMAN_SET_TRIED_COLLISION_SIZE = 10
ADDRMAN_REPLACEMENT_HOURS = 4
m_max_outbound_full_relay = 8
if def5_flag:
    m_max_outbound_block_relay = 8
else:
    m_max_outbound_block_relay = 2

m_max_outbound = m_max_outbound_full_relay + m_max_outbound_block_relay
nTimePenalty = 2 * 60 * 60

if def3_flag:
    FEELER_INTERVAL = round(30)
else:
    FEELER_INTERVAL = round(120)


##################################################################### Our Parameters
nStart = 1542562302
# nEnd = nStart +  60*60*24*380
nEnd = 1575481296
victim_age = 30
victim_as = sys.argv[2]
# victim_as = "amsterdam01"
nAttackStart = nStart + 60*60*24*victim_age
attacker_as = sys.argv[1]
# attacker_as = 174

nCheckSuccessfulRate = 0
timestamp_margin = 60
reduced_inbound_rate = 0.1
attack_flooding_rate = 2 # IPs/s
malicious_addr_interval = int(1000/attack_flooding_rate)
# random.seed(267)
malicious_outbound_peer_cnt = 0
max_estimated_malicious_outbound_peer = int(sys.argv[3])

# adaptive attack
no_conn_behind = 1
isAdaptive = True

##################################################################### Bitcoin data structure
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
nNextFeeler = nStart + FEELER_INTERVAL


##################################################################### Our data structure
currentOutboundPeers = []
nNextOpenOutboundConnection = 9999999999
legitimate_addr_msg = dict()
malicious_addr_msg = dict()
ip_reachability = dict()
full_shadow_prefix = []
full_shadow_prefix_group = defaultdict()
estimated_shadow_prefix = []
as_path_tree = radix.Radix() # Muoi: use Radix tree for performance
last_time_full_connection = nStart



##################################################################### Bitcoin functions
def GetNewBucket(sk, src_ip, ip):

    if def6_flag:
        peer_group = GetGroup(src_ip)
        ip_group = GetGroup(ip)

    else:
        if '.' in src_ip:
            peer_group = src_ip.split('.')[0]+"."+src_ip.split('.')[1]
        else:
            peer_group = src_ip.split(':')[0]+":"+src_ip.split(':')[1]
        if '.' in ip:
            ip_group = ip.split('.')[0]+"."+ip.split('.')[1]
        else:
            ip_group = ip.split(':')[0]+":"+ip.split(':')[1]

    hash1 = int(hashlib.sha256((sk+ip_group+peer_group).encode()).hexdigest(),base=16) 
    hash2 = int(hashlib.sha256((sk+peer_group+str(hash1%ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP)).encode()).hexdigest(), base=16)
    return hash2 % ADDRMAN_NEW_BUCKET_COUNT

def GetTriedBucket(sk, ip):
    if def6_flag:
        ip_group = GetGroup(ip)
    else:
        if '.' in ip:
            ip_group = ip.split('.')[0]+"."+ip.split('.')[1]
        else:
            ip_group = ip.split(':')[0]+":"+ip.split(':')[1]

    hash1 = int(hashlib.sha256((sk+ip).encode()).hexdigest(), base=16)
    hash2 = int(hashlib.sha256((sk+ip_group+str(hash1 % ADDRMAN_TRIED_BUCKETS_PER_GROUP)).encode()).hexdigest(), base=16)
    return hash2 % ADDRMAN_TRIED_BUCKET_COUNT


def GetBucketPosition(sk, fNew, nBucket, ip):
    if fNew:
        h = int(hashlib.sha256((sk+'N'+str(nBucket)+ip).encode()).hexdigest(), base=16)
    else:
        h = int(hashlib.sha256((sk+'K'+str(nBucket)+ip).encode()).hexdigest(), base=16)
    return h % ADDRMAN_BUCKET_SIZE


def IsTerrible(nNow, info):
    nLastTry = info["nLastTry"]
    nTime = info["nTime"]
    nLastSuccess = info["nLastSuccess"]
    nAttempts = info["nAttempts"]
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
    return fChance

# used for our own randomization (guaranteed to be IPv4)
def GetGroupPrefix(prefix):
    # v4, try to lookup in asn db
    ip = str(ipaddress.ip_interface(prefix_str).network.network_address)
    asn, _ = asn_db.lookup(ip)

    if asn != None:
        # we found the asn number
        return str(asn)
    else:
        # could not find asn, fall back to /16 based group
        return ip.split(".")[0] + "." + ip.split(".")[1]

def GetGroup(prefix):
    if def6_flag:
        # if v6, don't lookup asn
        if ':' in prefix:
            return prefix.split(":")[0] + "." + prefix.split(":")[1]

        else:
            # v4, try to lookup in asn db
            asn, _ = asn_db.lookup(prefix)
        
            if asn != None:
                # we found the asn number
                return str(asn)
            else:
                # could not find asn, fall back to /16 based group
                return prefix.split(".")[0] + "." + prefix.split(".")[1]
    else:
        prefix = str(prefix)
        if ':' in prefix:
            ipstr = str(prefix).split('/')[0] if '/' in str(prefix) else str(prefix)
            splt = ipaddress.ip_address(ipstr).exploded.split(':')
            return splt[0] + ':' + splt[1]
        splt = prefix.split('.')
        return splt[0] + '.' + splt[1]



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
    if info["fInTried"]:
        return
    if test_before_evict and vvTried[tried_bucket][tried_bucket_pos] != -1:
        global m_tried_collisions
        if len(m_tried_collisions) < ADDRMAN_SET_TRIED_COLLISION_SIZE:
            m_tried_collisions += [nId]
    else:
        MakeTried(ip)


def Add(nNow, src_ip, ip, nTimePenalty):
    if ip == "":
        return
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
                    fInsert = True
        if fInsert:
            ClearNew(nUBucket, nUBucketPos)        
            pinfo["nRefCount"] += 1
            mapInfo[nId] = pinfo
            vvNew[nUBucket][nUBucketPos] = nId
        else:
            if pinfo["nRefCount"] == 0:
                Delete(pinfo["addr"])

def Select(nNow, newOnly):
    if nNew == 0 and nTried == 0:
        return -1
    
    if def1_flag:
        if nTried > ADDRMAN_TRIED_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE / 4:
            fSelectFromTried = 1
        else:
            fSelectFromTried = 0.5
        if not newOnly and (nTried > 0 and (nNew == 0 or random.random() <= fSelectFromTried)):
            fChanceFactor = 1.0
            while True:
                nKBucket = int(random.random()*ADDRMAN_TRIED_BUCKET_COUNT)
                nKBucketPos = int(random.random()*ADDRMAN_BUCKET_SIZE)
                while vvTried[nKBucket][nKBucketPos] == -1:
                    nKBucket = (nKBucket+int(random.random()*ADDRMAN_TRIED_BUCKET_COUNT))%ADDRMAN_TRIED_BUCKET_COUNT
                    nKBucketPos=(nKBucketPos+int(random.random()*ADDRMAN_BUCKET_SIZE))%ADDRMAN_BUCKET_SIZE
                nId = vvTried[nKBucket][nKBucketPos]
                if nId not in mapInfo:
                    continue
                if random.random() < fChanceFactor * GetChance(nNow, mapInfo[nId]):
                    return nId
                fChanceFactor *= 1.2
        else:
            fChanceFactor = 1.0
            while True:
                nUBucket = int(random.random()*ADDRMAN_NEW_BUCKET_COUNT)
                nUBucketPos = int(random.random()*ADDRMAN_BUCKET_SIZE)
                while vvNew[nUBucket][nUBucketPos] == -1:
                    nUBucket = (nUBucket+int(random.random()*ADDRMAN_NEW_BUCKET_COUNT))%ADDRMAN_NEW_BUCKET_COUNT
                    nUBucketPos=(nUBucketPos+int(random.random()*ADDRMAN_BUCKET_SIZE))%ADDRMAN_BUCKET_SIZE
                nId = vvNew[nUBucket][nUBucketPos]
                if nId not in mapInfo:
                    continue
                if random.random() < fChanceFactor * GetChance(nNow, mapInfo[nId]):
                    return nId
                fChanceFactor *= 1.2

    else:
        if not newOnly and (nTried > 0 and (nNew == 0 or random.randint(0,1) == 0)):
            fChanceFactor = 1.0
            while True:
                nKBucket = int(random.random()*ADDRMAN_TRIED_BUCKET_COUNT)
                nKBucketPos = int(random.random()*ADDRMAN_BUCKET_SIZE)
                while vvTried[nKBucket][nKBucketPos] == -1:
                    nKBucket = (nKBucket+int(random.random()*ADDRMAN_TRIED_BUCKET_COUNT))%ADDRMAN_TRIED_BUCKET_COUNT
                    nKBucketPos=(nKBucketPos+int(random.random()*ADDRMAN_BUCKET_SIZE))%ADDRMAN_BUCKET_SIZE
                nId = vvTried[nKBucket][nKBucketPos]
                if nId not in mapInfo:
                    continue
                if random.random() < fChanceFactor * GetChance(nNow, mapInfo[nId]):
                    return nId
                fChanceFactor *= 1.2
        else:
            fChanceFactor = 1.0
            while True:
                nUBucket = int(random.random()*ADDRMAN_NEW_BUCKET_COUNT)
                nUBucketPos = int(random.random()*ADDRMAN_BUCKET_SIZE)
                while vvNew[nUBucket][nUBucketPos] == -1:
                    nUBucket = (nUBucket+int(random.random()*ADDRMAN_NEW_BUCKET_COUNT))%ADDRMAN_NEW_BUCKET_COUNT
                    nUBucketPos=(nUBucketPos+int(random.random()*ADDRMAN_BUCKET_SIZE))%ADDRMAN_BUCKET_SIZE
                nId = vvNew[nUBucket][nUBucketPos]
                if nId not in mapInfo:
                    continue
                if random.random() < fChanceFactor * GetChance(nNow, mapInfo[nId]):
                    return nId
                fChanceFactor *= 1.2

def ResolveCollisions(nNow):
    if len(m_tried_collisions) <= 0:
        return
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
                    if nNow - info_old["nLastTry"] > 0:
                        Good(ip, False, nNow)
                        erase_collision = True
        if erase_collision:
            m_tried_collisions.remove(nId)

def SelectTriedCollision(nNow):
    if len(m_tried_collisions) == 0:
        return -1
    id_new = random.sample(m_tried_collisions,1)[0]
    info_new = mapInfo[id_new]
    ip = info_new["addr"]

    tried_bucket = GetTriedBucket(nKey, ip)
    tried_bucket_pos = GetBucketPosition(nKey, False, tried_bucket, ip)
    return vvTried[tried_bucket][tried_bucket_pos]

def ThreadOpenConnections(nNow):
    addrConnect = ""
    global currentOutboundPeers
    global nNextOpenOutboundConnection
    global nNextFeeler
    global malicious_outbound_peer_cnt

    as_count_on_existing_conn = dict() # Muoi: count AS on existing connections
    as_path = []
    nOutboundFullRelay = 0
    nOutboundBlockRelay = 0
    setConnected = set([])
    closted_cycle_end = 9999999999

    for (addr, cycle_end, block_relay_only, as_path, _) in currentOutboundPeers:
        setConnected.add(GetGroup(addr))
        if block_relay_only:
            nOutboundBlockRelay += 1
        else:
            nOutboundFullRelay += 1
        closted_cycle_end = min(closted_cycle_end, cycle_end)
        for asn in as_path:
            if asn not in as_count_on_existing_conn:
                as_count_on_existing_conn[asn] = 1
            else:
                as_count_on_existing_conn[asn] += 1


    fFeeler = False

    if nOutboundFullRelay >= m_max_outbound_full_relay and nOutboundBlockRelay >= m_max_outbound_block_relay:
        if nNow > nNextFeeler:
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
        addr = mapInfo[nId]["addr"]
        if GetGroup(addr) in setConnected and not fFeeler:
            break
        nTries += 1
        if nTries > 10:
            break
        if (nNow - mapInfo[nId]["nLastTry"] < 600 and nTries < 3):
            continue
        if not fFeeler:
            rnode = as_path_tree.search_best(addr)
            as_path_to_this_ip = []
            if rnode == None: # muoi: if we cannot find addr, we skip it
                continue
            else:
                as_path_to_this_ip = rnode.data[0] # muoi: retrieve the as-path
                # continue
            
            can_choose = True
            for asn in as_path_to_this_ip:
                if asn in as_count_on_existing_conn:
                    if as_count_on_existing_conn[asn] + 1 > max_estimated_malicious_outbound_peer: # muoi: if any AS violates
                        can_choose = False
                        # print("Cannot choose", addr, "because", asn, "will appear more than", max_estimated_malicious_outbound_peer)
                        break
            if not can_choose:
                continue
            else:
                as_path = as_path_to_this_ip
        addrConnect = addr

        break

    if addrConnect != "":
        nId = mapAddr[addrConnect]    
        (reachable, cycle_end) = IsReachable(nNow, addrConnect)
        if reachable:
            Good(addrConnect, True, nNow)
            if not fFeeler:
                block_relay_only = nOutboundBlockRelay < m_max_outbound_block_relay and nOutboundFullRelay >= m_max_outbound_full_relay
                is_shadow = search_index(addrConnect, full_shadow_prefix) != -1
                currentOutboundPeers += [(addrConnect, cycle_end, block_relay_only, as_path, is_shadow)]
                nNextOpenOutboundConnection = min(closted_cycle_end, cycle_end)
                if is_shadow and nNow > nAttackStart:
                    malicious_outbound_peer_cnt += 1
        else:
            mapInfo[nId]["nAttempts"] += 1
            mapInfo[nId]["nLastTry"] = nNow 


##################################################################### Our functions
def read_file(filename):
    if filename == "":
        return []
    with open(filename) as f:
        line_list = f.readlines()
    line_list = [x.strip() for x in line_list]
    return line_list

# def find_nearest(timestamp, value):
#     timestamp = np.asarray(timestamp)
#     idx = (np.abs(timestamp - value)).argmin()
#     return timestamp[idx]

def IsReachable(nNow, ip):
    if nNow >= nAttackStart:
        if search_index(ip, full_shadow_prefix) != -1:
            return (True, 9999999999)

    if ip in ip_reachability:
        for (ts_start, ts_end) in ip_reachability[ip]:
            if ts_start - timestamp_margin <= nNow and nNow <= ts_end + timestamp_margin:
                return (True, ts_end)
    return (False, 9999999999)

def search_index(x, tuple_list):
    if isinstance(x, str) and ("." in x or ":" in x):
        x = int(ipaddress.ip_address(x))
    low = 0
    high = len(tuple_list)-1
    while (low <= high):
        mid = (low + high) >> 1
        if x >= tuple_list[mid][0] and x <= tuple_list[mid][1]:
            return mid
        elif x < tuple_list[mid][0]:
            high = mid - 1
        else:
            low = mid + 1
    return -1

def get_random_ip(prefix_group, prefix_index, prefix_group_keys):
    if len(prefix_group_keys) == 0:
        return ""
    chosen_group = random.choice(prefix_group_keys)
    prefixes = prefix_group[chosen_group]
    indexes = prefix_index[chosen_group]
    sum_index = indexes[-1][1]+1
    select_index = int(random.random()*sum_index)
    idx = search_index(select_index, indexes)
    select_prefix = prefixes[idx]
    select_ip_int = int(random.random()*(select_prefix[1]-select_prefix[0]))+select_prefix[0]
    select_ip = ipaddress.ip_address(select_ip_int)
    return str(select_ip), select_prefix[0], chosen_group

def check_success_rate(nNow):
    cnt_tried = 0
    cnt_new = 0
    mal_new = 0
    mal_tried = 0
    alive_new = 0
    alive_tried = 0

    global no_conn_behind
    global isAdaptive
    global nNextOpenOutboundConnection
    global malicious_outbound_peer_cnt
    global currentOutboundPeers

    for i in range(ADDRMAN_NEW_BUCKET_COUNT):
        for j in range(ADDRMAN_BUCKET_SIZE):
            if vvNew[i][j] != -1:
                addr = mapInfo[vvNew[i][j]]["addr"]

                if search_index(addr, full_shadow_prefix) != -1:
                    mal_new += 1

                (reachable, _) = IsReachable(nNow, addr)
                if reachable:
                    alive_new += 1
                cnt_new += 1

    for i in range(ADDRMAN_TRIED_BUCKET_COUNT):
        for j in range(ADDRMAN_BUCKET_SIZE):
            if vvTried[i][j] != -1:
                addr = mapInfo[vvTried[i][j]]["addr"]

                if search_index(addr, full_shadow_prefix) != -1:
                    mal_tried += 1

                (reachable, _) = IsReachable(nNow, addr)
                if reachable:
                    alive_tried += 1
                cnt_tried += 1

    if alive_new == 0 or alive_tried == 0:
        return

    if def1_flag:
        success_rate = (mal_tried/alive_tried)
    else:
        success_rate = (mal_new/alive_new*0.5 + mal_tried/alive_tried*0.5)

    complete_success_rate = pow(success_rate, m_max_outbound)
    expected_malicious_outbound_peer = m_max_outbound * success_rate

    # print([nNow, "Attack status", nCheckSuccessfulRate, "days: New(shadow/alive/total)", mal_new, alive_new, cnt_new, "Tried(shadow/alive/total)", mal_tried, alive_tried, cnt_tried, success_rate, malicious_outbound_peer_cnt, expected_malicious_outbound_peer])
    if def4_flag:
        if (malicious_outbound_peer_cnt + no_conn_behind < expected_malicious_outbound_peer or complete_success_rate >= 0.15) and malicious_outbound_peer_cnt < m_max_outbound and isAdaptive:
            # print([nNow, "Attack status", "Expect to occupy more", malicious_outbound_peer_cnt, expected_malicious_outbound_peer, complete_success_rate])
            print('Reboot triggered!')
            # filtering block only first
            nNextOpenOutboundConnection = 9999999999
            nextOutboundPeers = [(addr, cycle_end, block_relay_only, is_estimated_shadow, is_shadow) for (addr, cycle_end, block_relay_only, is_estimated_shadow, is_shadow) in currentOutboundPeers if block_relay_only]

            # picking only two at maximum
            if len(nextOutboundPeers) > 2:
                nextOutboundPeers = random.sample(nextOutboundPeers, 2)

            malicious_outbound_peer_cnt = 0

            for (addr, cycle_end, block_relay_only, _, is_shadow) in nextOutboundPeers:
                nNextOpenOutboundConnection = min(nNextOpenOutboundConnection, cycle_end)
                if is_shadow:
                    malicious_outbound_peer_cnt += 1

            # assigning the two anchor connectoins
            currentOutboundPeers = nextOutboundPeers

    else:
        if (malicious_outbound_peer_cnt + no_conn_behind < expected_malicious_outbound_peer or complete_success_rate >= 0.15) and malicious_outbound_peer_cnt < m_max_outbound and isAdaptive:
            # print([nNow, "Attack status", "Expect to occupy more", malicious_outbound_peer_cnt, expected_malicious_outbound_peer, complete_success_rate])
            print('Reboot triggered!')
            nNextOpenOutboundConnection = 9999999999
            for outbound_peer in currentOutboundPeers[:]:
                addr = outbound_peer[0]
                # is_malicious = outbound_peer[4]
                # print([nNow, nCheckSuccessfulRate, "days", "Reboot victim: Disconnecting outbound connection with",addr, is_malicious])
                currentOutboundPeers.remove(outbound_peer)

            malicious_outbound_peer_cnt = 0

    return nCheckSuccessfulRate + 1

def mergeIntervals(arr):
    arr.sort(key = lambda x: x[0]) 
    m = [] 
    s = -1
    max = -1
    for i in range(len(arr)): 
        a = arr[i] 
        if a[0] > max: 
            if i != 0: 
                m.append([s,max]) 
            max = a[1] 
            s = a[0] 
        else: 
            if a[1] >= max: 
                max = a[1]   
    if max != -1 and [s, max] not in m: 
        m.append([s, max]) 
    return m

def load_legitimate_addr_message(filename):
    with gzip.GzipFile(filename, 'r') as f:
        addr_messages = f.read().decode('utf-8')
    legitimate_addr_msg = []
    legitimate_addr_msg_ts = []
    for msg in addr_messages.split("\n"):
        if msg == "":
            continue
        msg_split = msg.split("\t")
        if len(msg_split) <= 1:
            continue
        timestamp = int(msg_split[0])
        if timestamp < nStart or timestamp > nEnd:
            continue
        legitimate_addr_msg_ts += [timestamp]
        this_ts = []
        for t_split in msg_split[1:]:
            s_split = t_split.split(" ")
            src_ip = s_split[0]
            this_ts += [(src_ip, s_split[1:])]
        legitimate_addr_msg += [this_ts]
    # legitimate_addr_msg_ts = sorted(legitimate_addr_msg_ts)
    legitimate_addr_msg_ts = set(legitimate_addr_msg_ts)
    return legitimate_addr_msg, legitimate_addr_msg_ts

def load_ip_reachability(filename):
    with gzip.GzipFile(filename, 'r') as f:
        ip_reachability_str = f.read().decode('utf-8')
    ip_reachability = dict()
    for line in ip_reachability_str.split("\n"):
        if line == "":
            continue
        line_split = line.split("\t")
        ip = line_split[0]
        ip_reachability[ip] = []
        for period in line_split[1:]:
            period_split = period.split(" ")
            ts_start = int(period_split[0])
            ts_end = int(period_split[1])
            ip_reachability[ip] += [(ts_start, ts_end)]
    return ip_reachability

##################################################################### Data preparation
t1 = time.time()

# ensure output exists
if not os.path.exists('output'):
    os.mkdir('output')

# if case1 check if number of shadow IPs are >= 10
# if not we can skip the simulation
# note: the emulator will still run for 30 days to evaluate the connection-making behaviour of the node
# this is particularly useful is case2/3 where we may be interested in the effect of \tau.
if case_num == 'case1':
    with open("./data/full-shadow-stats/" + str(attacker_as) + "-" + str(victim_as) + ".txt") as fd:
        num_prefix_group = int(fd.read().split()[1])
        if num_prefix_group < 10:
            # impossible attack.. skip
            impossible_attack_flag = True

# if case2/3 check if number of hidden-shadow IPs are >= 10
# if not we can skip the simulation
impossible_attack_flag = False
if case_num == 'case2' or case_num == 'case3':
    with open("./data/hidden-shadow-stats/" + str(attacker_as) + "-" + str(victim_as) + ".txt") as fd:
        num_prefix_group = int(fd.read().split()[1])
        if num_prefix_group < 10:
            # impossible attack.. skip
            impossible_attack_flag = True

# Load bitnodes data to test for reachability
ip_reachability = load_ip_reachability("./data/ip-reachability-stripped-incoming-addr-after-30.txt.gz")

# Load IPs to be seeded to the node before it starts
starter_ips = read_file("./data/random-reachable-ips-dns-1542562102.txt")

# Load legitimate IPs
legitimate_addr_msg, legitimate_addr_msg_ts = load_legitimate_addr_message("./data/ip-from-addr-stripped-incoming-addr-after-30.txt.gz")

# Load malicious IPs
full_shadow_prefix_str = read_file("./data/shadow-prefix-traceroute/"+str(attacker_as) +"-" + str(victim_as)+".txt")
if case_num == 'case1':
    estimated_shadow_prefix_str = []
elif case_num == 'case2':
    estimated_shadow_prefix_str = read_file("./data/shadow-prefix-estimation/"+attacker_as+"-"+victim_as+".txt")
elif case_num == 'case3':
    estimated_shadow_prefix_str = read_file("./data/shadow-prefix-estimation/"+attacker_as+"-"+victim_as+".txt")    
else:
    print('Invalid case. Pass `case1` || `case2` || `case3` as third argument.')
    sys.exit(1)

asn_dat_fp = './data/ipasn.20200225.dat'

# initialize pyasn
if def6_flag:
    asn_db = pyasn.pyasn(asn_dat_fp)
else:
    asn_db = None


# IPs that a node starts with
for ip in starter_ips:
    src_ip = "127.0.1.1"
    nNow = nStart-3*24*60*60-random.randint(0,4)*24*60*60
    Add(nNow, src_ip, ip, 0)
del starter_ips
gc.collect()

# constuct full shadow IP set (all IPs that are owned by or pass through given AS)
full_shadow_prefix_index = defaultdict()
for prefix_str in full_shadow_prefix_str:
    if def6_flag:
        group = GetGroupPrefix(prefix_str)
    else:
        group = GetGroup(prefix_str)

    prefix_network = ipaddress.ip_interface(prefix_str).network
    prefix_tuple = (int(prefix_network.network_address), int(prefix_network.broadcast_address))
    full_shadow_prefix += [prefix_tuple]

    prefix_size = prefix_network.num_addresses
    if group not in full_shadow_prefix_group:
        full_shadow_prefix_group[group] = [prefix_tuple]
        full_shadow_prefix_index[group] = [(0, prefix_size-1)]
    else:
        full_shadow_prefix_group[group] += [prefix_tuple]
        sum_index = full_shadow_prefix_index[group][-1][1]+1
        full_shadow_prefix_index[group] += [(sum_index, sum_index+prefix_size-1)]
full_shadow_prefix = mergeIntervals(full_shadow_prefix)
full_shadow_prefix = sorted(full_shadow_prefix, key=itemgetter(0))
full_shadow_prefix_group_keys = list(full_shadow_prefix_group.keys())

# Load AS-paths in the victim view
as_path_str_list = read_file("./data/as-path/"+victim_as+".txt")
for as_path_str in as_path_str_list:
    line_split = as_path_str.split(" ")
    rnode = as_path_tree.add(line_split[0])
    rnode.data[0] = line_split[1:]

# We only need to create malicious addr for 1 month, then we can replay it every month
# may be with a different src_ip
malicious_addr_msg_cnt_monthly = int(60*60*24*30/malicious_addr_interval)
cnt_month = int((nEnd - nAttackStart)/(60*60*24*30))+1
malicious_src_ip_cnt = malicious_addr_msg_cnt_monthly*cnt_month
malicious_src_ip = []

# create dict to broadcast malicious IPs at appropriate time
if case_num == "case1":
    # case 1, blind spot IPs are not seperated explicitly by the attacker
    for i in range(malicious_addr_msg_cnt_monthly):
        ts = i*malicious_addr_interval
        # create list of 1000 IPs per message
        ip_list = []
        for j in range(1000):
            ip, _, _ = get_random_ip(full_shadow_prefix_group, full_shadow_prefix_index, full_shadow_prefix_group_keys)
            ip_list += [ip]
        malicious_addr_msg[ts] = ip_list

elif case_num == "case2":
    # case 2, blind spot IPs are not seperated explicitly by the attacker, but RAP is deployed
    for i in range(malicious_addr_msg_cnt_monthly):
        ts = i*malicious_addr_interval
        # create list of 1000 IPs per message
        ip_list = []
        for j in range(1000):
            ip, prefix, group = get_random_ip(full_shadow_prefix_group, full_shadow_prefix_index, full_shadow_prefix_group_keys)
            ip_list += [ip]

        malicious_addr_msg[ts] = ip_list

else:
    # case 3, RAP is deployed optimize for blind_spot IPs
    blind_spot_prefix_str = list(set(full_shadow_prefix_str)-set(estimated_shadow_prefix_str))
    blind_spot_prefix_index = defaultdict()
    blind_spot_prefix_group = defaultdict()
    blind_spot_prefix = []
    total_ips = 0
    for prefix_str in blind_spot_prefix_str:

        # we update the view of the victim here
        if "47065" not in victim_as:
            rnode = as_path_tree.search_exact(prefix_str)
            if rnode != None:
                if attacker_as in rnode.data[0]:
                    rnode.data[0].remove(attacker_as)

        if def6_flag:
            group = GetGroupPrefix(prefix_str)
        else:
            group = GetGroup(prefix_str)

        prefix_network = ipaddress.ip_interface(prefix_str).network
        prefix_tuple = (int(prefix_network.network_address), int(prefix_network.broadcast_address))
        blind_spot_prefix += [prefix_tuple]

        prefix_size = prefix_network.num_addresses
        total_ips += prefix_size
        if group not in blind_spot_prefix_group:
            blind_spot_prefix_group[group] = [prefix_tuple]
            blind_spot_prefix_index[group] = [(0, prefix_size-1)]
        else:
            blind_spot_prefix_group[group] += [prefix_tuple]
            sum_index = blind_spot_prefix_index[group][-1][1]+1
            blind_spot_prefix_index[group] += [(sum_index, sum_index+prefix_size-1)]
    blind_spot_prefix_group_keys = list(blind_spot_prefix_group.keys())

    total_addr_msg_cnt = malicious_addr_msg_cnt_monthly * 1000
    # calculate minimum number of hidden shadow IPs to be broadcast -> 5 mil * (k - t)/k
    repeat_constant = 5
    min_malicious_addrs = total_addr_msg_cnt * (m_max_outbound - max_estimated_malicious_outbound_peer) / m_max_outbound

    # keep filling hidden shadow IPs until we reach min_malicious_addrs
    blind_spot_addr_count = 0
    all_mal_ip_list = []
    done_flag = False
    extra_flag = False

    while True:
        if len(blind_spot_prefix) == 0:
            break

        # try enumerating through all blind_spots, repeat_constant number of times
        for i in range(repeat_constant):
            for prefix in blind_spot_prefix:
                nw_address = prefix[0]
                bc_address = prefix[1]

                # enumerate bw tuple range
                for ip_int in range(nw_address, bc_address + 1):
                    ip_str = str(ipaddress.ip_address(ip_int))

                    all_mal_ip_list += [ip_str]
                    blind_spot_addr_count += 1

                    # in case we fill up everything, break
                    if blind_spot_addr_count >= total_addr_msg_cnt:
                        done_flag = True
                        break

                    # in case we are filling up extra blind spot IPs, and have reached the min_malicious_addrs target, break
                    if extra_flag and blind_spot_addr_count >= min_malicious_addrs:
                        done_flag = True
                        break

                if done_flag:
                    break

            if done_flag:
                break

        if done_flag:
            break

        # if we still haven't filled upto min_malicious_addrs, repeat again
        if blind_spot_addr_count < min_malicious_addrs:
            extra_flag = True

    # at this point, we have filled up at least min_malicious_addrs number of blind spot IPs
    # add shadow IPs to fill up the remainder of the list (if needed)
    all_addr_count = blind_spot_addr_count
    while all_addr_count < total_addr_msg_cnt:
        ip, _, _ = get_random_ip(full_shadow_prefix_group, full_shadow_prefix_index, full_shadow_prefix_group_keys)
        all_mal_ip_list += [ip]

        all_addr_count += 1

    # our list is ready.. shuffle
    random.shuffle(all_mal_ip_list)

    # split into separate addr messages
    for i in range(malicious_addr_msg_cnt_monthly):
        ts = i * malicious_addr_interval

        # check if we're within the index range
        if (i + 1) * 1000 < len(all_mal_ip_list):
            malicious_addr_msg[ts] = all_mal_ip_list[i*1000 : (i+1)*1000]
        
        else:
            # just add remainder and exit loop
            malicious_addr_msg[ts] = all_mal_ip_list[i*1000 : ] 
            break

    del blind_spot_prefix_group
    del blind_spot_prefix_index
    del blind_spot_prefix_group_keys
    del blind_spot_prefix_str
    del blind_spot_prefix

del full_shadow_prefix_group
del full_shadow_prefix_index
del full_shadow_prefix_group_keys
del full_shadow_prefix_str
del estimated_shadow_prefix_str


t2 = time.time()
print("Preparation done", attacker_as, victim_as, t2-t1)
gc.collect()

##################################################################### Main emulation

t1 = time.time()

# Main loop

legitimate_addr_msg_iter = 0

for nNow in range(nStart, nEnd):

    # Check success rate every day 
    if nNow >= nStart + nCheckSuccessfulRate*24*60*60:
        print(nCheckSuccessfulRate, attacker_as, victim_as, malicious_outbound_peer_cnt, len(currentOutboundPeers))

        if nNow >= nAttackStart:
            if impossible_attack_flag:
                # terminate
                malicious_outbound_peer_cnt = -1
                break
    
        nCheckSuccessfulRate += 1

    # It's time to check if any existing outbound connection ends
    if nNow >= nNextOpenOutboundConnection:
        for outbound_peer in currentOutboundPeers[:]:
            (addr, cycle_end, _, _, is_shadow) = outbound_peer
            if nNow >= cycle_end:
                if is_shadow and nNow > nAttackStart:
                    malicious_outbound_peer_cnt -= 1
                currentOutboundPeers.remove(outbound_peer)


    # prepare legitimate addresses to broadcast (i.e. addresses that are broadcast from legitimate peers)
    to_add_addr_msg = []
    if nNow in legitimate_addr_msg_ts:
        this_ts = legitimate_addr_msg[legitimate_addr_msg_iter]
        legitimate_addr_msg_iter += 1
        for (src_ip, ip_list) in this_ts:
            from_outbound = "8333" in src_ip
            for ip in ip_list:
                if from_outbound:
                    if len(currentOutboundPeers) > 0:
                        (random_outbound_peer, _, _, _, is_shadow) = random.choice(currentOutboundPeers)
                        if not is_shadow:
                            to_add_addr_msg += [(random_outbound_peer, ip)]
                else:
                    to_add_addr_msg += [(src_ip.split(":")[0], ip)]

    # broadcast malicious addresses if it is time
    if nNow >= nAttackStart:
        malicious_ts = (nNow-nStart) % (60*60*24*30)
        if malicious_ts in malicious_addr_msg:
            # generate random source
            bits = random.getrandbits(32)
            src_ip = str(ipaddress.ip_address(bits))
            for ip in malicious_addr_msg[malicious_ts]:
                to_add_addr_msg += [(src_ip, ip)]
    for (src_ip, ip) in to_add_addr_msg:
        Add(nNow, src_ip, ip, nTimePenalty)

    # open a new connection if a) there are less than m_max_outbound connections and 
    # b) if we're trying to make a feeler connection
    if len(currentOutboundPeers) < m_max_outbound or nNow > nNextFeeler:
        ThreadOpenConnections(nNow)
        if len(currentOutboundPeers) >= m_max_outbound:
            last_time_full_connection = nNow
        # if we weren't able to make a full connection in the past hour, readjust m_max_outbound to currentOutboundPeers
        if  nNow - last_time_full_connection > 60 * 60:
            # readjusting
            m_max_outbound = len(currentOutboundPeers)
            if m_max_outbound <= m_max_outbound_full_relay:
                # reset full_relay to m_max_outbound and block_relay to 0
                m_max_outbound_full_relay = m_max_outbound
                m_max_outbound_block_relay = 0
            else:
                # leave m_max_outbound_full_relay untouched; adjust block relay
                m_max_outbound_block_relay = m_max_outbound - m_max_outbound_full_relay

        if malicious_outbound_peer_cnt >= m_max_outbound:
            break

t2 = time.time()

# save o/p
with open("output/"+str(attacker_as)+"-"+str(victim_as)+".txt", "w") as log_file:
    log_arr = ["Days:", int((nNow-nStart)/(60*60*24)) - 30, "Attacker:", attacker_as, "Victim:", victim_as, "SimTime:", t2 - t1, "Occupied:", malicious_outbound_peer_cnt, "Outbound:", len(currentOutboundPeers)]
    string = ""
    for x in log_arr:
        if isinstance(x, float):
            string += '%.3f' % x + " "
        else:
            string += str(x) + " "
    log_file.write(string + "\n")

print("Emulated", int((nNow-nStart)/(60*60*24)), "days in", t2-t1, attacker_as, victim_as, "occupy", malicious_outbound_peer_cnt, "tau", max_estimated_malicious_outbound_peer)
