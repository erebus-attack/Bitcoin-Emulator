import random
import hashlib
import ipaddress

from cfg import Config
from . import get_config
import src.libemulate as libemulate

COUNTERMEASURES, ADDRMAN_PARAMS, EMU_PARAMS, EMU_VARS = get_config()

class CAddrMan:
    """
    We try to faithfully replicate Bitcoin's peer management protocol.
    The functions have been translated from the actual Bitcoin source code to accurately replicate
    behaviour.
    """

    def __init__(self, asn_db):
        self.nIdCount = 0
        self.nKey = "1313842542810890645741820448452432526161972925574964606024061314128846616260L"
        self.mapInfo = dict()
        self.mapAddr = dict()
        self.vvNew = dict()
        self.vvTried = dict()
        self.m_tried_collisions = []
        self.nNew = 0
        self.nTried = 0

        for i in range(ADDRMAN_PARAMS.ADDRMAN_NEW_BUCKET_COUNT):
            self.vvNew[i] = dict()
            for j in range(ADDRMAN_PARAMS.ADDRMAN_BUCKET_SIZE):
                self.vvNew[i][j] = -1

        for i in range(ADDRMAN_PARAMS.ADDRMAN_TRIED_BUCKET_COUNT):
            self.vvTried[i] = dict()
            for j in range(ADDRMAN_PARAMS.ADDRMAN_BUCKET_SIZE):
                self.vvTried[i][j] = -1

        self.nNextFeeler = EMU_PARAMS.nStart + ADDRMAN_PARAMS.FEELER_INTERVAL

        # mechanism to lookup ASN numbers
        self.asn_db = asn_db

    def GetNewBucket(self, sk, src_ip, ip):
        if COUNTERMEASURES.ct1_flag:
            peer_group = self.GetGroup(src_ip)
            ip_group = self.GetGroup(ip)

        else:
            if '.' in src_ip:
                peer_group = src_ip.split('.')[0] + "." + src_ip.split('.')[1]
            else:
                peer_group = src_ip.split(':')[0] + ":" + src_ip.split(':')[1]
            if '.' in ip:
                ip_group = ip.split('.')[0] + "." + ip.split('.')[1]
            else:
                ip_group = ip.split(':')[0] + ":" + ip.split(':')[1]

        hash1 = int(hashlib.sha256((sk + ip_group + peer_group).encode()).hexdigest(), base=16) 
        hash2 = int(hashlib.sha256((sk + peer_group + str(hash1 % ADDRMAN_PARAMS.ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP)).encode()).hexdigest(), base=16)
        return hash2 % ADDRMAN_PARAMS.ADDRMAN_NEW_BUCKET_COUNT

    def GetTriedBucket(self, sk, ip):
        if COUNTERMEASURES.ct1_flag:
            ip_group = self.GetGroup(ip)

        else:
            if '.' in ip:
                ip_group = ip.split('.')[0] + "." + ip.split('.')[1]
            else:
                ip_group = ip.split(':')[0] + ":" + ip.split(':')[1]

        hash1 = int(hashlib.sha256((sk + ip).encode()).hexdigest(), base=16)
        hash2 = int(hashlib.sha256((sk + ip_group + str(hash1 % ADDRMAN_PARAMS.ADDRMAN_TRIED_BUCKETS_PER_GROUP)).encode()).hexdigest(), base=16)
        return hash2 % ADDRMAN_PARAMS.ADDRMAN_TRIED_BUCKET_COUNT

    def GetBucketPosition(self, sk, fNew, nBucket, ip):
        if fNew:
            h = int(hashlib.sha256((sk + 'N' + str(nBucket) + ip).encode()).hexdigest(), base=16)
        else:
            h = int(hashlib.sha256((sk + 'K' + str(nBucket) + ip).encode()).hexdigest(), base=16)
        return h % ADDRMAN_PARAMS.ADDRMAN_BUCKET_SIZE

    def IsTerrible(self, nNow, info):
        nLastTry = info["nLastTry"]
        nTime = info["nTime"]
        nLastSuccess = info["nLastSuccess"]
        nAttempts = info["nAttempts"]
        if nLastTry >= nNow - 60:
            return False
        if nTime > nNow + 10 * 60:
            return True
        if nTime == 0 or nNow - nTime > ADDRMAN_PARAMS.ADDRMAN_HORIZON_DAYS * 24 * 60 * 60:
            return True

        if nLastSuccess == 0 and nAttempts >= ADDRMAN_PARAMS.ADDRMAN_RETRIES:
            return True;

        if nNow - nLastSuccess > ADDRMAN_PARAMS.ADDRMAN_MIN_FAIL_DAYS * 24 * 60 * 60 and nAttempts >= ADDRMAN_PARAMS.ADDRMAN_MAX_FAILURES:
            return True

        return False;

    def GetChance(self, nNow, info):
        nLastTry = info["nLastTry"]
        nAttempts = info["nAttempts"]
        fChance = 1.0

        nSinceLastTry = max(nNow - nLastTry, 0)
        if nSinceLastTry < 60 * 10:
            fChance *= 0.01

        fChance *= pow(0.66, min(nAttempts, 8))
        return fChance

    def GetGroup(self, prefix):
        if COUNTERMEASURES.ct1_flag:
            # group based on AS Number
            if ':' in prefix:
                # if v6, don't lookup asn
                return prefix.split(":")[0] + "." + prefix.split(":")[1]

            else:
                # v4, try to lookup in asn db
                asn, _ = self.asn_db.lookup(prefix)

                if asn != None:
                    # we found the asn number
                    return str(asn)
                else:
                    # could not find asn, fall back to /16 based group
                    return prefix.split(".")[0] + "." + prefix.split(".")[1]

        else:
            # group based on /16 prefix
            prefix = str(prefix)

            if ':' in prefix:
                ipstr = str(prefix).split('/')[0] if '/' in str(prefix) else str(prefix)
                splt = ipaddress.ip_address(ipstr).exploded.split(':')
                return splt[0] + ':' + splt[1]

            splt = prefix.split('.')
            return splt[0] + '.' + splt[1]

    def Create(self, nTime, src_ip, ip):
        self.nIdCount += 1
        nId = self.nIdCount

        info = dict()
        info["nTime"] = nTime
        info["addr"] = ip
        info["nRefCount"] = 0
        info["nLastTry"] = 0
        info["nLastSuccess"] = 0
        info["nAttempts"] = 0
        info["addrSource"] = src_ip
        info["fInTried"] = False

        self.mapInfo[nId] = info
        self.mapAddr[ip] = nId

    def Delete(self, ip):
        if ip not in self.mapAddr:
            return
        if self.mapAddr[ip] not in self.mapInfo:
            return

        info = self.mapInfo[self.mapAddr[ip]]

        if "addr" not in info or ("addr" in info and info["addr"] != ip):
            return
        if "fInTried" in info and info["fInTried"]:
            return
        if "nRefCount" in info and info["nRefCount"] > 0:
            return

        del self.mapInfo[self.mapAddr[ip]]
        del self.mapAddr[ip]

        self.nNew -= 1

    def ClearNew(self, nUBucket, nUBucketPos):
        if self.vvNew[nUBucket][nUBucketPos] == -1:
            return

        nIdDelete = self.vvNew[nUBucket][nUBucketPos]

        if "nRefCount" in self.mapInfo[nIdDelete] and self.mapInfo[nIdDelete]["nRefCount"] > 0:
            self.mapInfo[nIdDelete]["nRefCount"] -= 1
            self.vvNew[nUBucket][nUBucketPos] = -1

        if self.mapInfo[nIdDelete]["nRefCount"] == 0:
            self.Delete(self.mapInfo[nIdDelete]["addr"])

    def MakeTried(self, ip):
        if ip not in self.mapAddr:
            return

        nId = self.mapAddr[ip]
        if nId not in self.mapInfo:
            return

        for bucket in range(ADDRMAN_PARAMS.ADDRMAN_NEW_BUCKET_COUNT):
            pos = self.GetBucketPosition(self.nKey, True, bucket, ip)
            if (self.vvNew[bucket][pos] == nId):
                self.vvNew[bucket][pos] = -1
                self.mapInfo[nId]["nRefCount"] -= 1

        self.nNew -= 1

        nKBucket = self.GetTriedBucket(self.nKey, ip)
        nKBucketPos = self.GetBucketPosition(self.nKey, False, nKBucket, ip)

        if (self.vvTried[nKBucket][nKBucketPos] != -1):
            nIdEvict = self.vvTried[nKBucket][nKBucketPos]

            self.mapInfo[nIdEvict]["fInTried"] = False
            self.vvTried[nKBucket][nKBucketPos] = -1
            self.nTried -= 1

            nUBucket = self.GetNewBucket(self.nKey, self.mapInfo[nIdEvict]["addrSource"], self.mapInfo[nIdEvict]["addr"])
            nUBucketPos = self.GetBucketPosition(self.nKey, True, nUBucket, ip)
            self.ClearNew(nUBucket, nUBucketPos)

            self.mapInfo[nIdEvict]["nRefCount"] = 1
            self.vvNew[nUBucket, nUBucketPos] = nIdEvict
            self.nNew += 1

        self.vvTried[nKBucket][nKBucketPos] = nId
        self.mapInfo[nId]["fInTried"] = True
        self.nTried += 1

    def Good(self, ip, test_before_evict, nTime):
        if ip not in self.mapAddr:
            return
        nId = self.mapAddr[ip]
        if nId not in self.mapInfo:
            return

        info = self.mapInfo[nId]
        info["nLastSuccess"] = nTime
        info["nLastTry"] = nTime
        info["nAttempts"] = 0
        self.mapInfo[nId] = info

        tried_bucket = self.GetTriedBucket(self.nKey, ip)
        tried_bucket_pos = self.GetBucketPosition(self.nKey, False, tried_bucket, ip)

        if info["fInTried"]:
            return
        if test_before_evict and self.vvTried[tried_bucket][tried_bucket_pos] != -1:
            if len(self.m_tried_collisions) < ADDRMAN_PARAMS.ADDRMAN_SET_TRIED_COLLISION_SIZE:
                self.m_tried_collisions += [nId]
        else:
            self.MakeTried(ip)

    def Add(self, nNow, src_ip, ip, nTimePenalty):
        if ip == "":
            return
        if ip not in self.mapAddr:
            self.Create(nNow, src_ip, ip)
            self.mapInfo[self.mapAddr[ip]]["nTime"] = max(0, self.mapInfo[self.mapAddr[ip]]["nTime"] - nTimePenalty)

            self.nNew += 1
            nId = self.mapAddr[ip]
            pinfo = self.mapInfo[nId]

        else:
            nId = self.mapAddr[ip]
            pinfo = self.mapInfo[nId]

            fCurrentlyOnline = nNow - pinfo["nTime"] < 24 * 60 * 60
            nUpdateInterval = 60 * 60 if fCurrentlyOnline else 24 * 60 * 60

            if pinfo["nTime"] < nNow - nUpdateInterval - nTimePenalty:
                pinfo["nTime"] = max(0, nNow - nTimePenalty)
                self.mapInfo[nId] = pinfo

            if nNow <= pinfo["nTime"]:
                return
            if "fInTried" in pinfo and pinfo["fInTried"]:
                return
            if pinfo["nRefCount"] >= ADDRMAN_PARAMS.ADDRMAN_NEW_BUCKETS_PER_ADDRESS:
                return

            nFactor = pow(2, pinfo["nRefCount"])
            if nFactor > 1 and random.randint(0, nFactor) != 0:
                return

        nUBucket = self.GetNewBucket(self.nKey, src_ip, ip)
        nUBucketPos = self.GetBucketPosition(self.nKey, True, nUBucket, ip)

        if (self.vvNew[nUBucket][nUBucketPos] != nId):
            fInsert = self.vvNew[nUBucket][nUBucketPos] == -1
            if not fInsert:
                infoExisting = self.mapInfo[self.vvNew[nUBucket][nUBucketPos]]
                if self.IsTerrible(nNow, infoExisting) or (infoExisting["nRefCount"] > 1 and pinfo["nRefCount"] == 0):
                    fInsert = True

            if fInsert:
                self.ClearNew(nUBucket, nUBucketPos)
                pinfo["nRefCount"] += 1
                self.mapInfo[nId] = pinfo
                self.vvNew[nUBucket][nUBucketPos] = nId

            else:
                if pinfo["nRefCount"] == 0:
                    self.Delete(pinfo["addr"])

    def Select(self, nNow, newOnly):
        if self.nNew == 0 and self.nTried == 0:
            return -1

        # table selection chance
        fSelectFromTried = 0.5

        if COUNTERMEASURES.ct4_flag:
            # try to select from tried preferentially (if there are sufficient addresses)
            if self.nTried > ADDRMAN_PARAMS.ADDRMAN_TRIED_BUCKET_COUNT * ADDRMAN_PARAMS.ADDRMAN_BUCKET_SIZE / 4:
                fSelectFromTried = 1

        if not newOnly and (self.nTried > 0 and (self.nNew == 0 or random.random() <= fSelectFromTried)):
            fChanceFactor = 1.0
            while True:
                nKBucket = int(random.random() * ADDRMAN_PARAMS.ADDRMAN_TRIED_BUCKET_COUNT)
                nKBucketPos = int(random.random() * ADDRMAN_PARAMS.ADDRMAN_BUCKET_SIZE)

                while self.vvTried[nKBucket][nKBucketPos] == -1:
                    nKBucket = (nKBucket + int(random.random() * ADDRMAN_PARAMS.ADDRMAN_TRIED_BUCKET_COUNT)) % ADDRMAN_PARAMS.ADDRMAN_TRIED_BUCKET_COUNT
                    nKBucketPos = (nKBucketPos + int(random.random() * ADDRMAN_PARAMS.ADDRMAN_BUCKET_SIZE)) % ADDRMAN_PARAMS.ADDRMAN_BUCKET_SIZE

                nId = self.vvTried[nKBucket][nKBucketPos]

                if nId not in self.mapInfo:
                    continue
                if random.random() < fChanceFactor * self.GetChance(nNow, self.mapInfo[nId]):
                    return nId

                fChanceFactor *= 1.2

        else:
            fChanceFactor = 1.0
            while True:
                nUBucket = int(random.random() * ADDRMAN_PARAMS.ADDRMAN_NEW_BUCKET_COUNT)
                nUBucketPos = int(random.random() * ADDRMAN_PARAMS.ADDRMAN_BUCKET_SIZE)

                while self.vvNew[nUBucket][nUBucketPos] == -1:
                    nUBucket = (nUBucket + int(random.random() * ADDRMAN_PARAMS.ADDRMAN_NEW_BUCKET_COUNT)) % ADDRMAN_PARAMS.ADDRMAN_NEW_BUCKET_COUNT
                    nUBucketPos = (nUBucketPos + int(random.random() * ADDRMAN_PARAMS.ADDRMAN_BUCKET_SIZE)) % ADDRMAN_PARAMS.ADDRMAN_BUCKET_SIZE

                nId = self.vvNew[nUBucket][nUBucketPos]

                if nId not in self.mapInfo:
                    continue
                if random.random() < fChanceFactor * self.GetChance(nNow, self.mapInfo[nId]):
                    return nId

                fChanceFactor *= 1.2

    def ResolveCollisions(self, nNow):
        if len(self.m_tried_collisions) <= 0:
            return

        for nId in self.m_tried_collisions:
            erase_collision = False
            if nId not in self.mapInfo:
                erase_collision = True

            else:
                info_new = self.mapInfo[nId]
                ip = info_new["addr"]
                tried_bucket = self.GetTriedBucket(self.nKey, ip)
                tried_bucket_pos = self.GetBucketPosition(self.nKey, False, tried_bucket, ip)

                if self.vvTried[tried_bucket][tried_bucket_pos] == -1:
                    self.Good(ip, False, nNow)
                    erase_collision = True

                else:
                    info_old = self.mapInfo[self.vvTried[tried_bucket][tried_bucket_pos]]
                    if nNow - info_old["nLastSuccess"] < ADDRMAN_PARAMS.ADDRMAN_REPLACEMENT_HOURS * 60 * 60:
                        erase_collision = True
                    elif nNow - info_old["nLastTry"] < ADDRMAN_PARAMS.ADDRMAN_REPLACEMENT_HOURS * 60 * 60:
                        if nNow - info_old["nLastTry"] > 0:
                            self.Good(ip, False, nNow)
                            erase_collision = True

            if erase_collision:
                self.m_tried_collisions.remove(nId)

    def SelectTriedCollision(self, nNow):
        if len(self.m_tried_collisions) == 0:
            return -1

        id_new = random.sample(self.m_tried_collisions, 1)[0]
        info_new = self.mapInfo[id_new]
        ip = info_new["addr"]

        tried_bucket = self.GetTriedBucket(self.nKey, ip)
        tried_bucket_pos = self.GetBucketPosition(self.nKey, False, tried_bucket, ip)

        return self.vvTried[tried_bucket][tried_bucket_pos]

    def ThreadOpenConnections(self, nNow):
        addrConnect = ""

        # the RAP defense keeps track of the number of times an ASN appears on path a connection
        as_count_on_existing_conn = dict()
        as_path = []
        nOutboundFullRelay = 0
        nOutboundBlockRelay = 0
        connectedSet = set([])
        closted_cycle_end = 9999999999

        for (addr, cycle_end, block_relay_only, as_path, _) in EMU_VARS.currentOutboundPeers:
            connectedSet.add(self.GetGroup(addr))
            if block_relay_only:
                nOutboundBlockRelay += 1
            else:
                nOutboundFullRelay += 1

            closted_cycle_end = min(closted_cycle_end, cycle_end)

            # construct map to keep count of ASes on paths to outbound peers
            if EMU_PARAMS.rap_enabled:
                for asn in as_path:
                    if asn not in as_count_on_existing_conn:
                        as_count_on_existing_conn[asn] = 1
                    else:
                        as_count_on_existing_conn[asn] += 1

        # check if we must make a feeler connection
        fFeeler = False
        if nOutboundFullRelay >= ADDRMAN_PARAMS.m_max_outbound_full_relay and nOutboundBlockRelay >= ADDRMAN_PARAMS.m_max_outbound_block_relay:
            if nNow > EMU_VARS.nNextFeeler:
                EMU_VARS.nNextFeeler = nNow + ADDRMAN_PARAMS.FEELER_INTERVAL
                fFeeler = True

        self.ResolveCollisions(nNow)

        nTries = 0

        while True:
            nId = self.SelectTriedCollision(nNow)
            if not fFeeler or nId == -1:
                nId = self.Select(nNow, fFeeler)
            if nId == -1:
                break

            addr = self.mapInfo[nId]["addr"]
            if self.GetGroup(addr) in connectedSet and not fFeeler:
                break

            nTries += 1

            if nTries > 10:
                break
            if (nNow - self.mapInfo[nId]["nLastTry"] < 600 and nTries < 3):
                continue

            # if we're making an outgoing connection, and rap is enabled, check if within contraints
            if EMU_PARAMS.rap_enabled and not fFeeler:
                # try to retrieve AS path for the node
                as_path_to_this_ip = []
                node = EMU_VARS.as_path_tree.search_best(addr) # radix search

                # if we don't find addr, we skip it
                if node == None:
                    continue
                else:
                    as_path_to_this_ip = node.data[0]

                # check if this candidate shares an AS with other connections more than tau number of times
                can_choose = True
                for asn in as_path_to_this_ip:
                    if asn in as_count_on_existing_conn:
                        if as_count_on_existing_conn[asn] + 1 > EMU_PARAMS.threshold_tau:
                            # pick a new connection
                            can_choose = False
                            break

                if not can_choose:
                    continue
                else:
                    as_path = as_path_to_this_ip

            addrConnect = addr
            break

        if addrConnect != "":
            nId = self.mapAddr[addrConnect]
            (reachable, cycle_end) = libemulate.is_reachable(nNow, addrConnect)
            # cycle_end keeps track of when IP will go offline next

            if reachable:
                # mark address as good
                self.Good(addrConnect, True, nNow)

                if not fFeeler:
                    # open connection if not feeler
                    # check if block_relay_only
                    block_relay_only = nOutboundBlockRelay < ADDRMAN_PARAMS.m_max_outbound_block_relay and nOutboundFullRelay >= ADDRMAN_PARAMS.m_max_outbound_full_relay
                    # check if shadow IP
                    is_shadow = libemulate.search_prefix_list(addrConnect, EMU_VARS.prefixes_list_shadow) != -1
                    # add to currentOutboundPeers
                    EMU_VARS.currentOutboundPeers += [(addrConnect, cycle_end, block_relay_only, as_path, is_shadow)]
                    # check when to open next outbound connection
                    EMU_VARS.nNextOpenOutboundConnection = min(closted_cycle_end, cycle_end)
                    # if we are connecting to a shadow IP, increase malicious count
                    if is_shadow and nNow > EMU_PARAMS.nAttackStart:
                        EMU_VARS.shadow_outbound_peer_cnt += 1

            else:
                # IP unreachable
                self.mapInfo[nId]["nAttempts"] += 1
                self.mapInfo[nId]["nLastTry"] = nNow 
