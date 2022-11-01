# Library contains helper functions and utilities to perform emulation
import ipaddress
import random
import time

from cfg import Config
from . import get_config

COUNTERMEASURES, ADDRMAN_PARAMS, EMU_PARAMS, EMU_VARS = get_config()

def search_prefix_list(ip, prefix_list):
    """
    Check if IP address exists in some prefix which is part of `prefix_list`
    `prefix_list` must be a list of tuples
    Each tuple must be of form (ip_prefix_begin, ip_prefix_end) in int equivalent (check preparation step)
    1. Convert IP to int equivalent
    2. Binary search through list of tuples. Check if ip falls between (tuple[0], tuple[1])
    3. Return prefix if it does
    """
    if isinstance(ip, str) and ("." in ip or ":" in ip):
        ip = int(ipaddress.ip_address(ip))

    low = 0
    high = len(prefix_list) - 1

    while (low <= high):
        mid = (low + high) >> 1 # divide by 2
        if ip >= prefix_list[mid][0] and ip <= prefix_list[mid][1]:
            return mid
        elif ip < prefix_list[mid][0]:
            high = mid - 1
        else:
            low = mid + 1

    return -1

def is_reachable(nNow, ip):
    """
    Is `ip` reachable (online) at time `nNow`?
    If IP is a shadow IP, it is always reachable.
    """
    if nNow >= EMU_PARAMS.nAttackStart:
        # if it is shadow
        if search_prefix_list(ip, EMU_VARS.prefixes_list_shadow) != -1:
            return (True, 9999999999)

    # else, check the bitnodes dataset
    if ip in EMU_VARS.ip_reachability:
        for (ts_start, ts_end) in EMU_VARS.ip_reachability[ip]:
            # add a 60 second margin
            if ts_start - 60 <= nNow and nNow <= ts_end + 60:
                return (True, ts_end)

    return (False, 9999999999)

def check_success_rate(nNow, addrman):
    """
    Measure the rate of the progression of the attack and trigger a reboot of the node (if set and
    if required).
    The goal of the attacker is to force the node to select shadow IP addresses as outbound 
    connections. The protocol (under standard operation) selects either of the 2 tables with a 50%
    chance. Further, the IP must also be reachable (alive) at that time moment.

    The success rate is measured as the probability that the node will select a shadow IP address.    
        -> Pr(selecting shadow) = (shadow_new / alive_new) * 0.5 + (shadow_tried / alive_tried) * 0.5

    The probability that all outgoing connections would be shadow IPs:
        -> Pr(selecting all outbound as shadow) = pow(Pr(selecting shadow), m_max_outbound)

    Expected number of shadow outgoing connections:
        -> E(selecting all outbound as shadow) = Pr(selecting shadow) * m_max_outbound

    A reboot is triggered under the following conditions:
    - EMU_PARAMS.is_adaptive is true
    - EMU_VARS.shadow_outbound_peer_cnt < m_max_outbound 
    - E(selecting all outbound as shadow) > EMU_VARS.shadow_outbound_peer_cnt + 1 or Pr(selecting all outbound as shadow) >= 0.15
        (the first expression says that if the expected number (or potential number) of shadow 
        connections that can be made are greater than 1 + current number of shadow connections,
        then a reboot could increase the count by 1)

    In case COUNTERMEASURES.ct4_flag is set (i.e. preferentially select tried IPs), the 
    rate is calculated only based on tried table IPs.

    In case COUNTERMEASURES.ct2_flag is set (i.e. anchor connections), two connections are
    persisted across reboots.
    """
    cnt_tried = 0
    cnt_new = 0
    shadow_new = 0
    shadow_tried = 0
    alive_new = 0
    alive_tried = 0

    # count IPs in the new table
    for i in range(ADDRMAN_PARAMS.ADDRMAN_NEW_BUCKET_COUNT):
        for j in range(ADDRMAN_PARAMS.ADDRMAN_BUCKET_SIZE):
            if addrman.vvNew[i][j] != -1:
                addr = addrman.mapInfo[addrman.vvNew[i][j]]["addr"]

                if search_prefix_list(addr, EMU_VARS.prefixes_list_shadow) != -1:
                    shadow_new += 1

                (reachable, _) = is_reachable(nNow, addr)
                if reachable:
                    alive_new += 1
                cnt_new += 1

    # count IPs in the tried table
    for i in range(ADDRMAN_PARAMS.ADDRMAN_TRIED_BUCKET_COUNT):
        for j in range(ADDRMAN_PARAMS.ADDRMAN_BUCKET_SIZE):
            if addrman.vvTried[i][j] != -1:
                addr = addrman.mapInfo[addrman.vvTried[i][j]]["addr"]

                if search_prefix_list(addr, EMU_VARS.prefixes_list_shadow) != -1:
                    shadow_tried += 1

                (reachable, _) = is_reachable(nNow, addr)
                if reachable:
                    alive_tried += 1
                cnt_tried += 1

    if alive_new == 0 or alive_tried == 0:
        return

    # calculate the success rate: Pr(selecting shadow)
    if COUNTERMEASURES.ct4_flag:
        success_rate = (shadow_tried/alive_tried)
    else:
        success_rate = (shadow_new/alive_new*0.5 + shadow_tried/alive_tried*0.5)

    # Pr(selecting all outbound as shadow)
    complete_success_rate = pow(success_rate, ADDRMAN_PARAMS.m_max_outbound)

    # E(selecting all outbound as shadow)    
    expected_shadow_outbound_cnt = success_rate * ADDRMAN_PARAMS.m_max_outbound

    # TODO check comment
    # print([nNow, "Attack status", nCheckSuccessfulRate, "days: New(shadow/alive/total)", shadow_new, alive_new, cnt_new, "Tried(shadow/alive/total)", shadow_tried, alive_tried, cnt_tried, success_rate, EMU_VARS.shadow_outbound_peer_cnt, expected_shadow_outbound_cnt])
    if COUNTERMEASURES.ct2_flag:
        # persist 2 connections across reboot (anchor connections)
        if (expected_shadow_outbound_cnt > 1 + EMU_VARS.shadow_outbound_peer_cnt or complete_success_rate >= 0.15) and EMU_VARS.shadow_outbound_peer_cnt < ADDRMAN_PARAMS.m_max_outbound and EMU_PARAMS.is_adaptive:
            # print([nNow, "Attack status", "Expect to occupy more", EMU_VARS.shadow_outbound_peer_cnt, expected_shadow_outbound_cnt, complete_success_rate])
            print('Reboot triggered!')
            EMU_VARS.nNextOpenOutboundConnection = 9999999999

            # filtering block only first
            nextOutboundPeers = [(addr, cycle_end, block_relay_only, is_estimated_shadow, is_shadow) for (addr, cycle_end, block_relay_only, is_estimated_shadow, is_shadow) in EMU_VARS.currentOutboundPeers if block_relay_only]

            # picking only two at maximum
            if len(nextOutboundPeers) > 2:
                nextOutboundPeers = random.sample(nextOutboundPeers, 2)

            # recalculate number of shadow IPs
            EMU_VARS.shadow_outbound_peer_cnt = 0
            for (addr, cycle_end, block_relay_only, _, is_shadow) in nextOutboundPeers:
                EMU_VARS.nNextOpenOutboundConnection = min(EMU_VARS.nNextOpenOutboundConnection, cycle_end)
                if is_shadow:
                    EMU_VARS.shadow_outbound_peer_cnt += 1

            # assigning the two anchor connectoins
            EMU_VARS.currentOutboundPeers = nextOutboundPeers

    else:
        # eject all connections
        if (expected_shadow_outbound_cnt > 1 + EMU_VARS.shadow_outbound_peer_cnt or complete_success_rate >= 0.15) and EMU_VARS.shadow_outbound_peer_cnt < ADDRMAN_PARAMS.m_max_outbound and EMU_PARAMS.is_adaptive:
            # print([nNow, "Attack status", "Expect to occupy more", EMU_VARS.shadow_outbound_peer_cnt, expected_shadow_outbound_cnt, complete_success_rate])
            print('Reboot triggered!')
            EMU_VARS.nNextOpenOutboundConnection = 9999999999
            for outbound_peer in EMU_VARS.currentOutboundPeers[:]:
                EMU_VARS.currentOutboundPeers.remove(outbound_peer)

            EMU_VARS.shadow_outbound_peer_cnt = 0

def run(addrman):
    legitimate_addr_msg_iter = 0
    check_next_success_rate = 0
    last_time_full_connection = EMU_PARAMS.nStart

    # run start time (stats)
    em_start = time.time()
    # start emulation: tick from start to end
    print("Starting emulation..")
    print("day shadow_cnt outbound_cnt")
    for nNow in range(EMU_PARAMS.nStart, EMU_PARAMS.nEnd):
        # check success rate every day 
        if nNow >= EMU_PARAMS.nStart + check_next_success_rate * 24 * 60 * 60:
            print(check_next_success_rate, EMU_VARS.shadow_outbound_peer_cnt, len(EMU_VARS.currentOutboundPeers))
            if nNow >= EMU_PARAMS.nAttackStart:
                # trigger reboot if necessary
                check_success_rate(nNow, addrman)
            check_next_success_rate += 1


        # check if any existing outbound connection ends
        if nNow >= EMU_VARS.nNextOpenOutboundConnection:
            for outbound_peer in EMU_VARS.currentOutboundPeers[:]:
                (addr, cycle_end, _, _, is_shadow) = outbound_peer
                if nNow >= cycle_end:
                    if is_shadow and nNow > EMU_PARAMS.nAttackStart:
                        EMU_VARS.shadow_outbound_peer_cnt -= 1
                    EMU_VARS.currentOutboundPeers.remove(outbound_peer)


        # prepare legitimate addresses to broadcast (i.e. addresses that are broadcast from 
        # legitimate peers)
        # only if we had recorded a message at this time - refer prepare.prepare_addr_broadcasts())
        to_add_addr_msg = []
        if nNow in EMU_VARS.legitimate_addr_msg_ts_set:
            this_ts = EMU_VARS.legitimate_addr_msg_list[legitimate_addr_msg_iter]
            legitimate_addr_msg_iter += 1
            for (src_ip, ip_list) in this_ts:
                # outbound connections advertise from port 8333
                from_outbound = "8333" in src_ip
                for ip in ip_list:
                    if from_outbound:
                        if len(EMU_VARS.currentOutboundPeers) > 0:
                            (random_outbound_peer, _, _, _, is_shadow) = random.choice(EMU_VARS.currentOutboundPeers)
                            if not is_shadow:
                                to_add_addr_msg += [(random_outbound_peer, ip)]
                    else:
                        to_add_addr_msg += [(src_ip.split(":")[0], ip)]

        # broadcast malicious addresses if it is time
        if nNow >= EMU_PARAMS.nAttackStart:
            if nNow in EMU_VARS.malicious_addr_msg_list:
                # generate random source
                bits = random.getrandbits(32)
                src_ip = str(ipaddress.ip_address(bits))
                for ip in EMU_VARS.malicious_addr_msg_list[nNow]:
                    to_add_addr_msg += [(src_ip, ip)]

        # add to node
        for (src_ip, ip) in to_add_addr_msg:
            addrman.Add(nNow, src_ip, ip, ADDRMAN_PARAMS.nTimePenalty)

        # open a new connection if a) there are less than m_max_outbound connections or 
        # b) if we're trying to make a feeler connection
        if len(EMU_VARS.currentOutboundPeers) < ADDRMAN_PARAMS.m_max_outbound or nNow > EMU_VARS.nNextFeeler:
            addrman.ThreadOpenConnections(nNow)

            # checkpoint time if we reached our target m_max_outbound
            if len(EMU_VARS.currentOutboundPeers) >= ADDRMAN_PARAMS.m_max_outbound:
                last_time_full_connection = nNow

            # if we weren't able to make a full connection in the past hour, readjust 
            # m_max_outbound to currentOutboundPeers.
            # we do this to measure attack success rate in case the node can't make all 10 
            # connections due to an agressive threshold_tau value (\S 6.2 in the paper)
            if  nNow - last_time_full_connection > 60 * 60:
                # readjusting
                ADDRMAN_PARAMS.m_max_outbound = len(EMU_VARS.currentOutboundPeers)

                if ADDRMAN_PARAMS.m_max_outbound <= ADDRMAN_PARAMS.m_max_outbound_full_relay:
                    # reset full_relay to m_max_outbound and block_relay to 0
                    ADDRMAN_PARAMS.m_max_outbound_full_relay = ADDRMAN_PARAMS.m_max_outbound
                    ADDRMAN_PARAMS.m_max_outbound_block_relay = 0
                else:
                    # leave m_max_outbound_full_relay untouched; adjust block relay
                    ADDRMAN_PARAMS.m_max_outbound_block_relay = ADDRMAN_PARAMS.m_max_outbound - ADDRMAN_PARAMS.m_max_outbound_full_relay

            # check if attack is successful
            if EMU_VARS.shadow_outbound_peer_cnt >= ADDRMAN_PARAMS.m_max_outbound:
                break

    em_end = time.time()

    save(nNow, em_start, em_end)

def save(nNow, em_start, em_end):
    # save to file
    with open("output/"+str(EMU_PARAMS.attacker_as)+"-"+str(EMU_PARAMS.victim_as)+".txt", "w") as log_file:
        log_arr = [
                    "EmulationDuration: " + str(int((nNow - EMU_PARAMS.nStart) / (60 * 60 * 24))),
                    "AttackDuration: " + str(int((nNow - EMU_PARAMS.nStart) / (60 * 60 * 24)) - EMU_PARAMS.victim_age),
                    "AttackSuccess: " + str(nNow < EMU_PARAMS.nEnd - 1),
                    "Attacker: " + EMU_PARAMS.attacker_as,
                    "Victim: " + EMU_PARAMS.victim_as,
                    "SimTime: " + '%.3f' % (em_end - em_start),
                    "ShadowPeerCount: " + str(EMU_VARS.shadow_outbound_peer_cnt),
                    "OutboundPeerCount: " + str(len(EMU_VARS.currentOutboundPeers)),
                ]

        log_arr += ["\n--- cfg.CounterMeasures ---\n"] + [ attr + ": " + str(getattr(COUNTERMEASURES, attr)) for attr in dir(COUNTERMEASURES) if not attr.startswith('__') ]
        log_arr += ["\n--- cfg.EmulationParams ---\n"] + [ attr + ": " + str(getattr(EMU_PARAMS, attr)) for attr in dir(EMU_PARAMS) if not attr.startswith('__') ]
        log_arr += ["\n--- cfg.BTCParams ---\n"] + [ attr + ": " + str(getattr(ADDRMAN_PARAMS, attr)) for attr in dir(ADDRMAN_PARAMS) if not attr.startswith('__') ]

        string = '\n'.join(log_arr)

        log_file.write(string)
        print(string)
