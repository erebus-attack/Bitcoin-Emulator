# Main config file
import radix

######## Countermeasure flags ########
# Toggle specific countermeasures against Erebus
# More details can be found in Table 1. of the paper

class CounterMeasures:
    # ASN-based grouping
    ct1_flag = False
    # anchor connections across reboots
    ct2_flag = False
    # more outgoing connections
    ct3_flag = False
    # always pick IPs from the `tried` table
    ct4_flag = False
    # reduce `tried table` size
    ct5_flag = False
    # reduce feeler connection interval
    ct6_flag = False


######## Bitcoin Parameters ########
# refer to the bitcoin documentation for more information regarding these parameters
class BTCParam:
    ADDRMAN_TRIED_BUCKETS_PER_GROUP = 8
    ADDRMAN_TRIED_BUCKET_COUNT = round(256)
    ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP = 64
    ADDRMAN_NEW_BUCKET_COUNT = round(1024)
    ADDRMAN_BUCKET_SIZE = 64
    ADDRMAN_HORIZON_DAYS = 30
    ADDRMAN_RETRIES = 3
    ADDRMAN_MAX_FAILURES = 10
    ADDRMAN_MIN_FAIL_DAYS = 7
    ADDRMAN_NEW_BUCKETS_PER_ADDRESS = 8
    ADDRMAN_SET_TRIED_COLLISION_SIZE = 10
    ADDRMAN_REPLACEMENT_HOURS = 4

    m_max_outbound_full_relay = 8
    m_max_outbound_block_relay = 2
    m_max_outbound = m_max_outbound_full_relay + m_max_outbound_block_relay

    nTimePenalty = 2 * 60 * 60

    FEELER_INTERVAL = round(120)

    def __init__(self):
        if CounterMeasures.ct5_flag:
            BTCParam.ADDRMAN_TRIED_BUCKET_COUNT = round(256 / 4)

        if CounterMeasures.ct3_flag:
            BTCParam.m_max_outbound_block_relay = 8

        if CounterMeasures.ct6_flag:
            BTCParam.FEELER_INTERVAL = round(30)


######## Emulation Parameters ########

class EmulationParam:
    attacker_as = "8167"
    victim_as = "4-1"

    # timestamp at which the emulation should begin
    nStart = 1542562302
    # timestamp at which the emulation should end
    nEnd = 1575481296

    # days after victim boots that the attack should begin (post)
    victim_age = 30
    nAttackStart = nStart + (60*60*24) * victim_age
    # the rate at which the adversary should broadcast shadow IPs
    attack_flooding_rate = 2 # IPs/s
    malicious_addr_interval = int(1000 / attack_flooding_rate) # every ADDR message contains 1000 IPs

    # an adaptive attack forces a reboot of the victim at key times to speed up the attack
    is_adaptive = True

    # should the RAP defense be deployed
    rap_enabled = True

    # threshold tau describes the maximum number of peer connections that can share the same AS
    # (see section 4.2 of the paper)
    threshold_tau = 5

    # filepaths
    asn_dat_fp = "/data/ipasn.20200225.dat"
    starter_ips_fp = "/data/random-reachable-ips-dns-1542562102.txt"
    ip_reachability_fp = "/data/ip-reachability-stripped-incoming-addr-after-30.txt.gz"
    addr_msgs_fp = "/data/ip-from-addr-stripped-incoming-addr-after-30.txt.gz"
    shadow_prefixes_fp = "/data/shadow-prefix-traceroute/" + attacker_as + "-" + victim_as + ".txt"
    nonhidden_shadow_prefixes_fp = "/data/shadow-prefix-estimation/" + attacker_as + "-" + victim_as + ".txt"
    victim_as_path = "/data/as-path/" + victim_as + ".txt"
    shadow_prefix_stats_fp = "/data/full-shadow-stats/" + attacker_as + "-" + victim_as + ".txt"


######## Emulation Variables ########
# variables essential to keep track of current emulation
# do not modify

class EmulationVariables:
    # keep track of current outbound peer connections made by node
    currentOutboundPeers = []
    # when the node must next open a connection (this is updated later during runtime)
    nNextOpenOutboundConnection = 9999999999
    # when the node must next open a feeler connection (starts with 
    # EmulationParam.nStart + BTCParam.FEELER_INTERVAL)
    nNextFeeler = 0
    # keep track of #current malcious outbound peer connections made by node
    shadow_outbound_peer_cnt = 0
    # optimize ip_addr to as_path storage
    as_path_tree = radix.Radix()

    # bitnodes dataset to test if some IP `ip` was reachable (online) at some time `t`
    # initialized during preparation step
    # {ip: [(ts_start, ts_end), ..], ..}
    ip_reachability = {}

    # set of all timestamps at which we broadcast an ADDR broadcast
    legitimate_addr_msg_list = []
    # array of tuples consisting of ADDR messages [(src, [addr1, addr2, ..]), ..],
    legitimate_addr_msg_ts_set = set()

    # dict of all timestamps against a malicious ADDR message
    malicious_addr_msg_list = {}

    ### structures to hold shadow IP prefix data ###
    # (shadow) array of prefix tuples in int form [(prefix_begin, prefix_end), ..]
    prefixes_list_shadow = []
    # (shadow) array of groups in int [prefix_group1, prefix_group2, ..]
    groups_list_shadow = []
    # (shadow) { prefix_group1: [(prefix_begin, prefix_end), ..]}
    group_prefixes_dict_shadow = {}
    # (shadow) { prefix_group1: [(0, prefix1_size+1), (prefix1_size+2, prefix2_size+1) ..]}
    # check libemulate.get_random_ip for more info
    group_prefix_index_dict_shadow = {}

    ### structures to hold shadow IP prefix data ###
    # analogous to shadow IPs above
    prefixes_list_hidden_shadow = []
    groups_list_hidden_shadow = []
    group_prefixes_dict_hidden_shadow = {}
    group_prefix_index_dict_hidden_shadow = {}

    def __init__(self):
        EmulationVariables.nNextFeeler = EmulationParam.nStart + BTCParam.FEELER_INTERVAL


class Config:
    CounterMeasures = CounterMeasures()
    BTCParam = BTCParam()
    EmulationParam = EmulationParam()
    EmulationVariables = EmulationVariables()
