"""
This file contains the main emulation loop.
We first prepare the data.
"""
import random
import gzip
import ipaddress
import gc
from operator import itemgetter
import time

from cfg import Config
from . import get_config
from . import libemulate

COUNTERMEASURES, ADDRMAN_PARAMS, EMU_PARAMS, EMU_VARS = get_config()

# decorator to log func names
def log_func(func):
    def inner(*args, **kwargs):
        print("\n>>> " +  func.__name__)
        begin = time.time()
        func(*args, **kwargs)
        end = time.time()
        print("\n<<< " + func.__name__ + " took " + '%.3f' % (end - begin) + " seconds..")
  
    return inner


def read_file_lines(filename):
    with open(filename) as f:
        line_list = f.readlines()

    line_list = [x.strip() for x in line_list]
    return line_list


def get_random_ip(group_prefixes_dict, group_prefix_indices_dict, prefix_group_list):
    """
    Get a random IP from some prefix group (check `CAddrMan.GetGroup()`) that is part of 
    `group_prefixes_dict` (shadow or hidden-shadow prefixes). We use the `prefix_group_list` list
    for quick selection.

    1. Select a random group from `prefix_group_list`.
    2. Select all the prefixes from that chosen group 
        prefixes -> [(ip_prefix1_beg, ip_prefix1_end), (ip_prefix2_beg, ip_prefix2_end..]
    3. Select the corresponding indices of that chosen_group
        indices -> [(0, prefix1_size+1), (prefix1_size+2, prefix2_size+1)..]
    4. Pick a random number from the indices range
    5. Call search_prefix_list to find out the _array_ index of the tuple in which the random
       number falls. This allows us to obtain the corresponding prefix from this index.
       Essentially, this uniformly select an IP at random. If we selected a random prefix, the IP
       distribution would not be uniform as some prefixes are larger than others.
       (Note that this is an atypical usage of the function. We wish to find out the array index
       as opposed to check if an IP exists in prefix_list)
    6. From the corresponding prefix, select a random IP    
    """
    if len(prefix_group_list) == 0:
        return ""

    # choose random group
    chosen_group = random.choice(prefix_group_list)

    # get the list of prefixes and corresponding indices
    prefixes = group_prefixes_dict[chosen_group]
    indices = group_prefix_indices_dict[chosen_group]

    # pick a random index from the range
    index_range = indices[-1][1]+1
    random_index = int(random.random() * index_range)

    # get the array index of the tuple in which the random ip index falls
    idx = libemulate.search_prefix_list(random_index, indices)
    random_prefix = prefixes[idx]

    # select a random IP from this prefix range
    random_ip_int = int(random.random() * (random_prefix[1] - random_prefix[0])) + random_prefix[0]
    random_ip_str = ipaddress.ip_address(random_ip_int)

    return str(random_ip_str), random_prefix[0], chosen_group


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

@log_func
def prepare_starter_ips(addrman):
    #### Load some starter IPs to seed the internal database of bitcoin ####
    filepath = EMU_PARAMS.starter_ips_fp
    print(f"Reading file.. {filepath}")
    starter_ips = read_file_lines(filepath)

    for ip in starter_ips:
        src_ip = "127.0.1.1"
        # set the add time to a random day T - [3, 7]
        nNow = EMU_PARAMS.nStart - 3 * 24 * 60 * 60 - random.randint(0, 4) * 24 * 60 * 60
        addrman.Add(nNow, src_ip, ip, 0)

    # clear memory
    del starter_ips
    gc.collect()

@log_func
def prepare_ip_rechability():
    #### Load bitnodes data to test for reachability ####
    """
    TODO file format
    """
    file_path = EMU_PARAMS.ip_reachability_fp
    print(f"Reading file.. {file_path}")
    with gzip.GzipFile(file_path, 'r') as f:
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

    EMU_VARS.ip_reachability = ip_reachability

@log_func
def prepare_addr_broadcasts():
    """
    We construct two data structures:
    1. `legitimate_addr_msg_ts_set` -> set of all timestamps at which we recorded an ADDR broadcast
    2. `legitimate_addr_msg_list` -> array of tuples consisting of ADDR messages [
            (src, [addr1, addr2..]),
            ...
        ]

        Before entering the main loop, we fist set an iterator variable. 
        In the main loop, we then check if the current timestamp nNow is present in 
        `legitimate_addr_msg_ts_set`. If it does, we access the corresponding ADDR message from
        `legitimate_addr_msg_list` and increment the iterator by 1.
    """
    filepath = EMU_PARAMS.addr_msgs_fp
    print(f"Reading file.. {filepath}")

    legitimate_addr_msg_ts_list = []
    with gzip.GzipFile(filepath, 'r') as f:
        addr_messages = f.read().decode('utf-8')

    for msg in addr_messages.split("\n"):
        if msg == "":
            continue

        msg_split = msg.split("\t")
        if len(msg_split) <= 1:
            continue

        timestamp = int(msg_split[0])
        if timestamp < EMU_PARAMS.nStart or timestamp > EMU_PARAMS.nEnd:
            continue

        legitimate_addr_msg_ts_list += [timestamp]

        this_ts = []
        for t_split in msg_split[1:]:
            s_split = t_split.split(" ")
            src_ip = s_split[0]
            this_ts += [(src_ip, s_split[1:])]

        EMU_VARS.legitimate_addr_msg_list += [this_ts]

    EMU_VARS.legitimate_addr_msg_ts_set = set(legitimate_addr_msg_ts_list)

@log_func
def prepare_shadow_ips(asn_db):
    #### Load shadow IP prefixes ####
    filepath = EMU_PARAMS.shadow_prefixes_fp
    print(f"Reading file.. {filepath}")
    # prefixes_list_str_shadow -> ["1.2.3.0/8", ...]
    prefixes_list_str_shadow = read_file_lines(filepath)

    for prefix_str in prefixes_list_str_shadow:
        # group based on ASN number instead of /16 prefix if defense flag is set
        if COUNTERMEASURES.ct1_flag:
            ip = str(ipaddress.ip_interface(prefix_str).network.network_address)
            asn, _ = asn_db.lookup(ip)

            if asn != None:
                # we found the asn number
                group = str(asn)
            else:
                # could not find asn, fall back to /16 based group
                group = prefix_str.split(".")[0] + "." + prefix_str.split(".")[1]
        else:
            splt = prefix_str.split('.')
            group = splt[0] + '.' + splt[1]

        prefix_network = ipaddress.ip_interface(prefix_str).network
        prefix_tuple = (int(prefix_network.network_address), int(prefix_network.broadcast_address))
        EMU_VARS.prefixes_list_shadow += [prefix_tuple]

        # prepare group based mapping
        # group_prefixes_dict_shadow -> { prefix_group1: [(prefix1_begin, prefix1_end), ..]}
        # group_prefix_index_dict_shadow -> { prefix_group1: [(0, prefix1_size+1), (prefix1_size+2, prefix2_size+1) ..]}
        prefix_size = prefix_network.num_addresses
        if group not in EMU_VARS.group_prefixes_dict_shadow:
            EMU_VARS.group_prefixes_dict_shadow[group] = [prefix_tuple]
            EMU_VARS.group_prefix_index_dict_shadow[group] = [(0, prefix_size-1)]
        else:
            EMU_VARS.group_prefixes_dict_shadow[group] += [prefix_tuple]
            sum_index = EMU_VARS.group_prefix_index_dict_shadow[group][-1][1]+1
            EMU_VARS.group_prefix_index_dict_shadow[group] += [(sum_index, sum_index+prefix_size-1)]

    print("Merging prefixes_list_shadow intervals..")
    EMU_VARS.prefixes_list_shadow = mergeIntervals(EMU_VARS.prefixes_list_shadow)

    # sort prefixes
    print("Sorting prefixes_list_shadow..")
    EMU_VARS.prefixes_list_shadow = sorted(EMU_VARS.prefixes_list_shadow, key=itemgetter(0))
    EMU_VARS.groups_list_shadow = list(EMU_VARS.group_prefixes_dict_shadow.keys())

    # free memory
    del prefixes_list_str_shadow

@log_func
def prepare_hidden_shadow_ips(asn_db):
    #### Load non-hidden shadow IP prefixes ####
    # Load the "ground truth" AS-paths to all prefixes from the victim's view
    filepath = EMU_PARAMS.victim_as_path
    print(f"Reading file.. {filepath}")
    as_path_str_list = read_file_lines(filepath)

    for as_path_str in as_path_str_list:
        line_split = as_path_str.split(" ")
        node = EMU_VARS.as_path_tree.add(line_split[0])
        node.data[0] = line_split[1:]

    # hidden shadow IPs = shadow IPs - nonhidden shaodw ips
    # non-hidden shadow IPs can be estimated by the victim using any of the estimation technique
    # described in the paper.
    # `prefixes_list_str_shadow` -> ["1.2.3.0/8", ...]
    filepath = EMU_PARAMS.shadow_prefixes_fp
    print(f"Reading file.. {filepath}")
    prefixes_list_str_shadow = read_file_lines(filepath)

    # prefixes_list_str_nonhidden_shadow -> ["1.2.3.0/8", ...]
    filepath = EMU_PARAMS.nonhidden_shadow_prefixes_fp
    print(f"Reading file.. {filepath}")
    prefixes_list_str_nonhidden_shadow = read_file_lines(filepath)

    # hidden shadow IPs = shadow IPs - nonhidden shadow ips
    prefixes_list_str_hidden_shadow = list(set(prefixes_list_str_shadow)-set(prefixes_list_str_nonhidden_shadow))

    total_ips = 0
    for prefix_str in prefixes_list_str_hidden_shadow:
        # we synthesize the "blind spot" from the victim's perspective here.
        # we drop the attacker AS from the "ground truth" AS-path data structure that we
        # constructed above
        if "47065" not in EMU_PARAMS.victim_as:
            rnode = EMU_VARS.as_path_tree.search_exact(prefix_str)
            if rnode != None:
                if EMU_PARAMS.attacker_as in rnode.data[0]:
                    rnode.data[0].remove(EMU_PARAMS.attacker_as)

        # group based on ASN number instead of /16 prefix if defense flag is set
        if COUNTERMEASURES.ct1_flag:
            ip = str(ipaddress.ip_interface(prefix_str).network.network_address)
            asn, _ = asn_db.lookup(ip)

            if asn != None:
                # we found the asn number
                group = str(asn)
            else:
                # could not find asn, fall back to /16 based group
                group = prefix_str.split(".")[0] + "." + prefix_str.split(".")[1]
        else:
            splt = prefix_str.split('.')
            group = splt[0] + '.' + splt[1]

        # prepare group based mapping
        # group_prefixes_dict_hidden_shadow -> { prefix_group1: [(prefix1_begin, prefix1_end), ..]}
        # group_prefix_index_dict_hidden_shadow -> { prefix_group1: [(0, prefix1_size+1), (prefix1_size+2, prefix2_size+1) ..]}
        prefix_network = ipaddress.ip_interface(prefix_str).network
        prefix_tuple = (int(prefix_network.network_address), int(prefix_network.broadcast_address))
        EMU_VARS.prefixes_list_hidden_shadow += [prefix_tuple]

        prefix_size = prefix_network.num_addresses
        total_ips += prefix_size
        if group not in EMU_VARS.group_prefixes_dict_hidden_shadow:
            EMU_VARS.group_prefixes_dict_hidden_shadow[group] = [prefix_tuple]
            EMU_VARS.group_prefix_index_dict_hidden_shadow[group] = [(0, prefix_size-1)]
        else:
            EMU_VARS.group_prefixes_dict_hidden_shadow[group] += [prefix_tuple]
            sum_index = EMU_VARS.group_prefix_index_dict_hidden_shadow[group][-1][1]+1
            EMU_VARS.group_prefix_index_dict_hidden_shadow[group] += [(sum_index, sum_index+prefix_size-1)]

    EMU_VARS.groups_list_hidden_shadow = list(EMU_VARS.group_prefixes_dict_hidden_shadow.keys())

    return total_ips

@log_func
def prepare_malicious_addr_broadcasts_shadow():
    # we only need to create malicious addr for 1 month, then we can replay it every month
    malicious_addr_msg_cnt_monthly = int(60 * 60 * 24 * 30 / EMU_PARAMS.malicious_addr_interval)

    # create dict to broadcast malicious IPs at appropriate time intervals
    for i in range(malicious_addr_msg_cnt_monthly):
        ts = EMU_PARAMS.nAttackStart + i * EMU_PARAMS.malicious_addr_interval

        # create list of 1000 IPs per message
        ip_list = []
        for j in range(1000):
            ip, _, _ = get_random_ip(EMU_VARS.group_prefixes_dict_shadow, EMU_VARS.group_prefix_index_dict_shadow, EMU_VARS.groups_list_shadow)
            ip_list += [ip]

        EMU_VARS.malicious_addr_msg_list[ts] = ip_list

@log_func
def prepare_malicious_addr_broadcasts_hidden_shadow():
    # we only need to create malicious addr for 1 month, then we can replay it every month
    malicious_addr_msg_cnt_monthly = int(60 * 60 * 24 * 30 / EMU_PARAMS.malicious_addr_interval)

    total_addr_msg_cnt = malicious_addr_msg_cnt_monthly * 1000

    # Hidden shadow are few, make the most of them.
    # Since threshold_tau dictates the number of connections that can share the same AS, the
    # attacker AS can appear on threshold_tau number of connections. In other words, shadow IPs
    # can occupy threshold_tau number of connections, while hidden shadow IPs can occupy the rest.
    # We distribute the combined malicious addresses list (shadow : hidden-shadow) proportionally.
    # The minimum number of hidden shadow addresses: 
    #   = total_addr_msg_cnt * (m_max_outbound - threshold_tau) / m_max_outbound
    min_hidden_shadow_ips = total_addr_msg_cnt * (ADDRMAN_PARAMS.m_max_outbound- EMU_PARAMS.threshold_tau) / ADDRMAN_PARAMS.m_max_outbound

    # Additionally, the actual number of hidden shadow IPs available to the adversary may still be
    # lower than min_hidden_shadow_ips. We repeat the batch 5 times to increase the odds.
    repeat_constant = 5

    # The algorithm is as follows:
    # 1. Try filling up all slots with hidden shadow IPs. 
    #    If #hidden-shadow-ips > total_addr_msg_cnt, break.
    #    This is the best case scenario for the adversary.
    # 2. Else, check if #hidden-shadow-ips < min_hidden_shadow_ips.
    #    If true, we must repeat the batch again until we reach min_hidden_shadow_ips. 
    hidden_shadow_count = 0
    malicious_addrs_list = []
    done_flag = False   # stop when we hit the target
    extra_flag = False  # signal that we need to repeat a batch

    while True:
        if len(EMU_VARS.prefixes_list_hidden_shadow) == 0:
            break

        # try enumerating through all hidden shadow IPs, repeat_constant number of times (note 
        # that we could break earlier)
        for i in range(repeat_constant):
            for prefix in EMU_VARS.prefixes_list_hidden_shadow:
                nw_address = prefix[0]
                bc_address = prefix[1]

                # enumerate bw tuple range
                for ip_int in range(nw_address, bc_address + 1):
                    ip_str = str(ipaddress.ip_address(ip_int))

                    malicious_addrs_list += [ip_str]
                    hidden_shadow_count += 1

                    # in case we fill up everything, break
                    if hidden_shadow_count >= total_addr_msg_cnt:
                        done_flag = True
                        break

                    # in case we are filling up extra hidden-shadow IPs, and have reached the 
                    # min_hidden_shadow_ips target, break
                    if extra_flag and hidden_shadow_count >= min_hidden_shadow_ips:
                        done_flag = True
                        break

                if done_flag:
                    break

            if done_flag:
                break

        if done_flag:
            break

        # if we still haven't filled upto min_hidden_shadow_ips, repeat again
        if hidden_shadow_count < min_hidden_shadow_ips:
            extra_flag = True

    # at this point, we have filled up at least min_hidden_shadow_ips number of hidden-shadow IPs
    # add shadow IPs to fill up the remainder of the list (if needed)
    all_addr_count = hidden_shadow_count
    while all_addr_count < total_addr_msg_cnt:
        ip, _, _ = get_random_ip(EMU_VARS.group_prefixes_dict_shadow, EMU_VARS.group_prefix_index_dict_shadow, EMU_VARS.groups_list_shadow)
        malicious_addrs_list += [ip]

        all_addr_count += 1

    # our list is ready.. shuffle
    random.shuffle(malicious_addrs_list)

    # split into separate addr messages
    for i in range(malicious_addr_msg_cnt_monthly):
        ts = EMU_PARAMS.nAttackStart + i * EMU_PARAMS.malicious_addr_interval

        # check if we're within the range
        if (i + 1) * 1000 < len(malicious_addrs_list):
            EMU_VARS.malicious_addr_msg_list[ts] = malicious_addrs_list[i*1000 : (i+1)*1000]

        else:
            # just add remainder and exit loop
            EMU_VARS.malicious_addr_msg_list[ts] = malicious_addrs_list[i*1000 : ] 
            break

