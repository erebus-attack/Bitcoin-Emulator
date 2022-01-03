# Erebus Attack Simulation
The [Erebus Attack](https://erebus-attack.comp.nus.edu.sg/) allows large malicious Internet Service Providers (ISPs) to isolate any targeted public Bitcoin nodes from the Bitcoin peer-to-peer network. Our recent [work](https://www.usenix.org/system/files/sec21fall-tran.pdf) also evaluates a potential defense against this attack.

Here we faithfully implement the connection making behaviour of the Bitcoin protocol in the application space and mount the attack based on data collected from the actual Bitcoin Network. Further, we also deploy the countermeasures stated in the defense paper which can be toggled on or off. The code is broadly paritioned into three components:
1. `addrman.py` - a replication of the Bitcoin Peer Management protocol.
2. `prepare.py` - the environment setting component that loads data into memory
2. `libemulate.py` - the emulation runner that drives addrman

The entire configuration is set in `cfg.py`.

By default, the emulation runs for 381 days and the attack begins at day 30.

## Data prerequisites
Our emulation scenario includes an adversary AS (`attacker_as`) mounting the attack against a victim (`victim_as`). The victim AS denotes the AS network that the target victim node is connected to.

A sample data package is provided [here](https://github.com/erebus-attack/Bitcoin-Emulator/releases/download/v0.1/data.tar.gz). The attacker is considered to be the L3 AS and the victim is considered to be a node in the Amazon AS.

The following files are required to run the emulator (paths defined in `cfg.EmulationParam`): 
- `asn_dat_fp`: IPASN data file that contains a long list of prefixes used to lookup an AS number from a given IP. Refer to the [pyasn](https://pypi.org/project/pyasn/) documentation on steps to obtain an updated file.
- `starter_ips_fp`: List of IPs seeded to the bitcoin internal database before the start of the simulation.
- `ip_reachability_fp`: A key value dictionary containing the IP address of a node against a list of timestamp ranges denoting the online time of the node. For example, a line containing `1.2.3.4 t1-t2 t3-t4` suggests that the node was continously online from time t=t1 to t2, and then t3 to t4. This is derived from [Bitnodes](https://bitnodes.io/) data.
- `addr_msgs_fp`: A tab delimited csv that contains the timestamp at which an ADDR message was received by the node, the src IP address of the ADDR message, and the list of advertised IP addresses.
- `shadow_prefixes_fp`: List of shadow prefixes.
- `nonhidden_shadow_prefixes_fp`: List of prefixes that were correctly "estimated" as shadow prefixes by the node. This is used to derive the list of hidden-shadow prefixes (`shadow-prefixes - nonhidden-shadow-prefixes`).
- `victim_as_path`: List of AS paths from the victim to all prefixes on the internet (`prefix_1 AS1 AS2`).

## Running the emulator
First, set the necessary configuration details defined in `cfg.py`. 

Second, ensure that the `data` directory is extracted and placed in the project root, and all the files described above are correctly referenced in `cfg.py`. 

We use the python virtual environment to manage dependencies.
```sh
# create venv
$ python3 -m venv ./venv
# activate it
$ source ./venv/bin/activate
# install dependencies
(venv) $ pip install -r requirements.txt
```

The following command will run the simulation:
```sh
(venv) $ python main.py
```

The run time depends on the input parameters, and may take approximately 20 minutes. The output will be saved in the `./output` directory!

The code has been tested on Ubuntu 16.04 and 18.04, with Python 3.8.

## Support
Feel free to raise questions in the Issues section.
