# Erebus Attack Simulation
The [Erebus Attack](https://erebus-attack.comp.nus.edu.sg/) allows large malicious Internet Service Providers (ISPs) to isolate any targeted public Bitcoin nodes from the Bitcoin peer-to-peer network. Our recent [work](https://www.usenix.org/system/files/sec21fall-tran.pdf) also evaluates a potential defense against this attack.

Here we faithfully implement the connection making behaviour of the Bitcoin protocol in the application space and mount the attack based on data collected from the actual Bitcoin Network. Further, we also deploy the countermeasures stated in the defense paper which can be toggled on or off. The code is broadly paritioned into three components:
1. `addrman.py` - a replication of the Bitcoin Peer Management protocol.
2. `prepare.py` - the environment setting component that loads data into memory
2. `libemulate.py` - the emulation runner that drives addrman

The entire configuration is set in `cfg.py`.

## Data prerequisites
The following files are required to run the emulator (paths defined in `cfg.EmulationParam`): 
- `asn_dat_fp`: 
- `starter_ips_fp`: 
- `ip_reachability_fp`: 
- `addr_msgs_fp`: 
- `shadow_prefixes_fp`: 
- `nonhidden_shadow_prefixes_fp`: 
- `victim_as_path`: 
- `shadow_prefix_stats_fp`: 

## Running the emulator
First, set the necessary configuration details defined in `cfg.py` and ensure the files are present in the correct locations.

We use the python virtual environment to manage dependencies.
```sh
# create venv
$ python3 -m venv ./venv
# activate it
$ source ./venv/bin/activate
# install dependencies
(venv) $ pip install -r requirements.txt
(venv) $ python main.py
```

The output will be saved in the `./output` directory!

## Support
Feel free to raise questions in the Issues section.
