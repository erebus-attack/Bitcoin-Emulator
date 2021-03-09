
# Bitcoin Erebus - Bitcoin emulator

## Description

This is a Bitcoin emulator that accurately emulates the address management (in [addrman.cpp](https://github.com/bitcoin/bitcoin/blob/master/src/addrman.cpp)) and outgoing connection establishment of Bitcoin (in [net.cpp](https://github.com/bitcoin/bitcoin/blob/master/src/net.cpp))

The emulator runs in three broad configurations:
1. `case1`: the RAP defense is disabled and the attacker makes use of full shadow IPs (hidden shadow + non-hidden shadow)
2. `case2`: the RAP defense is enabled and the attacker makes use of full shadow IPs (hidden shadow + non-hidden shadow)
3. `case3`: the RAP defense is enabled and the attacker optimizes for hidden shadow IPs over non-hidden shadow IPs.

Further, the victim can enable any countermeasures (described in the paper).
This is configured at the beginning of the file.

An additional parameter τ(tau) can be configured as an argument to the program.

## Requirements

* Python3
* py-radix `pip install py-radix`
* pyasn `pip install py-radix`

## Running the emulator
* Place the data in <link> in the `./data` folder
* Set the parameters described above
* Run it as
	```py
	python3 bitcoin-emulator.py <attacker> <victim> <tau>
	```

## License

This project is licensed under the [MIT License](http://www.opensource.org/licenses/mit-license.php).
