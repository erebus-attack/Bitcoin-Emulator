
# Bitcoin Erebus - Bitcoin emulator

## Description

This is a Bitcoin emulator that accurately emulates the address management (in [addrman.cpp](https://github.com/bitcoin/bitcoin/blob/master/src/addrman.cpp)) and outgoing connection establishment of Bitcoin (in [net.cpp](https://github.com/bitcoin/bitcoin/blob/master/src/net.cpp))

* The required format for the data is shown in /data/README.md

* We do not include the data here since the grouth truth data is too heavy

* Erebus parameters are configurable

* There are inline comments, hope it is helpful

## Requirement

* Python3 (yep, that's all!)

## Run the emulator

* Set the Erebus parameters and run it
	````
	python3 bitcoin-emulator.py
	````

## License

This project is licensed under the [MIT License](http://www.opensource.org/licenses/mit-license.php).