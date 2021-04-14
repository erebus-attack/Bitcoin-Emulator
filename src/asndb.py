import pyasn

from cfg import Config
from . import get_config

COUNTERMEASURES, ADDRMAN_PARAMS, EMU_PARAMS, EMU_VARS = get_config()

class ASN_DB:
    def __init__(self):
        self.asn_fp = EMU_PARAMS.asn_dat_fp

    def setup(self):
        self.asn_db_instance = pyasn.pyasn(self.asn_fp)

    def lookup(self, ip):
        return self.asn_db_instance.lookup(ip)

        