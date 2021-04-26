import os

import cfg
import src.addrman as addrman
import src.libemulate as libemulate
import src.prepare as prepare
import src.asndb as asndb

if __name__ == "__main__":
    # ensure output exists
    if not os.path.exists('output'):
        os.mkdir('output')

    # initialize asn_db if countermeasure is set
    asn_db = asndb.ASN_DB()
    if cfg.Config.CounterMeasures.ct1_flag:
        asn_db.setup()

    # initialize addman
    addrman = addrman.CAddrMan(asn_db)

    # prepare data
    prepare.prepare_starter_ips(addrman)
    prepare.prepare_ip_rechability()
    prepare.prepare_shadow_ips(asn_db)

    if cfg.Config.EmulationParam.rap_enabled:
        prepare.prepare_hidden_shadow_ips(asn_db)

    prepare.prepare_addr_broadcasts()
    prepare.prepare_malicious_addr_broadcasts_shadow()

    if cfg.Config.EmulationParam.rap_enabled:
        prepare.prepare_malicious_addr_broadcasts_hidden_shadow()

    # todo clear memory (maybe add function to prepare{})
    # begin emulation loop
    libemulate.run(addrman)
