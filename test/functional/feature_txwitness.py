#!/usr/bin/env python3
# Copyright (c) 2015-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test decoding scripts via decodescript RPC command."""

from test_framework.messages import CTransaction, CTxIn, CTxOut, sha256, ser_uint256, uint256_from_str
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, bytes_to_hex_str, hex_str_to_bytes

from io import BytesIO
import pprint

class TxWitnessTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def test_transaction_serialization(self):
        node = self.nodes[0]

        # spend money to segwit address
        unspent = node.listunspent()[0]
        addr = node.getnewaddress("", "p2sh-segwit")
        node.sendtoaddress(address=addr, amount=50, subtractfeefromamount=True)
        node.generate(1)
        pprint.pprint(node.listunspent())
        unspent = node.listunspent()[0]
        addr = node.getnewaddress("", "p2sh-segwit")

        raw = node.createrawtransaction(
            [{"txid": unspent["txid"], "vout": 0}],
            [{addr: "1"}]
        )
        pprint.pprint(node.decoderawtransaction(raw))
        rawtx = CTransaction()
        rawtx.deserialize(BytesIO(hex_str_to_bytes(raw)))
        assert_equal(rawtx.vin[0].prevout.hash, int("0x"+unspent["txid"], 0))

        tx = CTransaction()
        tx.nVersion = 2
        tx.nLockTime = 0
        tx.vin = [CTxIn(outpoint=rawtx.vin[0].prevout, nSequence=4294967295)]
        tx.vout = [CTxOut(scriptPubKey=rawtx.vout[0].scriptPubKey, nValue=rawtx.vout[0].nValue)]
        assert_equal(bytes_to_hex_str(tx.serialize()), raw)

        # now signing it to generate witnesses
        raw = node.signrawtransactionwithwallet(raw)["hex"]
        rawtx = CTransaction()
        rawtx.deserialize(BytesIO(hex_str_to_bytes(raw)))
        assert_equal(rawtx.vin[0].prevout.hash, int("0x"+unspent["txid"], 0))
        print(rawtx)

        tx = CTransaction()
        tx.nVersion = 2
        tx.nLockTime = 0
        tx.vin = [CTxIn(outpoint=rawtx.vin[0].prevout, nSequence=4294967295, scriptSig=rawtx.vin[0].scriptSig)]
        tx.wit.vtxinwit = rawtx.wit.vtxinwit
        tx.vout = [CTxOut(scriptPubKey=rawtx.vout[0].scriptPubKey, nValue=rawtx.vout[0].nValue)]
        print(tx)
        assert_equal(bytes_to_hex_str(tx.serialize()), raw)



    def run_test(self):
        node = self.nodes[0]
        node.generate(101)

        self.test_transaction_serialization()







if __name__ == '__main__':
    TxWitnessTest().main()
