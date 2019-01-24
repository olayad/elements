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
        self.num_nodes = 2

    def test_transaction_serialization(self):
        node = self.nodes[0]

        legacy_addr = self.nodes[0].getnewaddress("", "legacy")
        p2sh_addr = self.nodes[0].getnewaddress("", "p2sh-segwit")
        bech32_addr = self.nodes[0].getnewaddress("", "bech32")
        unknown_addr = self.nodes[1].getnewaddress()

        # directly seed types of utxos required
        self.nodes[0].generatetoaddress(1, legacy_addr)
        self.nodes[0].generatetoaddress(1, p2sh_addr)
        self.nodes[0].generatetoaddress(1, bech32_addr)
        self.nodes[0].generatetoaddress(101, unknown_addr)

        # grab utxos filtering by age
        legacy_utxo = self.nodes[0].listunspent(104, 104)[0]
        p2sh_utxo = self.nodes[0].listunspent(103, 103)[0]
        bech32_utxo = self.nodes[0].listunspent(102, 102)[0]

        # Non-segwit spend and serialization to nested address
        raw = node.createrawtransaction(
            [{"txid": legacy_utxo["txid"], "vout": legacy_utxo["vout"]}],
            [{[p2sh_addr: "1"}]
        )
        nonwit_decoded = node.decoderawtransaction(raw)
        assert_equal(len(nonwit_decoded["vin"]) , 1)
        assert('txinwitness' not in nonwit_decoded["vin"][0])
        pprint.pprint(node.decoderawtransaction(raw))

        # Cross-check python serialization
        rawtx = CTransaction()
        rawtx.deserialize(BytesIO(hex_str_to_bytes(raw)))
        assert_equal(rawtx.vin[0].prevout.hash, int("0x"+legacy_utxo["txid"], 0))

        signed_raw = node.signrawtransactionwithwallet(raw)["hex"]

        import pdb
        pdb.set_trace()


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
        assert_equal(rawtx.vin[0].prevout.hash, int("0x"+["txid"], 0))
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

        self.test_transaction_serialization()







if __name__ == '__main__':
    TxWitnessTest().main()
