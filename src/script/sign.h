// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SIGN_H
#define BITCOIN_SCRIPT_SIGN_H

#include "script/interpreter.h"

class CKeyID;
class CKeyStore;
class CScript;
class CTransaction;

struct CMutableTransaction;
class TransactionSignatureCreator;

class SignSelect {
public:
    int nHashType;
    std::vector<uint32_t> selectedInputs;
    std::vector<uint32_t> selectedOutputs;

    void SelectInput(std::vector<uint32_t> inputIndices)
    {
        selectedInputs.insert(selectedInputs.end(), inputIndices.begin(), inputIndices.end());
    }

    void SelectOutput(std::vector<uint32_t> outputIndices)
    {
        selectedOutputs.insert(selectedOutputs.end(), outputIndices.begin(), outputIndices.end());
    }

    bool HasInput(uint32_t inputIndex)
    {
        return std::find(selectedInputs.begin(), selectedInputs.end(), inputIndex) != selectedInputs.end();
    }

    bool HasOutput(uint32_t outputIndex)
    {
        return std::find(selectedOutputs.begin(), selectedOutputs.end(), outputIndex) != selectedOutputs.end();
    }

    void Write(std::vector<uint32_t> idx, std::vector<uint8_t>& buf) const
    {
        // serialize using utf-style bytes where the lower 7 bits are on/off toggles and the high 8th bit indicates whether
        // there is more data or whether the selection is finished
        if (idx.size() == 0) {
            // 0 selected
            buf.push_back(0);
            return;
        }
        uint32_t max = idx[0];
        for (uint32_t i = 1; i < idx.size(); i++) {
            if (max < idx[i]) max = idx[i];
        }
        uint32_t bytes = 1 + max / 7;
        uint8_t data[bytes];
        memset(data, 0, bytes);
        for (uint32_t i = 1; i < bytes; i++) {
            data[i] |= 0x80;
        }
        for (uint32_t i = 0; i < idx.size(); i++) {
            data[bytes - 1 - idx[i] / 7] |= 1 << (idx[i] % 7);
        }
        for (uint32_t i = 0; i < bytes; i++) {
            buf.push_back(data[i]);
        }
    }

    void Encode(std::vector<uint8_t>& s) const
    {
        if (nHashType & SIGHASH_SELECTOUTPUTS) {
            Write(selectedOutputs, s);
        }
        if (nHashType & SIGHASH_SELECTINPUTS) {
            Write(selectedInputs, s);
        }
        uint8_t ht = nHashType;
        s.push_back(ht);
    }

    void Decode(std::vector<uint8_t>& v)
    {
        // clear up
        selectedInputs.clear();
        selectedOutputs.clear();
        
        size_t csr = v.size() - 1;

        uint8_t ht = nHashType = v[csr--];
        std::vector<uint32_t> selections;
        if (ht & SIGHASH_SELECTINPUTS) {
            // read input selections
            uint32_t index = 0;
            for (;;) {
                uint8_t sel = v[csr--];
                for (uint8_t i = 0; i < 7; i++) {
                    if (sel & (1 << i)) selections.push_back(index);
                    index++;
                }
                if (!(sel & 0x80)) break;
            }
            // register
            SelectInput(selections);
        }
        if (ht & SIGHASH_SELECTOUTPUTS) {
            // read output selections
            uint32_t index = 0;
            selections.clear();
            for (;;) {
                uint8_t sel = v[csr--];
                for (uint8_t i = 0; i < 7; i++) {
                    if (sel & (1 << i)) selections.push_back(index);
                    index++;
                }
                if (!(sel & 0x80)) break;
            }
            // register
            SelectOutput(selections);
        }
    }
    CTransaction* ExtractSelection(const CTransaction* txTo, int& adjustedNIn);
};

/** Virtual base class for signature creators. */
class BaseSignatureCreator {
protected:
    const CKeyStore* keystore;

public:
    BaseSignatureCreator(const CKeyStore* keystoreIn) : keystore(keystoreIn) {}
    const CKeyStore& KeyStore() const { return *keystore; };
    virtual ~BaseSignatureCreator() {}
    virtual const BaseSignatureChecker& Checker() const =0;

    /** Create a singular (non-script) signature. */
    virtual bool CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const =0;
};

/** A signature creator for transactions. */
class TransactionSignatureCreator : public BaseSignatureCreator {
    const CTransaction* txTo;
    unsigned int nIn;
    int nHashType;
    CConfidentialValue amount;
    const TransactionNoWithdrawsSignatureChecker checker;
    SignSelect* signSelect;
public:
    TransactionSignatureCreator(const CKeyStore* keystoreIn, const CTransaction* txToIn, unsigned int nInIn, const CConfidentialValue& amountIn, int nHashTypeIn=SIGHASH_ALL, SignSelect* ss=NULL);
    const BaseSignatureChecker& Checker() const { return checker; }
    bool CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const;
};

class MutableTransactionSignatureCreator : public TransactionSignatureCreator {
    CTransaction tx;

public:
    MutableTransactionSignatureCreator(const CKeyStore* keystoreIn, const CMutableTransaction* txToIn, unsigned int nInIn, const CConfidentialValue& amount, int nHashTypeIn, SignSelect* ss=NULL) : TransactionSignatureCreator(keystoreIn, &tx, nInIn, amount, nHashTypeIn, ss), tx(*txToIn) {}
};

/** A signature creator that just produces 72-byte empty signatures. */
class DummySignatureCreator : public BaseSignatureCreator {
public:
    DummySignatureCreator(const CKeyStore* keystoreIn) : BaseSignatureCreator(keystoreIn) {}
    const BaseSignatureChecker& Checker() const;
    bool CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const;
};

struct SignatureData {
    CScript scriptSig;
    CScriptWitness scriptWitness;

    SignatureData() {}
    explicit SignatureData(const CScript& script) : scriptSig(script) {}
};

/** Produce a script signature using a generic signature creator. */
bool ProduceSignature(const BaseSignatureCreator& creator, const CScript& scriptPubKey, SignatureData& sigdata);

/** Produce a script signature for a transaction. */
bool SignSignature(const CKeyStore &keystore, const CScript& fromPubKey, CMutableTransaction& txTo, unsigned int nIn, const CConfidentialValue& amount, int nHashType);
bool SignSignature(const CKeyStore& keystore, const CTransaction& txFrom, CMutableTransaction& txTo, unsigned int nIn, int nHashType);

/** Combine two script signatures using a generic signature checker, intelligently, possibly with OP_0 placeholders. */
SignatureData CombineSignatures(const CScript& scriptPubKey, const BaseSignatureChecker& checker, const SignatureData& scriptSig1, const SignatureData& scriptSig2);

/** Extract signature data from a transaction, and insert it. */
SignatureData DataFromTransaction(const CMutableTransaction& tx, unsigned int nIn);
void UpdateTransaction(CMutableTransaction& tx, unsigned int nIn, const SignatureData& data);

#endif // BITCOIN_SCRIPT_SIGN_H
