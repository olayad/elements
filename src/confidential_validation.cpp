
#include <confidential_validation.h>
#include <secp256k1.h>


namespace {
static secp256k1_context *secp256k1_ctx_verify_amounts;

class CSecp256k1Init {
public:
    CSecp256k1Init() {
        assert(secp256k1_ctx_verify_amounts == NULL);
        secp256k1_ctx_verify_amounts = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
        assert(secp256k1_ctx_verify_amounts != NULL);
    }
    ~CSecp256k1Init() {
        assert(secp256k1_ctx_verify_amounts != NULL);
        secp256k1_context_destroy(secp256k1_ctx_verify_amounts);
        secp256k1_ctx_verify_amounts = NULL;
    }
};
static CSecp256k1Init instance_of_csecp256k1;
}

bool HasValidFee(const CTransaction& tx) {
    CAmountMap totalFee;
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        CAmount fee = 0;
        if (tx.vout[i].IsFee()) {
            fee = tx.vout[i].nValue.GetAmount();
            if (fee == 0 || !MoneyRange(fee))
                return false;
            totalFee[tx.vout[i].nAsset.GetAsset()] += fee;
        }
    }
    return MoneyRange(totalFee);
}

CAmountMap GetFeeMap(const CTransaction& tx) {
    CAmountMap fee;
    for (const CTxOut& txout : tx.vout) {
        if (txout.IsFee()) {
            fee[txout.nAsset.GetAsset()] += txout.nValue.GetAmount();
        }
    }
    return fee;
}

bool CRangeCheck::operator()()
{
    if (val->IsExplicit()) {
        return true;
    }

    if (!CachingRangeProofChecker(store).VerifyRangeProof(rangeproof, val->vchCommitment, assetCommitment, scriptPubKey, secp256k1_ctx_verify_amounts)) {
        error = SCRIPT_ERR_RANGEPROOF;
        return false;
    }

    return true;
};

bool CBalanceCheck::operator()()
{
    if (!secp256k1_pedersen_verify_tally(secp256k1_ctx_verify_amounts, vpCommitsIn.data(), vpCommitsIn.size(), vpCommitsOut.data(), vpCommitsOut.size())) {
        fAmountError = true;
        error = SCRIPT_ERR_PEDERSEN_TALLY;
        return false;
    }

    return true;
}

bool CSurjectionCheck::operator()()
{
    return CachingSurjectionProofChecker(store).VerifySurjectionProof(proof, vTags, gen, secp256k1_ctx_verify_amounts, wtxid);
}

size_t GetNumIssuances(const CTransaction& tx)
{
    unsigned int numIssuances = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        if (!tx.vin[i].assetIssuance.IsNull()) {
            if (!tx.vin[i].assetIssuance.nAmount.IsNull()) {
                numIssuances++;
            }
            if (!tx.vin[i].assetIssuance.nInflationKeys.IsNull()) {
                numIssuances++;
            }
        }
    }
    return numIssuances;
}

// Helper function for VerifyAmount(), not exported
static bool VerifyIssuanceAmount(secp256k1_pedersen_commitment& value_commit, secp256k1_generator& asset_gen,
                    const CAsset& asset, const CConfidentialValue& value, const std::vector<unsigned char>& rangeproof,
                    std::vector<CCheck*>* checks, const bool store_result)
{
    // This is used to add in the explicit values
    unsigned char explicit_blinds[32];
    memset(explicit_blinds, 0, sizeof(explicit_blinds));
    int ret;

    ret = secp256k1_generator_generate(secp256k1_ctx_verify_amounts, &asset_gen, asset.begin());
    assert(ret == 1);

    // Build value commitment
    if (value.IsExplicit()) {
        if (!MoneyRange(value.GetAmount()) || value.GetAmount() == 0) {
            return false;
        }
        if (!rangeproof.empty()) {
            return false;
        }


        ret = secp256k1_pedersen_commit(secp256k1_ctx_verify_amounts, &value_commit, explicit_blinds, value.GetAmount(), &asset_gen);
        // The explicit_blinds are all 0, and the amount is not 0. So secp256k1_pedersen_commit does not fail.
        assert(ret == 1);
    } else if (value.IsCommitment()) {
        // Verify range proof
        std::vector<unsigned char> vchAssetCommitment(CConfidentialAsset::nExplicitSize);
        secp256k1_generator_serialize(secp256k1_ctx_verify_amounts, vchAssetCommitment.data(), &asset_gen);
        if (QueueCheck(checks, new CRangeCheck(&value, rangeproof, vchAssetCommitment, CScript(), store_result)) != SCRIPT_ERR_OK) {
            return false;
        }

        if (secp256k1_pedersen_commitment_parse(secp256k1_ctx_verify_amounts, &value_commit, value.vchCommitment.data()) != 1) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool VerifyAmounts(const CCoinsViewCache& cache, const CTransaction& tx, std::vector<CCheck*>* pvChecks, const bool cacheStore)
{
    assert(!tx.IsCoinBase());

    std::vector<secp256k1_pedersen_commitment> vData;
    std::vector<secp256k1_pedersen_commitment *> vpCommitsIn, vpCommitsOut;

    vData.reserve((tx.vin.size() + tx.vout.size() + GetNumIssuances(tx)));
    secp256k1_pedersen_commitment *p = vData.data();
    secp256k1_pedersen_commitment commit;
    secp256k1_generator gen;
    // This is used to add in the explicit values
    unsigned char explBlinds[32];
    memset(explBlinds, 0, sizeof(explBlinds));
    int ret;

    uint256 wtxid(tx.GetHashWithWitness());

    // This list is used to verify surjection proofs.
    // Proofs must be constructed with the list being in
    // order of input and non-null issuance pseudo-inputs, with
    // input first, asset issuance second, reissuance token third.
    std::vector<secp256k1_generator> targetGenerators;
    targetGenerators.reserve(tx.vin.size() + GetNumIssuances(tx));

    // Tally up value commitments, check balance
    for (size_t i = 0; i < tx.vin.size(); ++i)
    {
        // Assumes IsValidPeginWitness has been called successfully
        const CTxOut out = tx.vin[i].m_is_pegin ? GetPeginOutputFromWitness(tx.wit.vtxinwit[i].m_pegin_witness) : cache.GetOutputFor(tx.vin[i]);
        const CConfidentialValue& val = out.nValue;
        const CConfidentialAsset& asset = out.nAsset;

        if (val.IsNull() || asset.IsNull())
            return false;

        if (asset.IsExplicit()) {
            ret = secp256k1_generator_generate(secp256k1_ctx_verify_amounts, &gen, asset.GetAsset().begin());
            assert(ret != 0);
        }
        else if (asset.IsCommitment()) {
            if (secp256k1_generator_parse(secp256k1_ctx_verify_amounts, &gen, &asset.vchCommitment[0]) != 1)
                return false;
        }
        else {
            return false;
        }

        targetGenerators.push_back(gen);

        if (val.IsExplicit()) {
            if (!MoneyRange(val.GetAmount()))
                return false;

            // Fails if val.GetAmount() == 0
            if (secp256k1_pedersen_commit(secp256k1_ctx_verify_amounts, &commit, explBlinds, val.GetAmount(), &gen) != 1)
                return false;
        } else if (val.IsCommitment()) {
            if (secp256k1_pedersen_commitment_parse(secp256k1_ctx_verify_amounts, &commit, &val.vchCommitment[0]) != 1)
                return false;
        } else {
                return false;
        }

        vData.push_back(commit);
        vpCommitsIn.push_back(p);
        p++;

        // Each transaction input may have up to two "pseudo-inputs" to add to the LHS
        // for (re)issuance and may require up to two rangeproof checks:
        // blinded value of the new assets being made
        // blinded value of the issuance tokens being made (only for initial issuance)
        const CAssetIssuance& issuance = tx.vin[i].assetIssuance;

        // No issuances to process, continue to next input
        if (issuance.IsNull()) {
            continue;
        }

        CAsset assetID;
        CAsset assetTokenID;

        // First construct the assets of the issuances and reissuance token
        // These are calculated differently depending on if initial issuance or followup

        // New issuance, compute the asset ids
        if (issuance.assetBlindingNonce.IsNull()) {
            uint256 entropy;
            GenerateAssetEntropy(entropy, tx.vin[i].prevout, issuance.assetEntropy);
            CalculateAsset(assetID, entropy);
            // Null nAmount is considered explicit 0, so just check for commitment
            CalculateReissuanceToken(assetTokenID, entropy, issuance.nAmount.IsCommitment());
        } else {
        // Re-issuance
            // hashAssetIdentifier doubles as the entropy on reissuance
            CalculateAsset(assetID, issuance.assetEntropy);
            CalculateReissuanceToken(assetTokenID, issuance.assetEntropy, issuance.nAmount.IsCommitment());

            // Must check that prevout is the blinded issuance token
            // prevout's asset tag = assetTokenID + assetBlindingNonce
            if (secp256k1_generator_generate_blinded(secp256k1_ctx_verify_amounts, &gen, assetTokenID.begin(), issuance.assetBlindingNonce.begin()) != 1) {
                return false;
            }
            // Serialize the generator for direct comparison
            unsigned char derived_generator[33];
            secp256k1_generator_serialize(secp256k1_ctx_verify_amounts, derived_generator, &gen);

            // Belt-and-suspenders: Check that asset commitment from issuance input is correct size
            if (asset.vchCommitment.size() != sizeof(derived_generator)) {
                return false;
            }

            // We have already checked the outputs' generator commitment for general validity, so directly compare serialized bytes
            if (memcmp(asset.vchCommitment.data(), derived_generator, sizeof(derived_generator))) {
                return false;
            }
        }

        // Process issuance of asset

        if (!issuance.nAmount.IsValid()) {
            return false;
        }
        if (!issuance.nAmount.IsNull()) {
            if (i >= tx.wit.vtxinwit.size()) {
                return false;
            }
            if (!VerifyIssuanceAmount(commit, gen, assetID, issuance.nAmount, tx.wit.vtxinwit[i].vchIssuanceAmountRangeproof, pvChecks, cacheStore)) {
                return false;
            }
            targetGenerators.push_back(gen);
            vData.push_back(commit);
            vpCommitsIn.push_back(p);
            p++;
        }

        if (!issuance.nAmount.IsValid()) {
            return false;
        }

        // Process issuance of reissuance tokens

        if (!issuance.nInflationKeys.IsValid()) {
            return false;
        }
        if (!issuance.nInflationKeys.IsNull()) {
            // Only initial issuance can have reissuance tokens
            if (!issuance.assetBlindingNonce.IsNull()) {
                return false;
            }

            if (i >= tx.wit.vtxinwit.size()) {
                return false;
            }
            if (!VerifyIssuanceAmount(commit, gen, assetTokenID, issuance.nInflationKeys, tx.wit.vtxinwit[i].vchInflationKeysRangeproof, pvChecks, cacheStore)) {
                return false;
            }
            targetGenerators.push_back(gen);
            vData.push_back(commit);
            vpCommitsIn.push_back(p);
            p++;
        }
    }

    for (size_t i = 0; i < tx.vout.size(); ++i)
    {
        const CConfidentialValue& val = tx.vout[i].nValue;
        const CConfidentialAsset& asset = tx.vout[i].nAsset;
        if (!asset.IsValid())
            return false;
        if (!val.IsValid())
            return false;
        if (!tx.vout[i].nNonce.IsValid())
            return false;

        if (asset.IsExplicit()) {
            ret = secp256k1_generator_generate(secp256k1_ctx_verify_amounts, &gen, asset.GetAsset().begin());
            assert(ret != 0);
        }
        else if (asset.IsCommitment()) {
            if (secp256k1_generator_parse(secp256k1_ctx_verify_amounts, &gen, &asset.vchCommitment[0]) != 1)
                return false;
        }
        else {
            return false;
        }

        if (val.IsExplicit()) {
            if (!MoneyRange(val.GetAmount()))
                return false;

            if (val.GetAmount() == 0) {
                if (tx.vout[i].scriptPubKey.IsUnspendable()) {
                    continue;
                } else {
                    // No spendable 0-value outputs
                    // Reason: A spendable output of 0 reissuance tokens would allow reissuance without reissuance tokens.
                    return false;
                }
            }

            ret = secp256k1_pedersen_commit(secp256k1_ctx_verify_amounts, &commit, explBlinds, val.GetAmount(), &gen);
            // The explBlinds are all 0, and the amount is not 0. So secp256k1_pedersen_commit does not fail.
            assert(ret == 1);
        }
        else if (val.IsCommitment()) {
            if (secp256k1_pedersen_commitment_parse(secp256k1_ctx_verify_amounts, &commit, &val.vchCommitment[0]) != 1)
                return false;
        } else {
            return false;
        }

        vData.push_back(commit);
        vpCommitsOut.push_back(p);
        p++;
    }

    // Check balance
    if (QueueCheck(pvChecks, new CBalanceCheck(vData, vpCommitsIn, vpCommitsOut)) != SCRIPT_ERR_OK) {
        return false;
    }

    // Range proofs
    for (size_t i = 0; i < tx.vout.size(); i++) {
        const CConfidentialValue& val = tx.vout[i].nValue;
        const CConfidentialAsset& asset = tx.vout[i].nAsset;
        std::vector<unsigned char> vchAssetCommitment = asset.vchCommitment;
        const CTxOutWitness* ptxoutwit = tx.wit.vtxoutwit.size() <= i? NULL: &tx.wit.vtxoutwit[i];
        if (val.IsExplicit())
        {
            if (ptxoutwit && !ptxoutwit->vchRangeproof.empty())
                return false;
            continue;
        }
        if (asset.IsExplicit()) {
            int ret = secp256k1_generator_generate(secp256k1_ctx_verify_amounts, &gen, asset.GetAsset().begin());
            assert(ret != 0);
            secp256k1_generator_serialize(secp256k1_ctx_verify_amounts, &vchAssetCommitment[0], &gen);
        }
        if (!ptxoutwit) {
            return false;
        }
        if (QueueCheck(pvChecks, new CRangeCheck(&val, ptxoutwit->vchRangeproof, vchAssetCommitment, tx.vout[i].scriptPubKey, cacheStore)) != SCRIPT_ERR_OK) {
            return false;
        }
    }

    // Surjection proofs
    for (size_t i = 0; i < tx.vout.size(); i++)
    {
        const CConfidentialAsset& asset = tx.vout[i].nAsset;
        const CTxOutWitness* ptxoutwit = tx.wit.vtxoutwit.size() <= i? NULL: &tx.wit.vtxoutwit[i];
        // No need for surjection proof
        if (asset.IsExplicit()) {
            if (ptxoutwit && !ptxoutwit->vchSurjectionproof.empty()) {
                return false;
            }
            continue;
        }
        if (!ptxoutwit)
            return false;
        if (secp256k1_generator_parse(secp256k1_ctx_verify_amounts, &gen, &asset.vchCommitment[0]) != 1)
            return false;

        secp256k1_surjectionproof proof;
        if (secp256k1_surjectionproof_parse(secp256k1_ctx_verify_amounts, &proof, &ptxoutwit->vchSurjectionproof[0], ptxoutwit->vchSurjectionproof.size()) != 1)
            return false;

        if (QueueCheck(pvChecks, new CSurjectionCheck(proof, targetGenerators, gen, wtxid, cacheStore)) != SCRIPT_ERR_OK) {
            return false;
        }
    }

    return true;
}

bool VerifyCoinbaseAmount(const CTransaction& tx, const CAmountMap& mapFees)
{
    assert(tx.IsCoinBase());
    CAmountMap remaining = mapFees;
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        if (!out.nValue.IsExplicit() || !out.nAsset.IsExplicit()) {
            return false;
        }
        if (!MoneyRange(out.nValue.GetAmount()) || (out.nValue.GetAmount() == 0 && !out.scriptPubKey.IsUnspendable())) {
            return false;
        }
        remaining[out.nAsset.GetAsset()] -= out.nValue.GetAmount();
    }
    return MoneyRange(remaining);
}

bool CachingRangeProofChecker::VerifyRangeProof(const std::vector<unsigned char>& vchRangeProof, const std::vector<unsigned char>& vchValueCommitment, const std::vector<unsigned char>& vchAssetCommitment, const CScript& scriptPubKey, const secp256k1_context* secp256k1_ctx_verify_amounts) const
{
    uint256 entry;
    rangeProofCache.ComputeEntry(entry, vchRangeProof, vchValueCommitment);

    if (rangeProofCache.Get(entry, !store)) {
        return true;
    }

    if (vchRangeProof.size() == 0) {
        return false;
    }

    uint64_t min_value, max_value;
    secp256k1_pedersen_commitment commit;
    if (secp256k1_pedersen_commitment_parse(secp256k1_ctx_verify_amounts, &commit, &vchValueCommitment[0]) != 1)
            return false;

    secp256k1_generator tag;
    if (secp256k1_generator_parse(secp256k1_ctx_verify_amounts, &tag, &vchAssetCommitment[0]) != 1)
        return false;

    if (!secp256k1_rangeproof_verify(secp256k1_ctx_verify_amounts, &min_value, &max_value, &commit, vchRangeProof.data(), vchRangeProof.size(), scriptPubKey.size() ? &scriptPubKey.front() : NULL, scriptPubKey.size(), &tag)) {
        return false;
    }

    // An rangeproof is not valid if the output is spendable but the minimum number
    // is 0. This is to prevent people passing 0-value tokens around, or conjuring
    // reissuance tokens from nothing then attempting to reissue an asset.
    // ie reissuance doesn't require revealing value of reissuance output
    // Issuances proofs are always "unspendable" as they commit to an empty script.
    if (min_value == 0 && !scriptPubKey.IsUnspendable()) {
        return false;
    }

    if (store) {
        rangeProofCache.Set(entry);
    }

    return true;
}

bool CachingSurjectionProofChecker::VerifySurjectionProof(secp256k1_surjectionproof& proof, std::vector<secp256k1_generator>& vTags, secp256k1_generator& gen, const secp256k1_context* secp256k1_ctx_verify_amounts, const uint256& wtxid) const
{

    // Serialize proof
    std::vector<unsigned char> vchproof;
    size_t proof_len = 0;
    vchproof.resize(secp256k1_surjectionproof_serialized_size(secp256k1_ctx_verify_amounts, &proof));
    secp256k1_surjectionproof_serialize(secp256k1_ctx_verify_amounts, &vchproof[0], &proof_len, &proof);

    // wtxid commits to all data including surj targets
    // we need to specify the proof and output asset point to be unique
    uint256 entry;
    surjectionProofCache.ComputeEntry(entry, wtxid, vchproof, std::vector<unsigned char>(std::begin(gen.data), std::end(gen.data)));

    if (surjectionProofCache.Get(entry, !store)) {
        return true;
    }

    if (secp256k1_surjectionproof_verify(secp256k1_ctx_verify_amounts, &proof, vTags.data(), vTags.size(), &gen) != 1) {
        return false;
    }

    if (store) {
        surjectionProofCache.Set(entry);
    }

    return true;
}

// To be called once in AppInit2/TestingSetup to initialize the rangeproof cache
void InitRangeproofCache()
{
    // nMaxCacheSize is unsigned. If -maxsigcachesize is set to zero,
    // setup_bytes creates the minimum possible cache (2 elements).
    size_t nMaxCacheSize = std::min(std::max((int64_t)0, GetArg("-maxsigcachesize", DEFAULT_MAX_SIG_CACHE_SIZE)), MAX_MAX_SIG_CACHE_SIZE) * ((size_t) 1 << 20);
    size_t nElems = rangeProofCache.setup_bytes(nMaxCacheSize);
    LogPrintf("Using %zu MiB out of %zu requested for rangeproof cache, able to store %zu elements\n",
            (nElems*sizeof(uint256)) >>20, nMaxCacheSize>>20, nElems);
}

// To be called once in AppInit2/TestingSetup to initialize the surjectionrproof cache
void InitSurjectionproofCache()
{
    // nMaxCacheSize is unsigned. If -maxsigcachesize is set to zero,
    // setup_bytes creates the minimum possible cache (2 elements).
    size_t nMaxCacheSize = std::min(std::max((int64_t)0, GetArg("-maxsigcachesize", DEFAULT_MAX_SIG_CACHE_SIZE)), MAX_MAX_SIG_CACHE_SIZE) * ((size_t) 1 << 20);
    size_t nElems = surjectionProofCache.setup_bytes(nMaxCacheSize);
    LogPrintf("Using %zu MiB out of %zu requested for surjectionproof cache, able to store %zu elements\n",
            (nElems*sizeof(uint256)) >>20, nMaxCacheSize>>20, nElems);
}
