// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "libzerocoin/Params.h"
#include "chainparams.h"
#include "consensus/merkle.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>
#include <limits>

#include "chainparamsseeds.h"

std::string CDNSSeedData::getHost(uint64_t requiredServiceBits) const {
    //use default host for non-filter-capable seeds or if we use the default service bits (NODE_NETWORK)
    if (!supportsServiceBitsFiltering || requiredServiceBits == NODE_NETWORK)
        return host;

    return strprintf("x%x.%s", requiredServiceBits, host);
}

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.nVersion = nVersion;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of the genesis coinbase cannot
 * be spent as it did not originally exist in the database.
 *
 * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
 *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
 *   vMerkleTree: e0028e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Sep 30 2018 - Indias Central Bank Denies Formal Creation of Blockchain Unit";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions
static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    (0, uint256("0000024c78d7d2fb56363f7777bab06de80307ac751b02e843ca7ae62d2310d2"))
    (100, uint256("00000a077be1f0b9850b8321fa847e5eb79fd939217596f51f1ea188b16284ea"))
    (200, uint256("00000003b64c5a430505a05eb3fcada74ff5663829a2cb39be5678223f2f4e59"))
    (300, uint256("0000000dbb7ac6312c6bbebd31c4dbf6baae9cd34d7ad5fcbe2e89b1c0681d3a"))
    (400, uint256("0000000a6551d2f6addaffd58fcfc92f1cdb1f0ed91c4cce2b7c925124c51bdc"))
    (500, uint256("d95c542234350153f61595a58c486485c9d9e01ea26b71614a1938779b4620ae"))
    (600, uint256("ae353efb716ed1e28c2c597fe41358a9a79f979178dd3da2a568a02f5f9973c8"))
    (25000, uint256("da9b39cd3d8a1a940e6cdc327ba6be3559de524626482489faf2a09e6ab69d4e")) // Automated 25000-block interval checkpointing past here
    (50000, uint256("ea5aa3fb7a8a181ff91fc8adf3d934de071a172ee0e19b89d9c2c35e1e3a3d07"))
    (75000, uint256("edd4f2e2cb88c992fa4697f0e63d1ab3a2cb84befabe4333b5efa3582c47aecc"))
    (100000, uint256("4bc2604874e1e3d2da3e9ead296e893f389367661b699c271125b75775dd1515"))
    (125000, uint256("cf3c1808bc555211cb32422b60dd37a32caf3edfc086e0c5b01ef7a1705a6729"))
    (150000, uint256("2c8018a8f76d5b805ed19a4ed354556eea9140d5029bd1067fba4d9ef296a475"))
    (175000, uint256("b1457e580e580ccf721fa38bcf52075dcec2f70ea385ae23d4eb53f04667e73f"))
    (200000, uint256("4110614e1ba848e1e3d9fadf220d9d73617e4f824fe25598727cdf7f4a376842"))
    (225000, uint256("f543789586705da3295236252b445e31d6b18c28681eee374f765cf536179883"))
    (250000, uint256("befcbdae271af6e2fe229506f5cf9d19e129dff9514a3af28e9cddfaa49f060f"))
    (275000, uint256("320370b529e3371a49e2c88f6fcefcb3b8c8b55857a3cacff2d49874e660914c"))
    (300000, uint256("698c0576726386f311dae87a13ef5a4c12cca90692ceb566f5c08ab8080bc8e6"))
    (325000, uint256("80d9965b9716843715518d14acfe379fd5818b97c87030f966f256d9ad231bd7"))
    (350000, uint256("8d4d2a10dd08d8cf331b82ad50abefe81ac886379764a25ce7ce8a748393fa07"))
    (375000, uint256("53b7d602471efe3975b3a4de0af089020db8a839b5e84e54384daffdcc5feff8"))
    (400000, uint256("ca732c0aa9808a052c2353bfba5face5d1b96e615bb6261a0775431f357770ec"))
    (425000, uint256("97d7859fa1c31baa2a352d1f3bc1253bcb539d74e4dcbfebd338c8ce28bfe051"))
    (450000, uint256("0f189a57d8fa6c8459407075944928a3adbf5ad092d03e2844f30056d9e94b3f"))
    (475000, uint256("ee4dc469a9b7b6889ad2d48b3877c2f037bf91a203624a0e84c7280b22739761"))
    (500000, uint256("2f134a9e6224bbef72691f38e23a2e55b156e5563917f1c0c1e286fec7c48161"))
    (525000, uint256("6958b6902f1eadc24131f481574cd23f6930399368e7d8b92e2eb6c75f22d50d"))
    (550000, uint256("5beb580ddf42d987e578147636d3f2b7bcdba410380c5d311e023fcb8a29fdf2"))
    (575000, uint256("1ba304dca4e6facb7075030bd277646a24c894fcd6787dbe5b3f78b5ad5a9e4b"))
    (600000, uint256("9773120486fdee1e1ace679813247a2148f84a9e9e9f2f44db28c54d79d3d07c"))
    (625000, uint256("68928981c2fc9f4e8e4bd7d4cc7cf1a8436d2406c4d95e3b82fdb1a7612e78a7"))
    (650000, uint256("06248960f7bee9fadc23701e05a6a688adb29719515f523dfb2651811d577b56"))
    (675000, uint256("ad408358b0c0cf545f65186203c9267df7052b712a392b317fdd98023386a966"))
    (700000, uint256("aafd7166ed25520e93e546bce5428f28c8375f3aaeeb3351a14b2f380806b645"))
    (725000, uint256("c1cda697d0b738d1b1e972a93725022a7dfb85a137fcbd32f24d73ee319000d4"))
    (750000, uint256("8e66096fe7c4f8ceecaba9c70c699abeb43f1e46983e24f91f2fb09beadb408c"))
    (775000, uint256("8398d56f0931913e298effd1d029f4238317f425e0f9a8a4b2e0e0c66ec035a9"))
    (800000, uint256("a40e58993827d422b3d874a8c91f92583b39ac5bdb90a824e11eb6a380c599d9"))
    (825000, uint256("bfc646db18388c576ec12b9ac2d32082fcc4e055c38c4aaaf7533ce16f34066e"))
    (850000, uint256("10fc098b963f0f113c4f570e6a44ebacc14013acb8b673d9205f4c3947ac5502"))
    (875000, uint256("1e1583e0e3edf1d65df50334abf449f2d66e6877f52c86a17515f1ee1bc85a70"))
    (900000, uint256("1581520407087daa61390fd464883428a0c6dc00c0a8fe03d587a782b2ccfb83"))
    (925000, uint256("24e577a18fbc0190d3c6b478560a5a606462ea1b5f00db1800b59e3d1455906c"))
    (950000, uint256("4ae7813aa500a0bb440a7f90760cc4d3d0c1c3aad94551ee52f09adec60bd371"))
    (975000, uint256("15e7b11d04b77c7d6ce92f28b8141d06b0c91b3f1a53523c8e30b36042082c88"))
    (1000000, uint256("08b32e80cc24c4b5afcbb2e8ad965022d5c535813a1bac42f47c9c7b9125b4c6"))
    (1025000, uint256("6b3e8287798feffa788749e89e129bb2f3e669685c1c25671d25c039c8d0e703"))
    (1050000, uint256("0e0ef08dd4a1e477f8138f3f1519fc254629a65b57a7849504c4385a7d7ae81b"))
    (1065767, uint256("254439a9c8022f0ea578405bc320411194a14f7dc929a92117e2c71797f2066c"))
    (1075000, uint256S("346889c333dd958f4dd48937d962fe58f376df745791ad2264cbebfbef3ca988"))
    (1100000, uint256S("0b16d0643f67cd082c6de74f31f6a8f2755c3efff2696551f984b639b721d753"))
    (1125000, uint256S("a84ebe209346364c4a1b0a46231cd539afc2440868b30313b9424ccad0d073a8"))
    (1150000, uint256S("b09a9dda4106a45dcdcc9fef33c9d3b49da0709817e48c5122ad69787e547558"))
    (1175000, uint256S("09968d4cca5e6692433dcf2572cff7e45424d5e84054aad59854cc60e4201415"))
    (1200000, uint256S("0a0ac10cc7585745ac65b6030ef0e4bfabb60b5d8ea7a2ba19583e03ec5bf4a0"))
    (1225000, uint256S("ea5f990651ef8355ab4963e7f4c0aeb43187acef15f92f867846cfdd75cb0ee0"))
    (1250000, uint256S("0606c7e11331d8322502e6e41d462ac2c9e8a3a92d86f780497b9f38d9d93c14"))
    (1275000, uint256S("2eb893a837fcf0292951b593673e2ef8fcae0f12ab1a88d8a5913ccefb429af2"))
    (1300000, uint256S("78b32b7b45eb194fda4b06a0f78715a1a7376041b31fff0305c2d76ca44b87b0"))
    (1325000, uint256S("07c96f223237953a1d15ccedbf60d56383b9fc41c06655184ab0c65d843af5d1"))
    (1350000, uint256S("ff2594b0c8371ebe04143694e484028867cc424721ae242a0977dd6770c13762"))
    (1375000, uint256S("a9698214755d54429eb8f6a5ed9252d28417cac485ca97403f409cfc92cfc62a"))
    (1400000, uint256S("1a8d47264cb24b59ffa3100d13b7f76b577dcb1fa19026342e3786f87b629e67"))
    (1425000, uint256S("785739c64ce0023a756073604de8550731e1f760157bf7f702d10b9e51abd062"))
    (1450000, uint256S("0d882d229139e40edb689c02b2957d7904d1800f5d0fff12b5ee34fad9e9862a"))
    (1475000, uint256S("150f94434ae3394f79cdc20be418dfb43093ec63e869b1af3f0991a84ab3b533"))
    (1500000, uint256S("75eb9915a18c1d05aedad4827767a6f8c5bbcd3b1f210bbe03629cf61f405cf5"))
    (1525000, uint256S("151f5e1769bedf1c75e39e6483b7530a911bee5fad868a3857a8260380683f2e"))
    (1550000, uint256S("0d6386a581a6482d6c82561a7b343ce64a65d007106dcbf2813520d649bb26d2"))
    (1575000, uint256S("70a33e02f762d43c8bae73c6311a815388af371f6cec80168633b3cfb56d8292"))
    (1600000, uint256S("1d6b0dff381ef1ee7d6eda5170908fd152fee68acb143df093d8ea93d5775ccb"))
    (1625000, uint256S("f46cb8b2e2046bddd683720eaa72ce39dd472b994457536ebf880536129ecba2"))
    (1650000, uint256S("cee076ec75bfcd83c1e700ac113883e31b9d201af180a1e05d10660b8d1bd8bf"))
    (1675000, uint256S("6b2e59680640cb0f0d2098bf6274b74b0d294a697bf7b1b5a0a50ee1e45a0a7b"))
    (1700000, uint256S("63e353797948c41380a32e8222772365111ff318060f7c9f9fbe365c855031ea"))
    (1725000, uint256S("6534c719b31064ca814aef1100da6e6063e52cd7f713ad53bab1b188fe46ec03"))
    (1750000, uint256S("d6aa3ce76ecfbd875c00f95376798374781a8e7d8fb0d9ae01ab671498a5f364"))
    (1775000, uint256S("f731ee575e163f72c4c64a9ed921be73b6b7cd21f097a532bfd4f20b4bd07cef"))
    (1800000, uint256S("29b69f8ed6bd4a4325c7811b6b5c691b869ed0e0d2025a0bfa58bc72e730fa1f"))
    (1825000, uint256S("921ca93f6eb0c0879f99c59195d2983d8c140a3f433fd184072e9cc3a3286fb6"))
    (1850000, uint256S("5d929d5c7b041498acdfca941322576524d5822f8d96f23055bc2a7d55a47548"))
    (1875000, uint256S("f0dee9edef5813df169b63841e85245f439959dd90f7eb7dade9af2aee133881"))
    (1900000, uint256S("31c5e3a1a80ef84ce6c6800d23a0ea2e18b31bc0412153707f415d7fc32538e1"))
    (1925000, uint256S("c3f38a748963a2204d19d579f5dec26fc7f30ffc03336e95881abdb07c0c98be"))
    (1950000, uint256S("880b4339366ed3e4682a5e7e074cc252705e24e838508855c343dca3e345bb7b"))
    (1975000, uint256S("8265b141914874ebd2f517f83641105de0c3aacd0a5bbefa679adc5863fc3e92"))
    (2000000, uint256S("c7f2739f082bcdce42bef66a24c5023793f48a4426801645bf928a0d01b42b15"))
    (2025000, uint256S("8b4e8254c4e3831122237a66fc789eb2c1b50d7d1d6f506b82f3f7bee1b6a01d"))
    (2050000, uint256S("a1c228dc4b13716c34a54c430a21e9e86d411d6df355a389bbf5a6df3a07713a"))
    (2075000, uint256S("9393c71152c51866ac9556e23b41c456975bb87a54b59fe4836a73def2f13996"))
    (2100000, uint256S("f0bdfabf7715335a281a3cbc5c1c59c46270bfb820cba6a9bae98b4456414080"))
    (2125000, uint256S("9f74e4315d2a8deb3187b444b2bc3daf0acde1a378b486e40699f88e5bea98da"))
    (2150000, uint256S("e616b457e76f801ce1019115a516f2d9c4447b3b196cbcb03e7b2c39c4b710e9"))
    (2175000, uint256S("593b36b8139b469ebc1796af4aba389b0a69e12165f80dd3df34dcfe53b871d1"))
    (2200000, uint256S("e032df1ea28970ed277765fa904f2acb83e49e87192cb9ae139311392e2a2a22"))
    (2225000, uint256S("80843331bb31ec8c6ad07fde69f9cb46604a986527b65e78934fceea520ea09f"))
    (2250000, uint256S("c8020a78b1c43e474d1ca221a5686999faa9082d0c1f0f9e39f7ecb5d4127254"))
    (2275000, uint256S("9b1faf24ad9cc1aa91692fd230da45d4ecbae603b1200a415ef54238982eede7"))
    (2300000, uint256S("c88b3a8200a0744f94826203379823f1f7a34e1712efc93e7affa89f764cb1cd"))
    (2325000, uint256S("258145eb7ac3659529ec3034702f38deaecc75e162beb7398b87e7558aba5693"))
    (2350000, uint256S("29a8d015e41ec88d6a8cce7f296fc30595d323c91dba696a413927c392f27705"))
    (2375000, uint256S("0b5efe986e59450ba549f3e4d9e96dd0d03141105763ea88c49131b44f5a40e8"))
    (2400000, uint256S("1a6ccd3a2ac67d8befd03746bdf0403a7f199cef0b5c63e7363c8bf475d4226d"))
    (2425000, uint256S("2eef311e663ee8c9e66a4dd4345c03b8aacbf49fb3f29e2cbc3b45497cf3c3a7"))
    (2450000, uint256S("29f5371fcf59ddc2645c4d1509e120ba39b8bededc6acaef09d028b838ddc0d2"))
    (2475000, uint256S("1c84c4bff13bee170ea7ba9d45d5f9a2c16dee038586efc3ca933aa03700fb06"))
    (2500000, uint256S("dad9f1594d8645197fe15207fc2d4e76dbbb646c5e4a9e510e244235379028b8"));
static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1691162505, // * UNIX timestamp of last checkpoint block
    5089306,    // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
    2776       // * estimated number of transactions per day after checkpoint
};


static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of
    (0, uint256S("0x001"));
static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1575145155,
    2971390,
    250};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256S("0x001"));
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1454124731,
    0,
    100};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";

        genesis = CreateGenesisBlock(1538323043, 1050765, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256("0000024c78d7d2fb56363f7777bab06de80307ac751b02e843ca7ae62d2310d2"));
        assert(genesis.hashMerkleRoot == uint256("7411c8de5f43691fd7cb0f6264867edb8bb35da1bd6f0377e0981b86832254a1"));

        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.powLimit   = ~UINT256_ZERO >> 20;   // ZENZO starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nBudgetCycleBlocks = 43200;       // approx. 1 every 30 days
        consensus.nBudgetFeeConfirmations = 6;      // Number of confirmations for the finalization fee
        consensus.nCoinbaseMaturity = 50;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMasternodeCountDrift = 20;       // num of MN we allow the see-saw payments to be off by
        consensus.nMaxMoneyOut = 83000000 * COIN;
        consensus.nPoolMaxTransactions = 3;
        consensus.nProposalEstablishmentTime = 60 * 60 * 24;    // must be at least a day old to make it into a budget
        consensus.nStakeMinAge = 3 * 60 * 60;
        consensus.nStakeMinDepth = 600;
        consensus.nTargetTimespan = 40 * 60;
        consensus.nTargetTimespanV2 = 30 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;
        consensus.strObfuscationPoolDummyAddress = "D87q2gC9j6nNrnzCsg4aY6bHMLsT9nUhEw";

        // spork keys
        consensus.strSporkPubKey = "041a3041a1018f6495fc808c044481f0d446be6560e593277a34b258537f77922661f983952cb71a9d1b8948b6e1611fcd28507989d23833f0ba3b5d60c7f289cf";

        // height-based activations
        consensus.height_last_PoW = 400;
        consensus.height_RHF = 935333;
        consensus.height_last_ZC_AccumCheckpoint = 231570;
        consensus.height_start_BIP65 = consensus.height_RHF;             // 82629b7a9978f5c7ea3f70a12db92633a7d2e436711500db28b97efd48b1e527
        consensus.height_start_MessSignaturesV2 = consensus.height_RHF;  // TimeProtocolV2, Blocks V7 and newMessageSignatures
        consensus.height_start_StakeModifierNewSelection = 1;
        consensus.height_start_StakeModifierV2 = consensus.height_RHF;
        consensus.height_start_TimeProtoV2 = consensus.height_RHF;       // TimeProtocolV2, Blocks V7 and newMessageSignatures
        consensus.height_start_ZC = 101;
        consensus.height_start_ZC_PublicSpends = consensus.height_RHF;
        consensus.height_start_ZC_SerialRangeCheck = consensus.height_RHF;
        consensus.height_start_ZC_SerialsV2 = consensus.height_RHF;

        // Zerocoin-related params
        consensus.ZC_Modulus = "d59f1d99dae2770f40fb82066b6f69bb0b3783113505ecf4d958a6021d7204a8612d7c824741ac69cbf426ba4056a0598f2683c54a72c9162821864da23add323b9af365c63d1c60af802a15c3961c4a23a0a4b8f8d0cd681faf9ff5f308a9d8348993a7f5e2560bdc4274aaa670878562ad8774c7fa15ec449385a7e3f2621b152e1f9978890cf02058d3f00d7ed1fc2fba76fe2b8358205dec3f0bd0b648b995f84b74e34ae77a2c134033075cf966b4339f028e039ce8200e279bd0169cf5994a4b135699280fa7be8f0328cfcaa1f7dc7cabe18ba0ec6f42e00792b3f128ec64fee8eb9306b871f6514946649d3fa2247c62ecd5050914570bb35b035fa80ef0995006790eb5ef2e383e7919b7e1aea89f59917c1a7adfdb1a73239c09e191cdde217c53ba0bf96ac9c265054aef811da8b51b1b3ea31d96f5d1ab9acf87363be80f42acf7353b3c4a5297eb3f5676f04b987a3144c5b04d1f6f3fdec243bab3fa2f463a1c50be50b49c156c421befad74c9b6f4367149163d3796355331";
        consensus.ZC_MaxPublicSpendsPerTx = 637;    // Assume about 220 bytes each input
        consensus.ZC_MaxSpendsPerTx = 7;            // Assume about 20kb each input
        consensus.ZC_MinMintConfirmations = 20;
        consensus.ZC_MinMintFee = 1 * CENT;
        consensus.ZC_MinStakeDepth = 200;
        consensus.ZC_TimeStart = 1508214600;        // October 17, 2017 4:30:00 AM

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0x7a;
        pchMessageStart[1] = 0x51;
        pchMessageStart[2] = 0xb9;
        pchMessageStart[3] = 0xc4;
        nDefaultPort = 26210;

        // Note that of those with the service bits flag, most only support a subset of possible options
        vSeeds.push_back(CDNSSeedData("seed1.zenzo.io", "seed1.zenzo.io"));
        vSeeds.push_back(CDNSSeedData("seed2.zenzo.io", "seed2.zenzo.io"));
        vSeeds.push_back(CDNSSeedData("seed3.zenzo.io", "seed3.zenzo.io"));
        vSeeds.push_back(CDNSSeedData("seed4.zenzo.io", "seed4.zenzo.io"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 81);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 53);
        base58Prefixes[STAKING_ADDRESS] = std::vector<unsigned char>(1, 63);     // starting with 'S'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 215);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x02)(0x2D)(0x25)(0x33).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x02)(0x21)(0x31)(0x2B).convert_to_container<std::vector<unsigned char> >();
        // BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        nExtCoinType = 377;

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }

};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";

        genesis = CreateGenesisBlock(1538323043, 1050765, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256("0000024c78d7d2fb56363f7777bab06de80307ac751b02e843ca7ae62d2310d2"));

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.powLimit   = ~UINT256_ZERO >> 20;   // ZENZO starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nBudgetCycleBlocks = 144;         // approx 10 cycles per day
        consensus.nBudgetFeeConfirmations = 3;      // (only 8-blocks window for finalization on testnet)
        consensus.nCoinbaseMaturity = 15;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMasternodeCountDrift = 4;        // num of MN we allow the see-saw payments to be off by
        consensus.nMaxMoneyOut = 83000000 * COIN;
        consensus.nPoolMaxTransactions = 2;
        consensus.nProposalEstablishmentTime = 60 * 5;  // at least 5 min old to make it into a budget
        consensus.nStakeMinAge = 60 * 60;
        consensus.nStakeMinDepth = 100;
        consensus.nTargetTimespan = 40 * 60;
        consensus.nTargetTimespanV2 = 30 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;
        consensus.strObfuscationPoolDummyAddress = "y57cqfGRkekRyDRNeJiLtYVEbvhXrNbmox";

        // spork keys
        consensus.strSporkPubKey = "041a3041a1018f6495fc808c044481f0d446be6560e593277a34b258537f77922661f983952cb71a9d1b8948b6e1611fcd28507989d23833f0ba3b5d60c7f289cf";

        // height based activations
        consensus.height_last_PoW = 200;
        consensus.height_last_ZC_AccumCheckpoint = 1106090;
        consensus.height_start_BIP65 = 851019;
        consensus.height_start_MessSignaturesV2 = 1347000;      // TimeProtocolV2, Blocks V7 and newMessageSignatures
        consensus.height_start_StakeModifierNewSelection = 51197;
        consensus.height_start_StakeModifierV2 = 1214000;
        consensus.height_start_TimeProtoV2 = 1347000;           // TimeProtocolV2, Blocks V7 and newMessageSignatures
        consensus.height_start_ZC = 201576;
        consensus.height_start_ZC_PublicSpends = 1106100;
        consensus.height_start_ZC_SerialRangeCheck = 1;
        consensus.height_start_ZC_SerialsV2 = 444020;

        // Zerocoin-related params
        consensus.ZC_Modulus = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784"
                "4069182906412495150821892985591491761845028084891200728449926873928072877767359714183472702618963750149718246911"
                "6507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363"
                "7259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133"
                "8441436038339044149526344321901146575444541784240209246165157233507787077498171257724679629263863563732899121548"
                "31438167899885040445364023527381951378636564391212010397122822120720357";
        consensus.ZC_MaxPublicSpendsPerTx = 637;    // Assume about 220 bytes each input
        consensus.ZC_MaxSpendsPerTx = 7;            // Assume about 20kb each input
        consensus.ZC_MinMintConfirmations = 20;
        consensus.ZC_MinMintFee = 1 * CENT;
        consensus.ZC_MinStakeDepth = 200;
        consensus.ZC_TimeStart = 1501776000;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */

        pchMessageStart[0] = 0x45;
        pchMessageStart[1] = 0x76;
        pchMessageStart[2] = 0x65;
        pchMessageStart[3] = 0xba;
        nDefaultPort = 51474;
        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back(CDNSSeedData("fuzzbawls.pw", "pivx-testnet.seed.fuzzbawls.pw", true));
        vSeeds.push_back(CDNSSeedData("fuzzbawls.pw", "pivx-testnet.seed2.fuzzbawls.pw", true));
        vSeeds.push_back(CDNSSeedData("warrows.dev", "testnet.dnsseed.pivx.warrows.dev"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 139); // Testnet ZENZO addresses start with 'x' or 'y'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);  // Testnet ZENZO script addresses start with '8' or '9'
        base58Prefixes[STAKING_ADDRESS] = std::vector<unsigned char>(1, 73);     // starting with 'W'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        // Testnet ZENZO BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x3a)(0x80)(0x61)(0xa0).convert_to_container<std::vector<unsigned char> >();
        // Testnet ZENZO BIP32 prvkeys start with 'DRKP'
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x3a)(0x80)(0x58)(0x37).convert_to_container<std::vector<unsigned char> >();
        // Testnet ZENZO BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";

        genesis = CreateGenesisBlock(1454124731, 2402015, 0x1e0ffff0, 1, 250 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        // assert(consensus.hashGenesisBlock == uint256("0x0000041e482b9b9691d98eefb48473405c0b8ec31b76df3797c74a78680ef818"));
        // assert(genesis.hashMerkleRoot == uint256("0x1b2ef6e2f28be914103a277377ae7729dcd125dfeb8bf97bd5964ba72b6dc39b"));

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.powLimit   = ~UINT256_ZERO >> 20;   // ZENZO starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nBudgetCycleBlocks = 144;         // approx 10 cycles per day
        consensus.nBudgetFeeConfirmations = 3;      // (only 8-blocks window for finalization on regtest)
        consensus.nCoinbaseMaturity = 100;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMasternodeCountDrift = 4;        // num of MN we allow the see-saw payments to be off by
        consensus.nMaxMoneyOut = 43199500 * COIN;
        consensus.nPoolMaxTransactions = 2;
        consensus.nProposalEstablishmentTime = 60 * 5;  // at least 5 min old to make it into a budget
        consensus.nStakeMinAge = 0;
        consensus.nStakeMinDepth = 2;
        consensus.nTargetTimespan = 40 * 60;
        consensus.nTargetTimespanV2 = 30 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;
        consensus.strObfuscationPoolDummyAddress = "y57cqfGRkekRyDRNeJiLtYVEbvhXrNbmox";

        /* Spork Key for RegTest:
        WIF private key: 932HEevBSujW2ud7RfB1YF91AFygbBRQj3de3LyaCRqNzKKgWXi
        private key hex: bd4960dcbd9e7f2223f24e7164ecb6f1fe96fc3a416f5d3a830ba5720c84b8ca
        Address: yCvUVd72w7xpimf981m114FSFbmAmne7j9
        */
        consensus.strSporkPubKey = "043969b1b0e6f327de37f297a015d37e2235eaaeeb3933deecd8162c075cee0207b13537618bde640879606001a8136091c62ec272dd0133424a178704e6e75bb7";

        // height based activations
        consensus.height_last_PoW = 250;
        consensus.height_last_ZC_AccumCheckpoint = 310;     // no checkpoints on regtest
        consensus.height_start_BIP65 = 851019;              // Not defined for regtest. Inherit TestNet value.
        consensus.height_start_MessSignaturesV2 = 1;
        consensus.height_start_StakeModifierNewSelection = 0;
        consensus.height_start_StakeModifierV2 = 251;       // start with modifier V2 on regtest
        consensus.height_start_TimeProtoV2 = 999999999;
        consensus.height_start_ZC = 300;
        consensus.height_start_ZC_PublicSpends = 400;
        consensus.height_start_ZC_SerialRangeCheck = 300;
        consensus.height_start_ZC_SerialsV2 = 300;

        // Zerocoin-related params
        consensus.ZC_Modulus = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784"
                "4069182906412495150821892985591491761845028084891200728449926873928072877767359714183472702618963750149718246911"
                "6507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363"
                "7259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133"
                "8441436038339044149526344321901146575444541784240209246165157233507787077498171257724679629263863563732899121548"
                "31438167899885040445364023527381951378636564391212010397122822120720357";
        consensus.ZC_MaxPublicSpendsPerTx = 637;    // Assume about 220 bytes each input
        consensus.ZC_MaxSpendsPerTx = 7;            // Assume about 20kb each input
        consensus.ZC_MinMintConfirmations = 10;
        consensus.ZC_MinMintFee = 1 * CENT;
        consensus.ZC_MinStakeDepth = 10;
        consensus.ZC_TimeStart = 0;                 // not implemented on regtest


        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */

        pchMessageStart[0] = 0xa1;
        pchMessageStart[1] = 0xcf;
        pchMessageStart[2] = 0x7e;
        pchMessageStart[3] = 0xac;
        nDefaultPort = 51476;

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

static CChainParams* pCurrentParams = 0;

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
