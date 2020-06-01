// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2020 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "addressbook.h"
#include "amount.h"
#include "base58.h"
#include "core_io.h"
#include "init.h"
#include "net.h"
#include "netbase.h"
#include "rpc/server.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "wallet.h"
#include "walletdb.h"
#include "zpivchain.h"

#include <stdint.h>

#include "libzerocoin/Coin.h"
#include "spork.h"
#include "zpiv/deterministicmint.h"
#include <boost/assign/list_of.hpp>
#include <boost/thread/thread.hpp>

#include <univalue.h>
#include <iostream>


CWallet *GetWalletForJSONRPCRequest(const JSONRPCRequest& request)
{
    // TODO: Some way to access secondary wallets
    return vpwallets.empty() ? nullptr : vpwallets[0];
}

std::string HelpRequiringPassphrase(CWallet * const pwallet)
{
    return pwallet && pwallet->IsCrypted() ? "\nRequires wallet passphrase to be set with walletpassphrase call." : "";
}

bool EnsureWalletIsAvailable(CWallet * const pwallet, bool avoidException)
{
    if (!pwallet)
    {
        if (!avoidException)
            throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (disabled)");
        else
            return false;
    }
    return true;
}

void EnsureWalletIsUnlocked(CWallet * const pwallet, bool fAllowAnonOnly)
{
    if (pwallet->IsLocked() || (!fAllowAnonOnly && pwallet->fWalletUnlockStaking))
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
}

void WalletTxToJSON(const CWalletTx& wtx, UniValue& entry)
{
    int confirms = wtx.GetDepthInMainChain(false);
    int confirmsTotal = GetIXConfirmations(wtx.GetHash()) + confirms;
    entry.push_back(Pair("confirmations", confirmsTotal));
    entry.push_back(Pair("bcconfirmations", confirms));
    if (wtx.IsCoinBase() || wtx.IsCoinStake())
        entry.push_back(Pair("generated", true));
    if (confirms > 0) {
        entry.push_back(Pair("blockhash", wtx.hashBlock.GetHex()));
        entry.push_back(Pair("blockindex", wtx.nIndex));
        entry.push_back(Pair("blocktime", mapBlockIndex[wtx.hashBlock]->GetBlockTime()));
    } else {
        entry.push_back(Pair("trusted", wtx.IsTrusted()));
    }
    uint256 hash = wtx.GetHash();
    entry.push_back(Pair("txid", hash.GetHex()));
    UniValue conflicts(UniValue::VARR);
    for (const uint256& conflict : wtx.GetConflicts())
        conflicts.push_back(conflict.GetHex());
    entry.push_back(Pair("walletconflicts", conflicts));
    entry.push_back(Pair("time", wtx.GetTxTime()));
    entry.push_back(Pair("timereceived", (int64_t)wtx.nTimeReceived));
    for (const PAIRTYPE(std::string, std::string) & item : wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

std::string AccountFromValue(const UniValue& value)
{
    std::string strAccount = value.get_str();
    if (strAccount == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    return strAccount;
}

CBitcoinAddress GetNewAddressFromAccount(CWallet * const pwallet, const std::string purpose, const UniValue &params,
        const CChainParams::Base58Type addrType = CChainParams::PUBKEY_ADDRESS)
{
    LOCK2(cs_main, pwallet->cs_wallet);
    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount;
    if (!params.isNull() && params.size() > 0)
        strAccount = AccountFromValue(params[0]);

    CBitcoinAddress address;
    PairResult r = pwallet->getNewAddress(address, strAccount, purpose, addrType);
    if(!r.result)
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, *r.status);
    return address;
}

/** Convert CAddressBookData to JSON record.  */
static UniValue AddressBookDataToJSON(const AddressBook::CAddressBookData& data, const bool verbose)
{
    UniValue ret(UniValue::VOBJ);
    if (verbose) {
        ret.pushKV("name", data.name);
    }
    ret.pushKV("purpose", data.purpose);
    return ret;
}

/** Checks if a CKey is in the given CWallet compressed or otherwise*/
bool HaveKey(const CWallet* wallet, const CKey& key)
{
    CKey key2;
    key2.Set(key.begin(), key.end(), !key.IsCompressed());
    return wallet->HaveKey(key.GetPubKey().GetID()) || wallet->HaveKey(key2.GetPubKey().GetID());
}

UniValue getaddressinfo(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    const std::string example_address = "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\"";

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
                "getaddressinfo ( \"address\" )\n"
                "\nReturn information about the given PIVX address.\n"
                "Some of the information will only be present if the address is in the active wallet.\n"
                "{Result:\n"
                "  \"address\" : \"address\",              (string) The bitcoin address validated.\n"
                "  \"scriptPubKey\" : \"hex\",             (string) The hex-encoded scriptPubKey generated by the address.\n"
                "  \"ismine\" : true|false,              (boolean) If the address is yours.\n"
                "  \"iswatchonly\" : true|false,         (boolean) If the address is watchonly.\n"
                "  \"desc\" : \"desc\",                    (string, optional) A descriptor for spending coins sent to this address (only when solvable).\n"
                "  \"isscript\" : true|false,            (boolean) If the key is a script.\n"
                "  \"script\" : \"type\"                   (string, optional) The output script type. Only if isscript is true and the redeemscript is known. Possible\n"
                "                                                         types: nonstandard, pubkey, pubkeyhash, scripthash, multisig, nulldata, witness_v0_keyhash,\n"
                "                                                         witness_v0_scripthash, witness_unknown.\n"
                "  \"hex\" : \"hex\",                      (string, optional) The redeemscript for the p2sh address.\n"
                "  \"pubkeys\"                           (array, optional) Array of pubkeys associated with the known redeemscript (only if script is multisig).\n"
                "    [\n"
                "      \"pubkey\" (string)\n"
                "      ,...\n"
                "    ]\n"
                "  \"sigsrequired\" : xxxxx              (numeric, optional) The number of signatures required to spend multisig output (only if script is multisig).\n"
                "  \"pubkey\" : \"publickeyhex\",          (string, optional) The hex value of the raw public key for single-key addresses (possibly embedded in P2SH or P2WSH).\n"
                "  \"embedded\" : {...},                 (object, optional) Information about the address embedded in P2SH or P2WSH, if relevant and known. Includes all\n"
                "                                                         getaddressinfo output fields for the embedded address, excluding metadata (timestamp, hdkeypath,\n"
                "                                                         hdseedid) and relation to the wallet (ismine, iswatchonly).\n"
                "  \"iscompressed\" : true|false,        (boolean, optional) If the pubkey is compressed.\n"
                "  \"label\" :  \"label\"                  (string) The label associated with the address. Defaults to \"\". Equivalent to the label name in the labels array below.\n"
                "  \"timestamp\" : timestamp,            (number, optional) The creation time of the key, if available, expressed in the UNIX epoch time.\n"
                "  \"hdkeypath\" : \"keypath\"             (string, optional) The HD keypath, if the key is HD and available.\n"
                "  \"hdseedid\" : \"<hash160>\"            (string, optional) The Hash160 of the HD seed.\n"
                "  \"hdmasterfingerprint\" : \"<hash160>\" (string, optional) The fingerprint of the master key.\n"
                "  \"labels\"                            (json object) An array of labels associated with the address. Currently limited to one label but returned\n"
                "                                               as an array to keep the API stable if multiple labels are enabled in the future.\n"
                "    [\n"
                "      \"label name\" (string) The label name. Defaults to \"\". Equivalent to the label field above.\n\n"
                "      { (json object of label data)\n"
                "        \"name\" : \"label name\" (string) The label name. Defaults to \"\". Equivalent to the label field above.\n"
                "        \"purpose\" : \"purpose\" (string) The purpose of the associated address (send or receive).\n"
                "      }\n"
                "    ]\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("getaddressinfo", example_address) + HelpExampleRpc("getaddressinfo", example_address)
                );

    LOCK(pwallet->cs_wallet);

    UniValue ret(UniValue::VOBJ);
    CBitcoinAddress address(request.params[0].get_str());
    // Make sure the destination is valid
    if (!address.IsValid()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }
    CTxDestination dest = address.Get();

    std::string currentAddress = address.ToString();
    ret.pushKV("address", currentAddress);

    CScript scriptPubKey = GetScriptForDestination(dest);
    ret.pushKV("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end()));

    isminetype mine = IsMine(*pwallet, address.Get());
    ret.pushKV("ismine", bool(mine & ISMINE_SPENDABLE_ALL));
    ret.pushKV("iswatchonly", bool(mine & ISMINE_WATCH_ONLY));

    // Return label field if existing. Currently only one label can be
    // associated with an address, so the label should be equivalent to the
    // value of the name key/value pair in the labels array below.
    if (pwallet->mapAddressBook.count(dest)) {
        ret.pushKV("label", pwallet->mapAddressBook[dest].name);
    }

    // TODO: Backport IsChange.
    //ret.pushKV("ischange", pwallet->IsChange(scriptPubKey))
    // Return a `labels` array containing the label associated with the address,
    // equivalent to the `label` field above. Currently only one label can be
    // associated with an address, but we return an array so the API remains
    // stable if we allow multiple labels to be associated with an address in
    // the future.
    //
    // DEPRECATED: The previous behavior of returning an array containing a JSON
    // object of `name` and `purpose` key/value pairs has been deprecated.
    UniValue labels(UniValue::VARR);
    std::map<CTxDestination, AddressBook::CAddressBookData>::iterator mi = pwallet->mapAddressBook.find(dest);
    if (mi != pwallet->mapAddressBook.end()) {
        labels.push_back(AddressBookDataToJSON(mi->second, true));
    }
    ret.pushKV("labels", std::move(labels));

    return ret;
}

UniValue getnewaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getnewaddress ( \"account\" )\n"
            "\nReturns a new PIVX address for receiving payments.\n"
            "If 'account' is specified (DEPRECATED), it is added to the address book \n"
            "so payments received with the address will be credited to 'account'.\n"

            "\nArguments:\n"
            "1. \"account\"        (string, optional) DEPRECATED. The account name for the address to be linked to. if not provided, the default account \"\" is used. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created if there is no account by the given name.\n"

            "\nResult:\n"
            "\"pivxaddress\"    (string) The new pivx address\n"

            "\nExamples:\n" +
            HelpExampleCli("getnewaddress", "") + HelpExampleRpc("getnewaddress", ""));

    return GetNewAddressFromAccount(pwallet, AddressBook::AddressBookPurpose::RECEIVE, request.params).ToString();
}

UniValue getnewstakingaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getnewstakingaddress ( \"account\" )\n"
            "\nReturns a new PIVX cold staking address for receiving delegated cold stakes.\n"

            "\nArguments:\n"
            "1. \"account\"        (string, optional) DEPRECATED. The account name for the address to be linked to. if not provided, the default account \"\" is used. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created if there is no account by the given name.\n"


            "\nResult:\n"
            "\"pivxaddress\"    (string) The new pivx address\n"

            "\nExamples:\n" +
            HelpExampleCli("getnewstakingaddress", "") + HelpExampleRpc("getnewstakingaddress", ""));

    return GetNewAddressFromAccount(pwallet, "coldstaking", request.params, CChainParams::STAKING_ADDRESS).ToString();
}

UniValue delegatoradd(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "delegatoradd \"addr\" ( \"label\" )\n"
            "\nAdd the provided address <addr> into the allowed delegators AddressBook.\n"
            "This enables the staking of coins delegated to this wallet, owned by <addr>\n"

            "\nArguments:\n"
            "1. \"addr\"        (string, required) The address to whitelist\n"
            "2. \"label\"       (string, optional) A label for the address to whitelist\n"

            "\nResult:\n"
            "true|false           (boolean) true if successful.\n"

            "\nExamples:\n" +
            HelpExampleCli("delegatoradd", "DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6") +
            HelpExampleRpc("delegatoradd", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\"") +
            HelpExampleRpc("delegatoradd", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\" \"myPaperWallet\""));

    CBitcoinAddress address(request.params[0].get_str());
    if (!address.IsValid() || address.IsStakingAddress())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid PIVX address");

    const std::string strLabel = (request.params.size() > 1 ? request.params[1].get_str() : "");

    CKeyID keyID;
    if (!address.GetKeyID(keyID))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to get KeyID from PIVX address");

    return pwallet->SetAddressBook(keyID, strLabel, AddressBook::AddressBookPurpose::DELEGATOR);
}

UniValue delegatorremove(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "delegatorremove \"addr\"\n"
            "\nUpdates the provided address <addr> from the allowed delegators keystore to a \"delegable\" status.\n"
            "This disables the staking of coins delegated to this wallet, owned by <addr>\n"

            "\nArguments:\n"
            "1. \"addr\"        (string, required) The address to blacklist\n"

            "\nResult:\n"
            "true|false           (boolean) true if successful.\n"

            "\nExamples:\n" +
            HelpExampleCli("delegatorremove", "DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6") +
            HelpExampleRpc("delegatorremove", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\""));

    CBitcoinAddress address(request.params[0].get_str());
    if (!address.IsValid() || address.IsStakingAddress())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid PIVX address");

    CKeyID keyID;
    if (!address.GetKeyID(keyID))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to get KeyID from PIVX address");

    if (!pwallet->HasAddressBook(keyID))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to get PIVX address from addressBook");

    std::string label = "";
    {
        LOCK(pwallet->cs_wallet);
        std::map<CTxDestination, AddressBook::CAddressBookData>::iterator mi = pwallet->mapAddressBook.find(address.Get());
        if (mi != pwallet->mapAddressBook.end()) {
            label = mi->second.name;
        }
    }

    return pwallet->SetAddressBook(keyID, label, AddressBook::AddressBookPurpose::DELEGABLE);
}

UniValue ListaddressesForPurpose(CWallet * const pwallet, const std::string strPurpose)
{
    const CChainParams::Base58Type addrType = (
            AddressBook::IsColdStakingPurpose(strPurpose) ?
                    CChainParams::STAKING_ADDRESS :
                    CChainParams::PUBKEY_ADDRESS);
    UniValue ret(UniValue::VARR);
    {
        LOCK(pwallet->cs_wallet);
        for (const auto& addr : pwallet->mapAddressBook) {
            if (addr.second.purpose != strPurpose) continue;
            UniValue entry(UniValue::VOBJ);
            entry.push_back(Pair("label", addr.second.name));
            entry.push_back(Pair("address", CBitcoinAddress(addr.first, addrType).ToString()));
            ret.push_back(entry);
        }
    }

    return ret;
}

UniValue listdelegators(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "listdelegators ( fBlacklist )\n"
            "\nShows the list of allowed delegator addresses for cold staking.\n"

            "\nArguments:\n"
            "1. fBlacklist             (boolean, optional, default = false) Show addresses removed\n"
            "                          from the delegators whitelist\n"

            "\nResult:\n"
            "[\n"
            "   {\n"
            "   \"label\": \"yyy\",    (string) account label\n"
            "   \"address\": \"xxx\",  (string) PIVX address string\n"
            "   }\n"
            "  ...\n"
            "]\n"

            "\nExamples:\n" +
            HelpExampleCli("listdelegators" , "") +
            HelpExampleRpc("listdelegators", ""));

    const bool fBlacklist = (request.params.size() > 0 ? request.params[0].get_bool() : false);
    return (fBlacklist ?
            ListaddressesForPurpose(pwallet, AddressBook::AddressBookPurpose::DELEGABLE) :
            ListaddressesForPurpose(pwallet, AddressBook::AddressBookPurpose::DELEGATOR));
}

UniValue liststakingaddresses(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "liststakingaddresses \"addr\"\n"
            "\nShows the list of staking addresses for this wallet.\n"

            "\nResult:\n"
            "[\n"
            "   {\n"
            "   \"label\": \"yyy\",  (string) account label\n"
            "   \"address\": \"xxx\",  (string) PIVX address string\n"
            "   }\n"
            "  ...\n"
            "]\n"

            "\nExamples:\n" +
            HelpExampleCli("liststakingaddresses" , "") +
            HelpExampleRpc("liststakingaddresses", ""));

    return ListaddressesForPurpose(pwallet, AddressBook::AddressBookPurpose::COLD_STAKING);
}

CBitcoinAddress GetAccountAddress(CWallet * const pwallet, std::string strAccount, bool bForceNew = false)
{
    CWalletDB walletdb(pwallet->GetDBHandle());

    CAccount account;
    walletdb.ReadAccount(strAccount, account);

    bool bKeyUsed = false;

    // Check if the current key has been used
    if (account.vchPubKey.IsValid()) {
        CScript scriptPubKey = GetScriptForDestination(account.vchPubKey.GetID());
        for (std::map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.begin();
             it != pwallet->mapWallet.end() && account.vchPubKey.IsValid();
             ++it) {
            const CWalletTx& wtx = (*it).second;
            for (const CTxOut& txout : wtx.vout)
                if (txout.scriptPubKey == scriptPubKey)
                    bKeyUsed = true;
        }
    }

    // Generate a new key
    if (!account.vchPubKey.IsValid() || bForceNew || bKeyUsed) {
        if (!pwallet->GetKeyFromPool(account.vchPubKey, false))
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

        pwallet->SetAddressBook(account.vchPubKey.GetID(), strAccount, AddressBook::AddressBookPurpose::RECEIVE);
        walletdb.WriteAccount(strAccount, account);
    }

    return CBitcoinAddress(account.vchPubKey.GetID());
}

UniValue getaccountaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getaccountaddress \"account\"\n"
            "\nDEPRECATED. Returns the current PIVX address for receiving payments to this account.\n"

            "\nArguments:\n"
            "1. \"account\"       (string, required) The account name for the address. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created and a new address created  if there is no account by the given name.\n"

            "\nResult:\n"
            "\"pivxaddress\"   (string) The account pivx address\n"

            "\nExamples:\n" +
            HelpExampleCli("getaccountaddress", "") + HelpExampleCli("getaccountaddress", "\"\"") +
            HelpExampleCli("getaccountaddress", "\"myaccount\"") + HelpExampleRpc("getaccountaddress", "\"myaccount\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount = AccountFromValue(request.params[0]);

    UniValue ret(UniValue::VSTR);

    ret = GetAccountAddress(pwallet, strAccount).ToString();
    return ret;
}


UniValue getrawchangeaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getrawchangeaddress\n"
            "\nReturns a new PIVX address, for receiving change.\n"
            "This is for use with raw transactions, NOT normal use.\n"

            "\nResult:\n"
            "\"address\"    (string) The address\n"

            "\nExamples:\n" +
            HelpExampleCli("getrawchangeaddress", "") + HelpExampleRpc("getrawchangeaddress", ""));

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!pwallet->IsLocked())
        pwallet->TopUpKeyPool();

    CReserveKey reservekey(pwallet);
    CPubKey vchPubKey;
    if (!reservekey.GetReservedKey(vchPubKey, true))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    reservekey.KeepKey();

    CKeyID keyID = vchPubKey.GetID();

    return CBitcoinAddress(keyID).ToString();
}


UniValue setaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "setaccount \"pivxaddress\" \"account\"\n"
            "\nDEPRECATED. Sets the account associated with the given address.\n"

            "\nArguments:\n"
            "1. \"pivxaddress\"  (string, required) The pivx address to be associated with an account.\n"
            "2. \"account\"         (string, required) The account to assign the address to.\n"

            "\nExamples:\n" +
            HelpExampleCli("setaccount", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\" \"tabby\"") + HelpExampleRpc("setaccount", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\", \"tabby\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    CBitcoinAddress address(request.params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid PIVX address");


    std::string strAccount;
    if (request.params.size() > 1)
        strAccount = AccountFromValue(request.params[1]);

    // Only add the account if the address is yours.
    if (IsMine(*pwallet, address.Get())) {
        // Detect when changing the account of an address that is the 'unused current key' of another account:
        if (pwallet->mapAddressBook.count(address.Get())) {
            std::string strOldAccount = pwallet->mapAddressBook[address.Get()].name;
            if (address == GetAccountAddress(pwallet, strOldAccount)) {
                GetAccountAddress(pwallet, strOldAccount, true);
            }
        }
        pwallet->SetAddressBook(address.Get(), strAccount, AddressBook::AddressBookPurpose::RECEIVE);
    } else
        throw JSONRPCError(RPC_MISC_ERROR, "setaccount can only be used with own address");

    return NullUniValue;
}


UniValue getaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getaccount \"pivxaddress\"\n"
            "\nDEPRECATED. Returns the account associated with the given address.\n"

            "\nArguments:\n"
            "1. \"pivxaddress\"  (string, required) The pivx address for account lookup.\n"

            "\nResult:\n"
            "\"accountname\"        (string) the account address\n"

            "\nExamples:\n" +
            HelpExampleCli("getaccount", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\"") + HelpExampleRpc("getaccount", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    CBitcoinAddress address(request.params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid PIVX address");

    std::string strAccount;
    std::map<CTxDestination, AddressBook::CAddressBookData>::iterator mi = pwallet->mapAddressBook.find(address.Get());
    if (mi != pwallet->mapAddressBook.end() && !(*mi).second.name.empty())
        strAccount = (*mi).second.name;
    return strAccount;
}


UniValue getaddressesbyaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getaddressesbyaccount \"account\"\n"
            "\nDEPRECATED. Returns the list of addresses for the given account.\n"

            "\nArguments:\n"
            "1. \"account\"  (string, required) The account name.\n"

            "\nResult:\n"
            "[                     (json array of string)\n"
            "  \"pivxaddress\"  (string) a pivx address associated with the given account\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n" +
            HelpExampleCli("getaddressesbyaccount", "\"tabby\"") + HelpExampleRpc("getaddressesbyaccount", "\"tabby\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount = AccountFromValue(request.params[0]);

    // Find all addresses that have the given account
    UniValue ret(UniValue::VARR);
    for (const PAIRTYPE(CBitcoinAddress, AddressBook::CAddressBookData) & item : pwallet->mapAddressBook) {
        const CBitcoinAddress& address = item.first;
        const std::string& strName = item.second.name;
        if (strName == strAccount)
            ret.push_back(address.ToString());
    }
    return ret;
}

void SendMoney(CWallet * const pwallet, const CTxDestination& address, CAmount nValue, CWalletTx& wtxNew, bool fUseIX = false)
{
    // Check amount
    if (nValue <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    if (nValue > pwallet->GetBalance())
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    std::string strError;
    if (pwallet->IsLocked()) {
        strError = "Error: Wallet locked, unable to create transaction!";
        LogPrintf("SendMoney() : %s", strError);
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    // Parse PIVX address
    CScript scriptPubKey = GetScriptForDestination(address);

    // Create and send the transaction
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    if (!pwallet->CreateTransaction(scriptPubKey, nValue, wtxNew, reservekey, nFeeRequired, strError, NULL, ALL_COINS, fUseIX, (CAmount)0)) {
        if (nValue + nFeeRequired > pwallet->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        LogPrintf("SendMoney() : %s\n", strError);
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    if (!pwallet->CommitTransaction(wtxNew, reservekey, (!fUseIX ? "tx" : "ix")))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
}

UniValue sendtoaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 4)
        throw std::runtime_error(
            "sendtoaddress \"pivxaddress\" amount ( \"comment\" \"comment-to\" )\n"
            "\nSend an amount to a given address. The amount is a real and is rounded to the nearest 0.00000001\n" +
            HelpRequiringPassphrase(pwallet) + "\n"

            "\nArguments:\n"
            "1. \"pivxaddress\"  (string, required) The pivx address to send to.\n"
            "2. \"amount\"      (numeric, required) The amount in PIV to send. eg 0.1\n"
            "3. \"comment\"     (string, optional) A comment used to store what the transaction is for. \n"
            "                             This is not part of the transaction, just kept in your wallet.\n"
            "4. \"comment-to\"  (string, optional) A comment to store the name of the person or organization \n"
            "                             to which you're sending the transaction. This is not part of the \n"
            "                             transaction, just kept in your wallet.\n"

            "\nResult:\n"
            "\"transactionid\"  (string) The transaction id.\n"

            "\nExamples:\n" +
            HelpExampleCli("sendtoaddress", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\" 0.1") +
            HelpExampleCli("sendtoaddress", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\" 0.1 \"donation\" \"seans outpost\"") +
            HelpExampleRpc("sendtoaddress", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\", 0.1, \"donation\", \"seans outpost\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    CBitcoinAddress address(request.params[0].get_str());
    if (!address.IsValid() || address.IsStakingAddress())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid PIVX address");

    // Amount
    CAmount nAmount = AmountFromValue(request.params[1]);

    // Wallet comments
    CWalletTx wtx;
    if (request.params.size() > 2 && !request.params[2].isNull() && !request.params[2].get_str().empty())
        wtx.mapValue["comment"] = request.params[2].get_str();
    if (request.params.size() > 3 && !request.params[3].isNull() && !request.params[3].get_str().empty())
        wtx.mapValue["to"] = request.params[3].get_str();

    EnsureWalletIsUnlocked(pwallet, false);

    SendMoney(pwallet, address.Get(), nAmount, wtx);

    return wtx.GetHash().GetHex();
}

UniValue CreateColdStakeDelegation(CWallet * const pwallet, const UniValue& params, CWalletTx& wtxNew, CReserveKey& reservekey)
{
    LOCK2(cs_main, pwallet->cs_wallet);

    // Check that Cold Staking has been enforced or fForceNotEnabled = true
    bool fForceNotEnabled = false;
    if (params.size() > 5 && !params[5].isNull())
        fForceNotEnabled = params[5].get_bool();

    if (!sporkManager.IsSporkActive(SPORK_17_COLDSTAKING_ENFORCEMENT) && !fForceNotEnabled) {
        std::string errMsg = "Cold Staking disabled with SPORK 17.\n"
                "You may force the stake delegation setting fForceNotEnabled to true.\n"
                "WARNING: If relayed before activation, this tx will be rejected resulting in a ban.\n";
        throw JSONRPCError(RPC_WALLET_ERROR, errMsg);
    }

    // Get Staking Address
    CBitcoinAddress stakeAddr(params[0].get_str());
    CKeyID stakeKey;
    if (!stakeAddr.IsValid() || !stakeAddr.IsStakingAddress())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid PIVX staking address");
    if (!stakeAddr.GetKeyID(stakeKey))
        throw JSONRPCError(RPC_WALLET_ERROR, "Unable to get stake pubkey hash from stakingaddress");

    // Get Amount
    CAmount nValue = AmountFromValue(params[1]);
    if (nValue < MIN_COLDSTAKING_AMOUNT)
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid amount (%d). Min amount: %d",
                nValue, MIN_COLDSTAKING_AMOUNT));

    // include already delegated coins
    bool fUseDelegated = false;
    if (params.size() > 4 && !params[4].isNull())
        fUseDelegated = params[4].get_bool();

    // Check amount
    CAmount currBalance = pwallet->GetBalance() + (fUseDelegated ? pwallet->GetDelegatedBalance() : 0);
    if (nValue > currBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    std::string strError;
    EnsureWalletIsUnlocked(pwallet, false);

    // Get Owner Address
    CBitcoinAddress ownerAddr;
    CKeyID ownerKey;
    if (params.size() > 2 && !params[2].isNull() && !params[2].get_str().empty()) {
        // Address provided
        ownerAddr.SetString(params[2].get_str());
        if (!ownerAddr.IsValid() || ownerAddr.IsStakingAddress())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid PIVX spending address");
        if (!ownerAddr.GetKeyID(ownerKey))
            throw JSONRPCError(RPC_WALLET_ERROR, "Unable to get spend pubkey hash from owneraddress");
        // Check that the owner address belongs to this wallet, or fForceExternalAddr is true
        bool fForceExternalAddr = params.size() > 3 && !params[3].isNull() ? params[3].get_bool() : false;
        if (!fForceExternalAddr && !pwallet->HaveKey(ownerKey)) {
            std::string errMsg = strprintf("The provided owneraddress \"%s\" is not present in this wallet.\n"
                    "Set 'fExternalOwner' argument to true, in order to force the stake delegation to an external owner address.\n"
                    "e.g. delegatestake stakingaddress amount owneraddress true.\n"
                    "WARNING: Only the owner of the key to owneraddress will be allowed to spend these coins after the delegation.",
                    ownerAddr.ToString());
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errMsg);
        }

    } else {
        // Get new owner address from keypool
        ownerAddr = GetNewAddressFromAccount(pwallet, "delegated", NullUniValue);
        if (!ownerAddr.GetKeyID(ownerKey))
            throw JSONRPCError(RPC_WALLET_ERROR, "Unable to get spend pubkey hash from owneraddress");
    }

    // Get P2CS script for addresses
    CScript scriptPubKey = GetScriptForStakeDelegation(stakeKey, ownerKey);

    // Create the transaction
    CAmount nFeeRequired;
    if (!pwallet->CreateTransaction(scriptPubKey, nValue, wtxNew, reservekey, nFeeRequired, strError, NULL, ALL_COINS, /*fUseIX*/ false, (CAmount)0, fUseDelegated)) {
        if (nValue + nFeeRequired > currBalance)
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        LogPrintf("%s : %s\n", __func__, strError);
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("owner_address", ownerAddr.ToString()));
    result.push_back(Pair("staker_address", stakeAddr.ToString()));
    return result;
}

UniValue delegatestake(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 6)
        throw std::runtime_error(
            "delegatestake \"stakingaddress\" amount ( \"owneraddress\" fExternalOwner fUseDelegated fForceNotEnabled )\n"
            "\nDelegate an amount to a given address for cold staking. The amount is a real and is rounded to the nearest 0.00000001\n" +
            HelpRequiringPassphrase(pwallet) + "\n"

            "\nArguments:\n"
            "1. \"stakingaddress\"      (string, required) The pivx staking address to delegate.\n"
            "2. \"amount\"              (numeric, required) The amount in PIV to delegate for staking. eg 100\n"
            "3. \"owneraddress\"        (string, optional) The pivx address corresponding to the key that will be able to spend the stake. \n"
            "                               If not provided, or empty string, a new wallet address is generated.\n"
            "4. \"fExternalOwner\"      (boolean, optional, default = false) use the provided 'owneraddress' anyway, even if not present in this wallet.\n"
            "                               WARNING: The owner of the keys to 'owneraddress' will be the only one allowed to spend these coins.\n"
            "5. \"fUseDelegated\"       (boolean, optional, default = false) include already delegated inputs if needed."
            "6. \"fForceNotEnabled\"    (boolean, optional, default = false) force the creation even if SPORK 17 is disabled (for tests)."

            "\nResult:\n"
            "{\n"
            "   \"owner_address\": \"xxx\"   (string) The owner (delegator) owneraddress.\n"
            "   \"staker_address\": \"xxx\"  (string) The cold staker (delegate) stakingaddress.\n"
            "   \"txid\": \"xxx\"            (string) The stake delegation transaction id.\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("delegatestake", "\"S1t2a3kab9c8c71VA78xxxy4MxZg6vgeS6\" 100") +
            HelpExampleCli("delegatestake", "\"S1t2a3kab9c8c71VA78xxxy4MxZg6vgeS6\" 1000 \"DMJRSsuU9zfyrvxVaAEFQqK4MxZg34fk\"") +
            HelpExampleRpc("delegatestake", "\"S1t2a3kab9c8c71VA78xxxy4MxZg6vgeS6\", 1000, \"DMJRSsuU9zfyrvxVaAEFQqK4MxZg34fk\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    CWalletTx wtx;
    CReserveKey reservekey(pwallet);
    UniValue ret = CreateColdStakeDelegation(pwallet, request.params, wtx, reservekey);

    if (!pwallet->CommitTransaction(wtx, reservekey, "tx"))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");

    ret.push_back(Pair("txid", wtx.GetHash().GetHex()));
    return ret;
}

UniValue rawdelegatestake(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 5)
        throw std::runtime_error(
            "rawdelegatestake \"stakingaddress\" amount ( \"owneraddress\" fExternalOwner fUseDelegated )\n"
            "\nDelegate an amount to a given address for cold staking. The amount is a real and is rounded to the nearest 0.00000001\n"
            "\nDelegate transaction is returned as json object." +
            HelpRequiringPassphrase(pwallet) + "\n"

            "\nArguments:\n"
            "1. \"stakingaddress\"      (string, required) The pivx staking address to delegate.\n"
            "2. \"amount\"              (numeric, required) The amount in PIV to delegate for staking. eg 100\n"
            "3. \"owneraddress\"        (string, optional) The pivx address corresponding to the key that will be able to spend the stake. \n"
            "                               If not provided, or empty string, a new wallet address is generated.\n"
            "4. \"fExternalOwner\"      (boolean, optional, default = false) use the provided 'owneraddress' anyway, even if not present in this wallet.\n"
            "                               WARNING: The owner of the keys to 'owneraddress' will be the only one allowed to spend these coins.\n"
            "5. \"fUseDelegated         (boolean, optional, default = false) include already delegated inputs if needed."

            "\nResult:\n"
            "{\n"
            "  \"txid\" : \"id\",        (string) The transaction id (same as provided)\n"
            "  \"version\" : n,          (numeric) The version\n"
            "  \"size\" : n,             (numeric) The serialized transaction size\n"
            "  \"locktime\" : ttt,       (numeric) The lock time\n"
            "  \"vin\" : [               (array of json objects)\n"
            "     {\n"
            "       \"txid\": \"id\",    (string) The transaction id\n"
            "       \"vout\": n,         (numeric) \n"
            "       \"scriptSig\": {     (json object) The script\n"
            "         \"asm\": \"asm\",  (string) asm\n"
            "         \"hex\": \"hex\"   (string) hex\n"
            "       },\n"
            "       \"sequence\": n      (numeric) The script sequence number\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vout\" : [              (array of json objects)\n"
            "     {\n"
            "       \"value\" : x.xxx,            (numeric) The value in btc\n"
            "       \"n\" : n,                    (numeric) index\n"
            "       \"scriptPubKey\" : {          (json object)\n"
            "         \"asm\" : \"asm\",          (string) the asm\n"
            "         \"hex\" : \"hex\",          (string) the hex\n"
            "         \"reqSigs\" : n,            (numeric) The required sigs\n"
            "         \"type\" : \"pubkeyhash\",  (string) The type, eg 'pubkeyhash'\n"
            "         \"addresses\" : [           (json array of string)\n"
            "           \"pivxaddress\"        (string) pivx address\n"
            "           ,...\n"
            "         ]\n"
            "       }\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"hex\" : \"data\",       (string) The serialized, hex-encoded data for 'txid'\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("rawdelegatestake", "\"S1t2a3kab9c8c71VA78xxxy4MxZg6vgeS6\" 100") +
            HelpExampleCli("rawdelegatestake", "\"S1t2a3kab9c8c71VA78xxxy4MxZg6vgeS6\" 1000 \"DMJRSsuU9zfyrvxVaAEFQqK4MxZg34fk\"") +
            HelpExampleRpc("rawdelegatestake", "\"S1t2a3kab9c8c71VA78xxxy4MxZg6vgeS6\", 1000, \"DMJRSsuU9zfyrvxVaAEFQqK4MxZg34fk\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    CWalletTx wtx;
    CReserveKey reservekey(pwallet);
    CreateColdStakeDelegation(pwallet, request.params, wtx, reservekey);

    UniValue result(UniValue::VOBJ);
    TxToUniv(wtx, UINT256_ZERO, result);

    return result;
}

UniValue sendtoaddressix(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 4)
        throw std::runtime_error(
            "sendtoaddressix \"pivxaddress\" amount ( \"comment\" \"comment-to\" )\n"
            "\nSend an amount to a given address. The amount is a real and is rounded to the nearest 0.00000001\n" +
            HelpRequiringPassphrase(pwallet) + "\n"

            "\nArguments:\n"
            "1. \"pivxaddress\"  (string, required) The pivx address to send to.\n"
            "2. \"amount\"      (numeric, required) The amount in PIV to send. eg 0.1\n"
            "3. \"comment\"     (string, optional) A comment used to store what the transaction is for. \n"
            "                             This is not part of the transaction, just kept in your wallet.\n"
            "4. \"comment-to\"  (string, optional) A comment to store the name of the person or organization \n"
            "                             to which you're sending the transaction. This is not part of the \n"
            "                             transaction, just kept in your wallet.\n"

            "\nResult:\n"
            "\"transactionid\"  (string) The transaction id.\n"

            "\nExamples:\n" +
            HelpExampleCli("sendtoaddressix", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\" 0.1") +
            HelpExampleCli("sendtoaddressix", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\" 0.1 \"donation\" \"seans outpost\"") +
            HelpExampleRpc("sendtoaddressix", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\", 0.1, \"donation\", \"seans outpost\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    CBitcoinAddress address(request.params[0].get_str());
    if (!address.IsValid() || address.IsStakingAddress())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid PIVX address");

    // Amount
    CAmount nAmount = AmountFromValue(request.params[1]);

    // Wallet comments
    CWalletTx wtx;
    if (request.params.size() > 2 && !request.params[2].isNull() && !request.params[2].get_str().empty())
        wtx.mapValue["comment"] = request.params[2].get_str();
    if (request.params.size() > 3 && !request.params[3].isNull() && !request.params[3].get_str().empty())
        wtx.mapValue["to"] = request.params[3].get_str();

    EnsureWalletIsUnlocked(pwallet, false);

    SendMoney(pwallet, address.Get(), nAmount, wtx, true);

    return wtx.GetHash().GetHex();
}

UniValue listaddressgroupings(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp)
        throw std::runtime_error(
            "listaddressgroupings\n"
            "\nLists groups of addresses which have had their common ownership\n"
            "made public by common use as inputs or as the resulting change\n"
            "in past transactions\n"

            "\nResult:\n"
            "[\n"
            "  [\n"
            "    [\n"
            "      \"pivxaddress\",     (string) The pivx address\n"
            "      amount,                 (numeric) The amount in PIV\n"
            "      \"account\"             (string, optional) The account (DEPRECATED)\n"
            "    ]\n"
            "    ,...\n"
            "  ]\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n" +
            HelpExampleCli("listaddressgroupings", "") + HelpExampleRpc("listaddressgroupings", ""));

    LOCK2(cs_main, pwallet->cs_wallet);

    UniValue jsonGroupings(UniValue::VARR);
    std::map<CTxDestination, CAmount> balances = pwallet->GetAddressBalances();
    for (std::set<CTxDestination> grouping : pwallet->GetAddressGroupings()) {
        UniValue jsonGrouping(UniValue::VARR);
        for (CTxDestination address : grouping) {
            UniValue addressInfo(UniValue::VARR);
            addressInfo.push_back(CBitcoinAddress(address).ToString());
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                if (pwallet->mapAddressBook.find(CBitcoinAddress(address).Get()) != pwallet->mapAddressBook.end())
                    addressInfo.push_back(pwallet->mapAddressBook.find(CBitcoinAddress(address).Get())->second.name);
            }
            jsonGrouping.push_back(addressInfo);
        }
        jsonGroupings.push_back(jsonGrouping);
    }
    return jsonGroupings;
}

UniValue signmessage(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "signmessage \"pivxaddress\" \"message\"\n"
            "\nSign a message with the private key of an address" +
            HelpRequiringPassphrase(pwallet) + "\n"

            "\nArguments:\n"
            "1. \"pivxaddress\"  (string, required) The pivx address to use for the private key.\n"
            "2. \"message\"         (string, required) The message to create a signature of.\n"

            "\nResult:\n"
            "\"signature\"          (string) The signature of the message encoded in base 64\n"

            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n" +
            HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n" +
            HelpExampleCli("signmessage", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\" \"my message\"") +
            "\nVerify the signature\n" +
            HelpExampleCli("verifymessage", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\" \"signature\" \"my message\"") +
            "\nAs json rpc\n" +
            HelpExampleRpc("signmessage", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\", \"my message\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet, false);

    std::string strAddress = request.params[0].get_str();
    std::string strMessage = request.params[1].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    CKey key;
    if (!pwallet->GetKey(keyID, key))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size());
}

UniValue getreceivedbyaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "getreceivedbyaddress \"pivxaddress\" ( minconf )\n"
            "\nReturns the total amount received by the given pivxaddress in transactions with at least minconf confirmations.\n"

            "\nArguments:\n"
            "1. \"pivxaddress\"  (string, required) The pivx address for transactions.\n"
            "2. minconf             (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"

            "\nResult:\n"
            "amount   (numeric) The total amount in PIV received at this address.\n"

            "\nExamples:\n"
            "\nThe amount from transactions with at least 1 confirmation\n" +
            HelpExampleCli("getreceivedbyaddress", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\"") +
            "\nThe amount including unconfirmed transactions, zero confirmations\n" +
            HelpExampleCli("getreceivedbyaddress", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\" 0") +
            "\nThe amount with at least 6 confirmation, very safe\n" +
            HelpExampleCli("getreceivedbyaddress", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\" 6") +
            "\nAs a json rpc call\n" +
            HelpExampleRpc("getreceivedbyaddress", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\", 6"));

    LOCK2(cs_main, pwallet->cs_wallet);

    // pivx address
    CBitcoinAddress address = CBitcoinAddress(request.params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid PIVX address");
    CScript scriptPubKey = GetScriptForDestination(address.Get());
    if (!IsMine(*pwallet, scriptPubKey))
        throw JSONRPCError(RPC_WALLET_ERROR, "Address not found in wallet");

    // Minimum confirmations
    int nMinDepth = 1;
    if (request.params.size() > 1)
        nMinDepth = request.params[1].get_int();

    // Tally
    CAmount nAmount = 0;
    for (std::map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.begin(); it != pwallet->mapWallet.end(); ++it) {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || !IsFinalTx(wtx))
            continue;

        for (const CTxOut& txout : wtx.vout)
            if (txout.scriptPubKey == scriptPubKey)
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
    }

    return ValueFromAmount(nAmount);
}


UniValue getreceivedbyaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "getreceivedbyaccount \"account\" ( minconf )\n"
            "\nDEPRECATED. Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.\n"

            "\nArguments:\n"
            "1. \"account\"      (string, required) The selected account, may be the default account using \"\".\n"
            "2. minconf          (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"

            "\nResult:\n"
            "amount              (numeric) The total amount in PIV received for this account.\n"

            "\nExamples:\n"
            "\nAmount received by the default account with at least 1 confirmation\n" +
            HelpExampleCli("getreceivedbyaccount", "\"\"") +
            "\nAmount received at the tabby account including unconfirmed amounts with zero confirmations\n" +
            HelpExampleCli("getreceivedbyaccount", "\"tabby\" 0") +
            "\nThe amount with at least 6 confirmation, very safe\n" +
            HelpExampleCli("getreceivedbyaccount", "\"tabby\" 6") +
            "\nAs a json rpc call\n" +
            HelpExampleRpc("getreceivedbyaccount", "\"tabby\", 6"));

    LOCK2(cs_main, pwallet->cs_wallet);

    // Minimum confirmations
    int nMinDepth = 1;
    if (request.params.size() > 1)
        nMinDepth = request.params[1].get_int();

    // Get the set of pub keys assigned to account
    std::string strAccount = AccountFromValue(request.params[0]);
    std::set<CTxDestination> setAddress = pwallet->GetAccountAddresses(strAccount);

    // Tally
    CAmount nAmount = 0;
    for (std::map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.begin(); it != pwallet->mapWallet.end(); ++it) {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || !IsFinalTx(wtx))
            continue;

        for (const CTxOut& txout : wtx.vout) {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*pwallet, address) && setAddress.count(address))
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
        }
    }

    return (double)nAmount / (double)COIN;
}


CAmount GetAccountBalance(CWallet * const pwallet, CWalletDB& walletdb, const std::string& strAccount, int nMinDepth, const isminefilter& filter)
{
    CAmount nBalance = 0;

    // Tally wallet transactions
    for (std::map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.begin(); it != pwallet->mapWallet.end(); ++it) {
        const CWalletTx& wtx = (*it).second;
        bool fConflicted;
        int depth = wtx.GetDepthAndMempool(fConflicted);

        if (!IsFinalTx(wtx) || wtx.GetBlocksToMaturity() > 0 || depth < 0 || fConflicted)
            continue;

        if (strAccount == "*") {
            // Calculate total balance a different way from GetBalance()
            // (GetBalance() sums up all unspent TxOuts)
            CAmount allFee;
            std::string strSentAccount;
            std::list<COutputEntry> listReceived;
            std::list<COutputEntry> listSent;
            wtx.GetAmounts(listReceived, listSent, allFee, strSentAccount, filter);
            if (wtx.GetDepthInMainChain() >= nMinDepth) {
                for (const COutputEntry& r : listReceived)
                    nBalance += r.amount;
            }
            for (const COutputEntry& s : listSent)
                nBalance -= s.amount;
            nBalance -= allFee;

        } else {

            CAmount nReceived, nSent, nFee;
            wtx.GetAccountAmounts(strAccount, nReceived, nSent, nFee, filter);

            if (nReceived != 0 && depth >= nMinDepth)
                nBalance += nReceived;
            nBalance -= nSent + nFee;
        }
    }

    // Tally internal accounting entries
    if (strAccount != "*")
        nBalance += walletdb.GetAccountCreditDebit(strAccount);

    return nBalance;
}

CAmount GetAccountBalance(CWallet * const pwallet, const std::string& strAccount, int nMinDepth, const isminefilter& filter)
{
    CWalletDB walletdb(pwallet->GetDBHandle());
    return GetAccountBalance(pwallet, walletdb, strAccount, nMinDepth, filter);
}


UniValue getbalance(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() > 4)
        throw std::runtime_error(
            "getbalance ( \"account\" minconf includeWatchonly includeDelegated )\n"
            "\nIf account is not specified, returns the server's total available balance (excluding zerocoins).\n"
            "If account is specified (DEPRECATED), returns the balance in the account.\n"
            "Note that the account \"\" is not the same as leaving the parameter out.\n"
            "The server total may be different to the balance in the default \"\" account.\n"

            "\nArguments:\n"
            "1. \"account\"      (string, optional) DEPRECATED. The selected account, or \"*\" for entire wallet. It may be the default account using \"\".\n"
            "2. minconf          (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "3. includeWatchonly (bool, optional, default=false) Also include balance in watchonly addresses (see 'importaddress')\n"
            "4. includeDelegated (bool, optional, default=true) Also include balance delegated to cold stakers\n"

            "\nResult:\n"
            "amount              (numeric) The total amount in PIV received for this account.\n"

            "\nExamples:\n"
            "\nThe total amount in the wallet\n" +
            HelpExampleCli("getbalance", "") +
            "\nThe total amount in the wallet, with at least 5 confirmations\n" +
            HelpExampleCli("getbalance", "\"*\" 6") +
            "\nAs a json rpc call\n" +
            HelpExampleRpc("getbalance", "\"*\", 6"));

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.params.size() == 0)
        return ValueFromAmount(pwallet->GetBalance());

    int nMinDepth = 1;
    if (request.params.size() > 1)
        nMinDepth = request.params[1].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if ( request.params.size() > 2 && request.params[2].get_bool() )
        filter = filter | ISMINE_WATCH_ONLY;
    if ( !(request.params.size() > 3) || request.params[3].get_bool() )
        filter = filter | ISMINE_SPENDABLE_DELEGATED;

    std::string strAccount = request.params[0].get_str();
    return ValueFromAmount(GetAccountBalance(pwallet, strAccount, nMinDepth, filter));
}

UniValue getcoldstakingbalance(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getcoldstakingbalance ( \"account\" )\n"
            "\nIf account is not specified, returns the server's total available cold balance.\n"
            "If account is specified (DEPRECATED), returns the cold balance in the account.\n"
            "Note that the account \"\" is not the same as leaving the parameter out.\n"
            "The server total may be different to the balance in the default \"\" account.\n"

            "\nArguments:\n"
            "1. \"account\"      (string, optional) DEPRECATED. The selected account, or \"*\" for entire wallet. It may be the default account using \"\".\n"

            "\nResult:\n"
            "amount              (numeric) The total amount in PIV received for this account in P2CS contracts.\n"

            "\nExamples:\n"
            "\nThe total amount in the wallet\n" +
            HelpExampleCli("getcoldstakingbalance", "") +
            "\nAs a json rpc call\n" +
            HelpExampleRpc("getcoldstakingbalance", "\"*\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.params.size() == 0)
        return ValueFromAmount(pwallet->GetColdStakingBalance());

    std::string strAccount = request.params[0].get_str();
    return ValueFromAmount(GetAccountBalance(pwallet, strAccount, /*nMinDepth*/ 1, ISMINE_COLD));
}

UniValue getdelegatedbalance(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getdelegatedbalance ( \"account\" )\n"
            "\nIf account is not specified, returns the server's total available delegated balance (sum of all utxos delegated\n"
            "to a cold staking address to stake on behalf of addresses of this wallet).\n"
            "If account is specified (DEPRECATED), returns the cold balance in the account.\n"
            "Note that the account \"\" is not the same as leaving the parameter out.\n"
            "The server total may be different to the balance in the default \"\" account.\n"

            "\nArguments:\n"
            "1. \"account\"      (string, optional) DEPRECATED. The selected account, or \"*\" for entire wallet. It may be the default account using \"\".\n"

            "\nResult:\n"
            "amount              (numeric) The total amount in PIV received for this account in P2CS contracts.\n"

            "\nExamples:\n"
            "\nThe total amount in the wallet\n" +
            HelpExampleCli("getdelegatedbalance", "") +
            "\nAs a json rpc call\n" +
            HelpExampleRpc("getdelegatedbalance", "\"*\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.params.size() == 0)
        return ValueFromAmount(pwallet->GetDelegatedBalance());

    std::string strAccount = request.params[0].get_str();
    return ValueFromAmount(GetAccountBalance(pwallet, strAccount, /*nMinDepth*/ 1, ISMINE_SPENDABLE_DELEGATED));
}

UniValue getunconfirmedbalance(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() > 0)
        throw std::runtime_error(
            "getunconfirmedbalance\n"
            "Returns the server's total unconfirmed balance\n");

    LOCK2(cs_main, pwallet->cs_wallet);

    return ValueFromAmount(pwallet->GetUnconfirmedBalance());
}


UniValue movecmd(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 3 || request.params.size() > 5)
        throw std::runtime_error(
            "move \"fromaccount\" \"toaccount\" amount ( minconf \"comment\" )\n"
            "\nDEPRECATED. Move a specified amount from one account in your wallet to another.\n"

            "\nArguments:\n"
            "1. \"fromaccount\"   (string, required) The name of the account to move funds from. May be the default account using \"\".\n"
            "2. \"toaccount\"     (string, required) The name of the account to move funds to. May be the default account using \"\".\n"
            "3. amount            (numeric, required) Quantity of PIV to move between accounts.\n"
            "4. minconf           (numeric, optional, default=1) Only use funds with at least this many confirmations.\n"
            "5. \"comment\"       (string, optional) An optional comment, stored in the wallet only.\n"

            "\nResult:\n"
            "true|false           (boolean) true if successful.\n"

            "\nExamples:\n"
            "\nMove 0.01 PIV from the default account to the account named tabby\n" +
            HelpExampleCli("move", "\"\" \"tabby\" 0.01") +
            "\nMove 0.01 PIV from timotei to akiko with a comment\n" +
            HelpExampleCli("move", "\"timotei\" \"akiko\" 0.01 1 \"happy birthday!\"") +
            "\nAs a json rpc call\n" +
            HelpExampleRpc("move", "\"timotei\", \"akiko\", 0.01, 1, \"happy birthday!\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strFrom = AccountFromValue(request.params[0]);
    std::string strTo = AccountFromValue(request.params[1]);
    CAmount nAmount = AmountFromValue(request.params[2]);
    if (request.params.size() > 3)
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)request.params[3].get_int();
    std::string strComment;
    if (request.params.size() > 4)
        strComment = request.params[4].get_str();

    if (!pwallet->AccountMove(strFrom, strTo, nAmount, strComment))
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");

    return true;
}


UniValue sendfrom(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 3 || request.params.size() > 7)
        throw std::runtime_error(
            "sendfrom \"fromaccount\" \"topivxaddress\" amount ( minconf \"comment\" \"comment-to\" includeDelegated)\n"
            "\nDEPRECATED (use sendtoaddress). Send an amount from an account to a pivx address.\n"
            "The amount is a real and is rounded to the nearest 0.00000001." +
            HelpRequiringPassphrase(pwallet) + "\n"

            "\nArguments:\n"
            "1. \"fromaccount\"       (string, required) The name of the account to send funds from. May be the default account using \"\".\n"
            "2. \"topivxaddress\"  (string, required) The pivx address to send funds to.\n"
            "3. amount                (numeric, required) The amount in PIV. (transaction fee is added on top).\n"
            "4. minconf               (numeric, optional, default=1) Only use funds with at least this many confirmations.\n"
            "5. \"comment\"           (string, optional) A comment used to store what the transaction is for. \n"
            "                                     This is not part of the transaction, just kept in your wallet.\n"
            "6. \"comment-to\"        (string, optional) An optional comment to store the name of the person or organization \n"
            "                                     to which you're sending the transaction. This is not part of the transaction, \n"
            "                                     it is just kept in your wallet.\n"
            "7. includeDelegated     (bool, optional, default=false) Also include balance delegated to cold stakers\n"

            "\nResult:\n"
            "\"transactionid\"        (string) The transaction id.\n"

            "\nExamples:\n"
            "\nSend 0.01 PIV from the default account to the address, must have at least 1 confirmation\n" +
            HelpExampleCli("sendfrom", "\"\" \"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\" 0.01") +
            "\nSend 0.01 from the tabby account to the given address, funds must have at least 6 confirmations\n" +
            HelpExampleCli("sendfrom", "\"tabby\" \"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\" 0.01 6 \"donation\" \"seans outpost\"") +
            "\nAs a json rpc call\n" +
            HelpExampleRpc("sendfrom", "\"tabby\", \"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\", 0.01, 6, \"donation\", \"seans outpost\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount = AccountFromValue(request.params[0]);
    CBitcoinAddress address(request.params[1].get_str());
    if (!address.IsValid() || address.IsStakingAddress())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid PIVX address");
    CAmount nAmount = AmountFromValue(request.params[2]);
    int nMinDepth = 1;
    if (request.params.size() > 3)
        nMinDepth = request.params[3].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (request.params.size() > 4 && !request.params[4].isNull() && !request.params[4].get_str().empty())
        wtx.mapValue["comment"] = request.params[4].get_str();
    if (request.params.size() > 5 && !request.params[5].isNull() && !request.params[5].get_str().empty())
        wtx.mapValue["to"] = request.params[5].get_str();

    isminefilter filter = ISMINE_SPENDABLE;
    if (request.params.size() > 6 && request.params[6].get_bool())
        filter = filter | ISMINE_SPENDABLE_DELEGATED;

    EnsureWalletIsUnlocked(pwallet, false);

    // Check funds
    CAmount nBalance = GetAccountBalance(pwallet, strAccount, nMinDepth, filter);
    if (nAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    SendMoney(pwallet, address.Get(), nAmount, wtx);

    return wtx.GetHash().GetHex();
}


UniValue sendmany(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 5)
        throw std::runtime_error(
            "sendmany \"fromaccount\" {\"address\":amount,...} ( minconf \"comment\" includeDelegated )\n"
            "\nSend multiple times. Amounts are double-precision floating point numbers." +
            HelpRequiringPassphrase(pwallet) + "\n"

            "\nArguments:\n"
            "1. \"fromaccount\"         (string, required) DEPRECATED. The account to send the funds from. Should be \"\" for the default account\n"
            "2. \"amounts\"             (string, required) A json object with addresses and amounts\n"
            "    {\n"
            "      \"address\":amount   (numeric) The pivx address is the key, the numeric amount in PIV is the value\n"
            "      ,...\n"
            "    }\n"
            "3. minconf                 (numeric, optional, default=1) Only use the balance confirmed at least this many times.\n"
            "4. \"comment\"             (string, optional) A comment\n"
            "5. includeDelegated     (bool, optional, default=false) Also include balance delegated to cold stakers\n"

            "\nResult:\n"
            "\"transactionid\"          (string) The transaction id for the send. Only 1 transaction is created regardless of \n"
            "                                    the number of addresses.\n"

            "\nExamples:\n"
            "\nSend two amounts to two different addresses:\n" +
            HelpExampleCli("sendmany", "\"\" \"{\\\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\\\":0.01,\\\"DAD3Y6ivr8nPQLT1NEPX84DxGCw9jz9Jvg\\\":0.02}\"") +
            "\nSend two amounts to two different addresses setting the confirmation and comment:\n" +
            HelpExampleCli("sendmany", "\"\" \"{\\\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\\\":0.01,\\\"DAD3Y6ivr8nPQLT1NEPX84DxGCw9jz9Jvg\\\":0.02}\" 6 \"testing\"") +
            "\nAs a json rpc call\n" +
            HelpExampleRpc("sendmany", "\"\", \"{\\\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\\\":0.01,\\\"DAD3Y6ivr8nPQLT1NEPX84DxGCw9jz9Jvg\\\":0.02}\", 6, \"testing\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount = AccountFromValue(request.params[0]);
    UniValue sendTo = request.params[1].get_obj();
    int nMinDepth = 1;
    if (request.params.size() > 2)
        nMinDepth = request.params[2].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (request.params.size() > 3 && !request.params[3].isNull() && !request.params[3].get_str().empty())
        wtx.mapValue["comment"] = request.params[3].get_str();

    std::set<CBitcoinAddress> setAddress;
    std::vector<std::pair<CScript, CAmount> > vecSend;

    CAmount totalAmount = 0;
    std::vector<std::string> keys = sendTo.getKeys();
    for (const std::string& name_ : keys) {
        CBitcoinAddress address(name_);
        if (!address.IsValid() || address.IsStakingAddress())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid PIVX address: ")+name_);

        if (setAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ")+name_);
        setAddress.insert(address);

        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = AmountFromValue(sendTo[name_]);
        totalAmount += nAmount;

        vecSend.push_back(std::make_pair(scriptPubKey, nAmount));
    }

    isminefilter filter = ISMINE_SPENDABLE;
    if (request.params.size() > 5 && request.params[5].get_bool())
        filter = filter | ISMINE_SPENDABLE_DELEGATED;

    EnsureWalletIsUnlocked(pwallet, false);

    // Check funds
    CAmount nBalance = GetAccountBalance(pwallet, strAccount, nMinDepth, ISMINE_SPENDABLE);
    if (totalAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
    CReserveKey keyChange(pwallet);
    CAmount nFeeRequired = 0;
    std::string strFailReason;
    bool fCreated = pwallet->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, strFailReason);
    if (!fCreated)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    if (!pwallet->CommitTransaction(wtx, keyChange))
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");

    return wtx.GetHash().GetHex();
}

// Defined in rpc/misc.cpp
extern CScript _createmultisig_redeemScript(CWallet * const pwallet, const UniValue& params);

UniValue addmultisigaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw std::runtime_error(
            "addmultisigaddress nrequired [\"key\",...] ( \"account\" )\n"
            "\nAdd a nrequired-to-sign multisignature address to the wallet.\n"
            "Each key is a PIVX address or hex-encoded public key.\n"
            "If 'account' is specified (DEPRECATED), assign address to that account.\n"

            "\nArguments:\n"
            "1. nrequired        (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keysobject\"   (string, required) A json array of pivx addresses or hex-encoded public keys\n"
            "     [\n"
            "       \"address\"  (string) pivx address or hex-encoded public key\n"
            "       ...,\n"
            "     ]\n"
            "3. \"account\"      (string, optional) DEPRECATED. An account to assign the addresses to.\n"

            "\nResult:\n"
            "\"pivxaddress\"  (string) A pivx address associated with the keys.\n"

            "\nExamples:\n"
            "\nAdd a multisig address from 2 addresses\n" +
            HelpExampleCli("addmultisigaddress", "2 \"[\\\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\\\",\\\"DAD3Y6ivr8nPQLT1NEPX84DxGCw9jz9Jvg\\\"]\"") +
            "\nAs json rpc call\n" +
            HelpExampleRpc("addmultisigaddress", "2, \"[\\\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\\\",\\\"DAD3Y6ivr8nPQLT1NEPX84DxGCw9jz9Jvg\\\"]\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount;
    if (request.params.size() > 2)
        strAccount = AccountFromValue(request.params[2]);

    // Construct using pay-to-script-hash:
    CScript inner = _createmultisig_redeemScript(pwallet, request.params);
    CScriptID innerID(inner);
    pwallet->AddCScript(inner);

    pwallet->SetAddressBook(innerID, strAccount, AddressBook::AddressBookPurpose::SEND);
    return CBitcoinAddress(innerID).ToString();
}


struct tallyitem {
    CAmount nAmount;
    int nConf;
    int nBCConf;
    std::vector<uint256> txids;
    bool fIsWatchonly;
    tallyitem()
    {
        nAmount = 0;
        nConf = std::numeric_limits<int>::max();
        nBCConf = std::numeric_limits<int>::max();
        fIsWatchonly = false;
    }
};

UniValue ListReceived(CWallet * const pwallet, const UniValue& params, bool fByAccounts)
{
    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    // Whether to include empty accounts
    bool fIncludeEmpty = false;
    if (params.size() > 1)
        fIncludeEmpty = params[1].get_bool();

    isminefilter filter = ISMINE_SPENDABLE_ALL;
    if (params.size() > 2)
        if (params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    // Tally
    std::map<CBitcoinAddress, tallyitem> mapTally;
    for (std::map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.begin(); it != pwallet->mapWallet.end(); ++it) {
        const CWalletTx& wtx = (*it).second;

        if (wtx.IsCoinBase() || !IsFinalTx(wtx))
            continue;

        int nDepth = wtx.GetDepthInMainChain();
        int nBCDepth = wtx.GetDepthInMainChain(false);
        if (nDepth < nMinDepth)
            continue;

        for (const CTxOut& txout : wtx.vout) {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address))
                continue;

            isminefilter mine = IsMine(*pwallet, address);
            if (!(mine & filter))
                continue;

            tallyitem& item = mapTally[address];
            item.nAmount += txout.nValue;
            item.nConf = std::min(item.nConf, nDepth);
            item.nBCConf = std::min(item.nBCConf, nBCDepth);
            item.txids.push_back(wtx.GetHash());
            if (mine & ISMINE_WATCH_ONLY)
                item.fIsWatchonly = true;
        }
    }

    // Reply
    UniValue ret(UniValue::VARR);
    std::map<std::string, tallyitem> mapAccountTally;
    for (const PAIRTYPE(CBitcoinAddress, AddressBook::CAddressBookData) & item : pwallet->mapAddressBook) {
        const CBitcoinAddress& address = item.first;
        const std::string& strAccount = item.second.name;
        std::map<CBitcoinAddress, tallyitem>::iterator it = mapTally.find(address);
        if (it == mapTally.end() && !fIncludeEmpty)
            continue;

        CAmount nAmount = 0;
        int nConf = std::numeric_limits<int>::max();
        int nBCConf = std::numeric_limits<int>::max();
        bool fIsWatchonly = false;
        if (it != mapTally.end()) {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
            nBCConf = (*it).second.nBCConf;
            fIsWatchonly = (*it).second.fIsWatchonly;
        }

        if (fByAccounts) {
            tallyitem& item = mapAccountTally[strAccount];
            item.nAmount += nAmount;
            item.nConf = std::min(item.nConf, nConf);
            item.nBCConf = std::min(item.nBCConf, nBCConf);
            item.fIsWatchonly = fIsWatchonly;
        } else {
            UniValue obj(UniValue::VOBJ);
            if (fIsWatchonly)
                obj.push_back(Pair("involvesWatchonly", true));
            obj.push_back(Pair("address", address.ToString()));
            obj.push_back(Pair("account", strAccount));
            obj.push_back(Pair("amount", ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            obj.push_back(Pair("bcconfirmations", (nBCConf == std::numeric_limits<int>::max() ? 0 : nBCConf)));
            UniValue transactions(UniValue::VARR);
            if (it != mapTally.end()) {
                for (const uint256& item : (*it).second.txids) {
                    transactions.push_back(item.GetHex());
                }
            }
            obj.push_back(Pair("txids", transactions));
            ret.push_back(obj);
        }
    }

    if (fByAccounts) {
        for (std::map<std::string, tallyitem>::iterator it = mapAccountTally.begin(); it != mapAccountTally.end(); ++it) {
            CAmount nAmount = (*it).second.nAmount;
            int nConf = (*it).second.nConf;
            int nBCConf = (*it).second.nBCConf;
            UniValue obj(UniValue::VOBJ);
            if ((*it).second.fIsWatchonly)
                obj.push_back(Pair("involvesWatchonly", true));
            obj.push_back(Pair("account", (*it).first));
            obj.push_back(Pair("amount", ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            obj.push_back(Pair("bcconfirmations", (nBCConf == std::numeric_limits<int>::max() ? 0 : nBCConf)));
            ret.push_back(obj);
        }
    }

    return ret;
}

UniValue listreceivedbyaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() > 3)
        throw std::runtime_error(
            "listreceivedbyaddress ( minconf includeempty includeWatchonly)\n"
            "\nList balances by receiving address.\n"

            "\nArguments:\n"
            "1. minconf       (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. includeempty  (numeric, optional, default=false) Whether to include addresses that haven't received any payments.\n"
            "3. includeWatchonly (bool, optional, default=false) Whether to include watchonly addresses (see 'importaddress').\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : \"true\",    (bool) Only returned if imported addresses were involved in transaction\n"
            "    \"address\" : \"receivingaddress\",  (string) The receiving address\n"
            "    \"account\" : \"accountname\",       (string) DEPRECATED. The account of the receiving address. The default account is \"\".\n"
            "    \"amount\" : x.xxx,                  (numeric) The total amount in PIV received by the address\n"
            "    \"confirmations\" : n                (numeric) The number of confirmations of the most recent transaction included\n"
            "    \"bcconfirmations\" : n              (numeric) The number of blockchain confirmations of the most recent transaction included\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n" +
            HelpExampleCli("listreceivedbyaddress", "") + HelpExampleCli("listreceivedbyaddress", "6 true") + HelpExampleRpc("listreceivedbyaddress", "6, true, true"));

    LOCK2(cs_main, pwallet->cs_wallet);

    return ListReceived(pwallet, request.params, false);
}

UniValue listreceivedbyaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() > 3)
        throw std::runtime_error(
            "listreceivedbyaccount ( minconf includeempty includeWatchonly)\n"
            "\nDEPRECATED. List balances by account.\n"

            "\nArguments:\n"
            "1. minconf      (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. includeempty (boolean, optional, default=false) Whether to include accounts that haven't received any payments.\n"
            "3. includeWatchonly (bool, optional, default=false) Whether to include watchonly addresses (see 'importaddress').\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : \"true\",    (bool) Only returned if imported addresses were involved in transaction\n"
            "    \"account\" : \"accountname\",  (string) The account name of the receiving account\n"
            "    \"amount\" : x.xxx,             (numeric) The total amount received by addresses with this account\n"
            "    \"confirmations\" : n           (numeric) The number of confirmations of the most recent transaction included\n"
            "    \"bcconfirmations\" : n         (numeric) The number of blockchain confirmations of the most recent transaction included\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n" +
            HelpExampleCli("listreceivedbyaccount", "") + HelpExampleCli("listreceivedbyaccount", "6 true") + HelpExampleRpc("listreceivedbyaccount", "6, true, true"));

    LOCK2(cs_main, pwallet->cs_wallet);

    return ListReceived(pwallet, request.params, true);
}

UniValue listcoldutxos(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "listcoldutxos ( nonWhitelistedOnly )\n"
            "\nList P2CS unspent outputs received by this wallet as cold-staker-\n"

            "\nArguments:\n"
            "1. nonWhitelistedOnly   (boolean, optional, default=false) Whether to exclude P2CS from whitelisted delegators.\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"txid\" : \"true\",            (string) The transaction id of the P2CS utxo\n"
            "    \"txidn\" : \"accountname\",    (string) The output number of the P2CS utxo\n"
            "    \"amount\" : x.xxx,             (numeric) The amount of the P2CS utxo\n"
            "    \"confirmations\" : n           (numeric) The number of confirmations of the P2CS utxo\n"
            "    \"cold-staker\" : n             (string) The cold-staker address of the P2CS utxo\n"
            "    \"coin-owner\" : n              (string) The coin-owner address of the P2CS utxo\n"
            "    \"whitelisted\" : n             (string) \"true\"/\"false\" coin-owner in delegator whitelist\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n" +
            HelpExampleCli("listcoldutxos", "") + HelpExampleCli("listcoldutxos", "true"));

    LOCK2(cs_main, pwallet->cs_wallet);

    bool fExcludeWhitelisted = false;
    if (request.params.size() > 0)
        fExcludeWhitelisted = request.params[0].get_bool();
    UniValue results(UniValue::VARR);

    for (std::map<uint256, CWalletTx>::const_iterator it =
            pwallet->mapWallet.begin(); it != pwallet->mapWallet.end(); ++it) {
        const uint256& wtxid = it->first;
        const CWalletTx* pcoin = &(*it).second;
        if (!CheckFinalTx(*pcoin) || !pcoin->IsTrusted())
            continue;

        // if this tx has no unspent P2CS outputs for us, skip it
        if(pcoin->GetColdStakingCredit() == 0 && pcoin->GetStakeDelegationCredit() == 0)
            continue;

        for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
            const CTxOut& out = pcoin->vout[i];
            isminetype mine = pwallet->IsMine(out);
            if (!bool(mine & ISMINE_COLD) && !bool(mine & ISMINE_SPENDABLE_DELEGATED))
                continue;
            txnouttype type;
            std::vector<CTxDestination> addresses;
            int nRequired;
            if (!ExtractDestinations(out.scriptPubKey, type, addresses, nRequired))
                continue;
            const bool fWhitelisted = pwallet->mapAddressBook.count(addresses[1]) > 0;
            if (fExcludeWhitelisted && fWhitelisted)
                continue;
            UniValue entry(UniValue::VOBJ);
            entry.push_back(Pair("txid", wtxid.GetHex()));
            entry.push_back(Pair("txidn", (int)i));
            entry.push_back(Pair("amount", ValueFromAmount(out.nValue)));
            entry.push_back(Pair("confirmations", pcoin->GetDepthInMainChain(false)));
            entry.push_back(Pair("cold-staker", CBitcoinAddress(addresses[0], CChainParams::STAKING_ADDRESS).ToString()));
            entry.push_back(Pair("coin-owner", CBitcoinAddress(addresses[1]).ToString()));
            entry.push_back(Pair("whitelisted", fWhitelisted ? "true" : "false"));
            results.push_back(entry);
        }
    }

    return results;
}

static void MaybePushAddress(UniValue & entry, const CTxDestination &dest)
{
    CBitcoinAddress addr;
    if (addr.Set(dest))
        entry.push_back(Pair("address", addr.ToString()));
}

void ListTransactions(CWallet * const pwallet, const CWalletTx& wtx, const std::string& strAccount, int nMinDepth, bool fLong, UniValue& ret, const isminefilter& filter)
{
    CAmount nFee;
    std::string strSentAccount;
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;

    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, filter);

    bool fAllAccounts = (strAccount == std::string("*"));
    bool involvesWatchonly = wtx.IsFromMe(ISMINE_WATCH_ONLY);

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount)) {
        for (const COutputEntry& s : listSent) {
            UniValue entry(UniValue::VOBJ);
            if (involvesWatchonly || (::IsMine(*pwallet, s.destination) & ISMINE_WATCH_ONLY))
                entry.push_back(Pair("involvesWatchonly", true));
            entry.push_back(Pair("account", strSentAccount));
            MaybePushAddress(entry, s.destination);
            std::map<std::string, std::string>::const_iterator it = wtx.mapValue.find("DS");
            entry.push_back(Pair("category", (it != wtx.mapValue.end() && it->second == "1") ? "darksent" : "send"));
            entry.push_back(Pair("amount", ValueFromAmount(-s.amount)));
            entry.push_back(Pair("vout", s.vout));
            entry.push_back(Pair("fee", ValueFromAmount(-nFee)));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            ret.push_back(entry);
        }
    }

    // Received
    int depth = wtx.GetDepthInMainChain();
    if (listReceived.size() > 0 && depth >= nMinDepth) {
        for (const COutputEntry& r : listReceived) {
            std::string account;
            if (pwallet->mapAddressBook.count(r.destination))
                account = pwallet->mapAddressBook[r.destination].name;
            if (fAllAccounts || (account == strAccount)) {
                UniValue entry(UniValue::VOBJ);
                if (involvesWatchonly || (::IsMine(*pwallet, r.destination) & ISMINE_WATCH_ONLY))
                    entry.push_back(Pair("involvesWatchonly", true));
                entry.push_back(Pair("account", account));
                MaybePushAddress(entry, r.destination);
                if (wtx.IsCoinBase()) {
                    if (depth < 1)
                        entry.push_back(Pair("category", "orphan"));
                    else if (wtx.GetBlocksToMaturity() > 0)
                        entry.push_back(Pair("category", "immature"));
                    else
                        entry.push_back(Pair("category", "generate"));
                } else {
                    entry.push_back(Pair("category", "receive"));
                }
                entry.push_back(Pair("amount", ValueFromAmount(r.amount)));
                entry.push_back(Pair("vout", r.vout));
                if (fLong)
                    WalletTxToJSON(wtx, entry);
                ret.push_back(entry);
            }
        }
    }
}

void AcentryToJSON(const CAccountingEntry& acentry, const std::string& strAccount, UniValue& ret)
{
    bool fAllAccounts = (strAccount == std::string("*"));

    if (fAllAccounts || acentry.strAccount == strAccount) {
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("account", acentry.strAccount));
        entry.push_back(Pair("category", "move"));
        entry.push_back(Pair("time", acentry.nTime));
        entry.push_back(Pair("amount", ValueFromAmount(acentry.nCreditDebit)));
        entry.push_back(Pair("otheraccount", acentry.strOtherAccount));
        entry.push_back(Pair("comment", acentry.strComment));
        ret.push_back(entry);
    }
}

UniValue listtransactions(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() > 6)
        throw std::runtime_error(
            "listtransactions ( \"account\" count from includeWatchonly includeDelegated )\n"
            "\nReturns up to 'count' most recent transactions skipping the first 'from' transactions for account 'account'.\n"

            "\nArguments:\n"
            "1. \"account\"    (string, optional) DEPRECATED. The account name. Should be \"*\".\n"
            "2. count          (numeric, optional, default=10) The number of transactions to return\n"
            "3. from           (numeric, optional, default=0) The number of transactions to skip\n"
            "4. includeWatchonly (bool, optional, default=false) Include transactions to watchonly addresses (see 'importaddress')\n"
            "5. includeDelegated     (bool, optional, default=true) Also include balance delegated to cold stakers\n"
            "6. includeCold     (bool, optional, default=true) Also include delegated balance received as cold-staker by this node\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the transaction. \n"
            "                                                It will be \"\" for the default account.\n"
            "    \"address\":\"pivxaddress\",    (string) The pivx address of the transaction. Not present for \n"
            "                                                move transactions (category = move).\n"
            "    \"category\":\"send|receive|move\", (string) The transaction category. 'move' is a local (off blockchain)\n"
            "                                                transaction between accounts, and not associated with an address,\n"
            "                                                transaction id or block. 'send' and 'receive' transactions are \n"
            "                                                associated with an address, transaction id and block details\n"
            "    \"amount\": x.xxx,          (numeric) The amount in PIV. This is negative for the 'send' category, and for the\n"
            "                                         'move' category for moves outbound. It is positive for the 'receive' category,\n"
            "                                         and for the 'move' category for inbound funds.\n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in PIV. This is negative and only available for the \n"
            "                                         'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and \n"
            "                                         'receive' category of transactions.\n"
            "    \"bcconfirmations\": n,     (numeric) The number of blockchain confirmations for the transaction. Available for 'send'\n"
            "                                         'receive' category of transactions. Negative confirmations indicate the\n"
            "                                         transation conflicts with the block chain\n"
            "    \"trusted\": xxx            (bool) Whether we consider the outputs of this unconfirmed transaction safe to spend.\n"
            "                                          and 'receive' category of transactions.\n"
            "    \"blockhash\": \"hashvalue\", (string) The block hash containing the transaction. Available for 'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The block index containing the transaction. Available for 'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"txid\": \"transactionid\", (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (midnight Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (midnight Jan 1 1970 GMT). Available \n"
            "                                          for 'send' and 'receive' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"otheraccount\": \"accountname\",  (string) For the 'move' category of transactions, the account the funds came \n"
            "                                          from (for receiving funds, positive amounts), or went to (for sending funds,\n"
            "                                          negative amounts).\n"
            "  }\n"
            "]\n"

            "\nExamples:\n"
            "\nList the most recent 10 transactions in the systems\n" +
            HelpExampleCli("listtransactions", "") +
            "\nList transactions 100 to 120\n" +
            HelpExampleCli("listtransactions", "\"*\" 20 100") +
            "\nAs a json rpc call\n" +
            HelpExampleRpc("listtransactions", "\"*\", 20, 100"));

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount = "*";
    if (request.params.size() > 0)
        strAccount = request.params[0].get_str();
    int nCount = 10;
    if (request.params.size() > 1)
        nCount = request.params[1].get_int();
    int nFrom = 0;
    if (request.params.size() > 2)
        nFrom = request.params[2].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if ( request.params.size() > 3 && request.params[3].get_bool() )
            filter = filter | ISMINE_WATCH_ONLY;
    if ( !(request.params.size() > 4) || request.params[4].get_bool() )
        filter = filter | ISMINE_SPENDABLE_DELEGATED;
    if ( !(request.params.size() > 5) || request.params[5].get_bool() )
        filter = filter | ISMINE_COLD;

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    UniValue ret(UniValue::VARR);

    const CWallet::TxItems & txOrdered = pwallet->wtxOrdered;

    // iterate backwards until we have nCount items to return:
    for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it) {
        CWalletTx* const pwtx = (*it).second.first;
        if (pwtx != 0)
            ListTransactions(pwallet, *pwtx, strAccount, 0, true, ret, filter);
        CAccountingEntry* const pacentry = (*it).second.second;
        if (pacentry != 0)
            AcentryToJSON(*pacentry, strAccount, ret);

        if ((int)ret.size() >= (nCount + nFrom)) break;
    }
    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;

    std::vector<UniValue> arrTmp = ret.getValues();

    std::vector<UniValue>::iterator first = arrTmp.begin();
    std::advance(first, nFrom);
    std::vector<UniValue>::iterator last = arrTmp.begin();
    std::advance(last, nFrom+nCount);

    if (last != arrTmp.end()) arrTmp.erase(last, arrTmp.end());
    if (first != arrTmp.begin()) arrTmp.erase(arrTmp.begin(), first);

    std::reverse(arrTmp.begin(), arrTmp.end()); // Return oldest to newest

    ret.clear();
    ret.setArray();
    ret.push_backV(arrTmp);

    return ret;
}

UniValue listaccounts(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
            "listaccounts ( minconf includeWatchonly)\n"
            "\nDEPRECATED. Returns Object that has account names as keys, account balances as values.\n"

            "\nArguments:\n"
            "1. minconf          (numeric, optional, default=1) Only include transactions with at least this many confirmations\n"
            "2. includeWatchonly (bool, optional, default=false) Include balances in watchonly addresses (see 'importaddress')\n"

            "\nResult:\n"
            "{                      (json object where keys are account names, and values are numeric balances\n"
            "  \"account\": x.xxx,  (numeric) The property name is the account name, and the value is the total balance for the account.\n"
            "  ...\n"
            "}\n"

            "\nExamples:\n"
            "\nList account balances where there at least 1 confirmation\n" +
            HelpExampleCli("listaccounts", "") +
            "\nList account balances including zero confirmation transactions\n" +
            HelpExampleCli("listaccounts", "0") +
            "\nList account balances for 6 or more confirmations\n" +
            HelpExampleCli("listaccounts", "6") +
            "\nAs json rpc call\n" +
            HelpExampleRpc("listaccounts", "6"));

    LOCK2(cs_main, pwallet->cs_wallet);

    int nMinDepth = 1;
    if (request.params.size() > 0)
        nMinDepth = request.params[0].get_int();
    isminefilter includeWatchonly = ISMINE_SPENDABLE;
    if (request.params.size() > 1)
        if (request.params[1].get_bool())
            includeWatchonly = includeWatchonly | ISMINE_WATCH_ONLY;

    std::map<std::string, CAmount> mapAccountBalances;
    for (const PAIRTYPE(CTxDestination, AddressBook::CAddressBookData) & entry : pwallet->mapAddressBook) {
        if (IsMine(*pwallet, entry.first) & includeWatchonly) // This address belongs to me
            mapAccountBalances[entry.second.name] = 0;
    }

    for (std::map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.begin(); it != pwallet->mapWallet.end(); ++it) {
        const CWalletTx& wtx = (*it).second;
        CAmount nFee;
        std::string strSentAccount;
        std::list<COutputEntry> listReceived;
        std::list<COutputEntry> listSent;
        bool fConflicted;
        int nDepth = wtx.GetDepthAndMempool(fConflicted);
        if (wtx.GetBlocksToMaturity() > 0 || nDepth < 0 || fConflicted)
            continue;
        wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, includeWatchonly);
        mapAccountBalances[strSentAccount] -= nFee;
        for (const COutputEntry& s : listSent)
            mapAccountBalances[strSentAccount] -= s.amount;
        if (nDepth >= nMinDepth) {
            for (const COutputEntry& r : listReceived)
                if (pwallet->mapAddressBook.count(r.destination))
                    mapAccountBalances[pwallet->mapAddressBook[r.destination].name] += r.amount;
                else
                    mapAccountBalances[""] += r.amount;
        }
    }

    const std::list<CAccountingEntry> & acentries = pwallet->laccentries;
    for (const CAccountingEntry& entry : acentries)
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit;

    UniValue ret(UniValue::VOBJ);
    for (const PAIRTYPE(std::string, CAmount) & accountBalance : mapAccountBalances) {
        ret.push_back(Pair(accountBalance.first, ValueFromAmount(accountBalance.second)));
    }
    return ret;
}

UniValue listsinceblock(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp)
        throw std::runtime_error(
            "listsinceblock ( \"blockhash\" target-confirmations includeWatchonly)\n"
            "\nGet all transactions in blocks since block [blockhash], or all transactions if omitted\n"

            "\nArguments:\n"
            "1. \"blockhash\"   (string, optional) The block hash to list transactions since\n"
            "2. target-confirmations:    (numeric, optional) The confirmations required, must be 1 or more\n"
            "3. includeWatchonly:        (bool, optional, default=false) Include transactions to watchonly addresses (see 'importaddress')"

            "\nResult:\n"
            "{\n"
            "  \"transactions\": [\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the transaction. Will be \"\" for the default account.\n"
            "    \"address\":\"pivxaddress\",    (string) The pivx address of the transaction. Not present for move transactions (category = move).\n"
            "    \"category\":\"send|receive\",     (string) The transaction category. 'send' has negative amounts, 'receive' has positive amounts.\n"
            "    \"amount\": x.xxx,          (numeric) The amount in PIV. This is negative for the 'send' category, and for the 'move' category for moves \n"
            "                                          outbound. It is positive for the 'receive' category, and for the 'move' category for inbound funds.\n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in PIV. This is negative and only available for the 'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"bcconfirmations\" : n,    (numeric) The number of blockchain confirmations for the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blockhash\": \"hashvalue\",     (string) The block hash containing the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The block index containing the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\",  (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (Jan 1 1970 GMT). Available for 'send' and 'receive' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"to\": \"...\",            (string) If a comment to is associated with the transaction.\n"
            "  ],\n"
            "  \"lastblock\": \"lastblockhash\"     (string) The hash of the last block\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("listsinceblock", "") +
            HelpExampleCli("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\" 6") +
            HelpExampleRpc("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\", 6"));

    LOCK2(cs_main, pwallet->cs_wallet);

    CBlockIndex* pindex = NULL;
    int target_confirms = 1;
    isminefilter filter = ISMINE_SPENDABLE_ALL | ISMINE_COLD;

    if (request.params.size() > 0) {
        uint256 blockId;

        blockId.SetHex(request.params[0].get_str());
        BlockMap::iterator it = mapBlockIndex.find(blockId);
        if (it != mapBlockIndex.end())
            pindex = it->second;
    }

    if (request.params.size() > 1) {
        target_confirms = request.params[1].get_int();

        if (target_confirms < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
    }

    if (request.params.size() > 2)
        if (request.params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    int depth = pindex ? (1 + chainActive.Height() - pindex->nHeight) : -1;

    UniValue transactions(UniValue::VARR);

    for (std::map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.begin(); it != pwallet->mapWallet.end(); it++) {
        CWalletTx tx = (*it).second;

        if (depth == -1 || tx.GetDepthInMainChain(false) < depth)
            ListTransactions(pwallet, tx, "*", 0, true, transactions, filter);
    }

    CBlockIndex* pblockLast = chainActive[chainActive.Height() + 1 - target_confirms];
    uint256 lastblock = pblockLast ? pblockLast->GetBlockHash() : UINT256_ZERO;

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("transactions", transactions));
    ret.push_back(Pair("lastblock", lastblock.GetHex()));

    return ret;
}

UniValue gettransaction(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "gettransaction \"txid\" ( includeWatchonly )\n"
            "\nGet detailed information about in-wallet transaction <txid>\n"

            "\nArguments:\n"
            "1. \"txid\"    (string, required) The transaction id\n"
            "2. \"includeWatchonly\"    (bool, optional, default=false) Whether to include watchonly addresses in balance calculation and details[]\n"

            "\nResult:\n"
            "{\n"
            "  \"amount\" : x.xxx,        (numeric) The transaction amount in PIV\n"
            "  \"confirmations\" : n,     (numeric) The number of confirmations\n"
            "  \"bcconfirmations\" : n,   (numeric) The number of blockchain confirmations\n"
            "  \"blockhash\" : \"hash\",  (string) The block hash\n"
            "  \"blockindex\" : xx,       (numeric) The block index\n"
            "  \"blocktime\" : ttt,       (numeric) The time in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"txid\" : \"transactionid\",   (string) The transaction id.\n"
            "  \"time\" : ttt,            (numeric) The transaction time in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"timereceived\" : ttt,    (numeric) The time received in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"details\" : [\n"
            "    {\n"
            "      \"account\" : \"accountname\",  (string) DEPRECATED. The account name involved in the transaction, can be \"\" for the default account.\n"
            "      \"address\" : \"pivxaddress\",   (string) The pivx address involved in the transaction\n"
            "      \"category\" : \"send|receive\",    (string) The category, either 'send' or 'receive'\n"
            "      \"amount\" : x.xxx                  (numeric) The amount in PIV\n"
            "      \"vout\" : n,                       (numeric) the vout value\n"
            "    }\n"
            "    ,...\n"
            "  ],\n"
            "  \"hex\" : \"data\"         (string) Raw data for transaction\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"") +
            HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\" true") +
            HelpExampleRpc("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    uint256 hash;
    hash.SetHex(request.params[0].get_str());

    isminefilter filter = ISMINE_SPENDABLE_ALL | ISMINE_COLD;
    if (request.params.size() > 1)
        if (request.params[1].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    UniValue entry(UniValue::VOBJ);
    if (!pwallet->mapWallet.count(hash))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    const CWalletTx& wtx = pwallet->mapWallet[hash];

    CAmount nCredit = wtx.GetCredit(filter);
    CAmount nDebit = wtx.GetDebit(filter);
    CAmount nNet = nCredit - nDebit;
    CAmount nFee = (wtx.IsFromMe(filter) ? wtx.GetValueOut() - nDebit : 0);

    entry.push_back(Pair("amount", ValueFromAmount(nNet - nFee)));
    if (wtx.IsFromMe(filter))
        entry.push_back(Pair("fee", ValueFromAmount(nFee)));

    WalletTxToJSON(wtx, entry);

    UniValue details(UniValue::VARR);
    ListTransactions(pwallet, wtx, "*", 0, false, details, filter);
    entry.push_back(Pair("details", details));

    std::string strHex = EncodeHexTx(static_cast<CTransaction>(wtx));
    entry.push_back(Pair("hex", strHex));

    return entry;
}

UniValue abandontransaction(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "abandontransaction \"txid\"\n"
            "\nMark in-wallet transaction <txid> as abandoned\n"
            "This will mark this transaction and all its in-wallet descendants as abandoned which will allow\n"
            "for their inputs to be respent.  It can be used to replace \"stuck\" or evicted transactions.\n"
            "It only works on transactions which are not included in a block and are not currently in the mempool.\n"
            "It has no effect on transactions which are already conflicted or abandoned.\n"
            "\nArguments:\n"
            "1. \"txid\"    (string, required) The transaction id\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleRpc("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
        );

    EnsureWalletIsUnlocked(pwallet, false);

    LOCK2(cs_main, pwallet->cs_wallet);

    uint256 hash;
    hash.SetHex(request.params[0].get_str());

    if (!pwallet->mapWallet.count(hash))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    if (!pwallet->AbandonTransaction(hash))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not eligible for abandonment");

    return NullUniValue;
}


UniValue backupwallet(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "backupwallet \"destination\"\n"
            "\nSafely copies wallet.dat to destination, which can be a directory or a path with filename.\n"

            "\nArguments:\n"
            "1. \"destination\"   (string) The destination directory or file\n"

            "\nExamples:\n" +
            HelpExampleCli("backupwallet", "\"backup.dat\"") + HelpExampleRpc("backupwallet", "\"backup.dat\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strDest = request.params[0].get_str();
    if (!pwallet->BackupWallet(strDest))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");

    return NullUniValue;
}


UniValue keypoolrefill(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "keypoolrefill ( newsize )\n"
            "\nFills the keypool." +
            HelpRequiringPassphrase(pwallet) + "\n"

            "\nArguments\n"
            "1. newsize     (numeric, optional, default=100) The new keypool size\n"

            "\nExamples:\n" +
            HelpExampleCli("keypoolrefill", "") + HelpExampleRpc("keypoolrefill", ""));

    LOCK2(cs_main, pwallet->cs_wallet);

    // 0 is interpreted by TopUpKeyPool() as the default keypool size given by -keypool
    unsigned int kpSize = 0;
    if (request.params.size() > 0) {
        if (request.params[0].get_int() < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size.");
        kpSize = (unsigned int)request.params[0].get_int();
    }

    EnsureWalletIsUnlocked(pwallet, false);
    pwallet->TopUpKeyPool(kpSize);

    if (pwallet->GetKeyPoolSize() < (pwallet->IsHDEnabled() ? kpSize * 2 : kpSize))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");

    return NullUniValue;
}


static void LockWallet(CWallet* pWallet)
{
    LOCK(pWallet->cs_wallet);
    pWallet->nRelockTime = 0;
    pWallet->fWalletUnlockStaking = false;
    pWallet->Lock();
}

UniValue walletpassphrase(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (pwallet->IsCrypted() && (request.fHelp || request.params.size() < 2 || request.params.size() > 3))
        throw std::runtime_error(
            "walletpassphrase \"passphrase\" timeout ( stakingonly )\n"
            "\nStores the wallet decryption key in memory for 'timeout' seconds.\n"
            "This is needed prior to performing transactions related to private keys such as sending PIVs\n"

            "\nArguments:\n"
            "1. \"passphrase\"     (string, required) The wallet passphrase\n"
            "2. timeout            (numeric, required) The time to keep the decryption key in seconds.\n"
            "3. stakingonly      (boolean, optional, default=false) If is true sending functions are disabled."

            "\nNote:\n"
            "Issuing the walletpassphrase command while the wallet is already unlocked will set a new unlock\n"
            "time that overrides the old one. A timeout of \"0\" unlocks until the wallet is closed.\n"

            "\nExamples:\n"
            "\nUnlock the wallet for 60 seconds\n" +
            HelpExampleCli("walletpassphrase", "\"my pass phrase\" 60") +
            "\nUnlock the wallet for 60 seconds but allow staking only\n" +
            HelpExampleCli("walletpassphrase", "\"my pass phrase\" 60 true") +
            "\nLock the wallet again (before 60 seconds)\n" +
            HelpExampleCli("walletlock", "") +
            "\nAs json rpc call\n" +
            HelpExampleRpc("walletpassphrase", "\"my pass phrase\", 60"));

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (!pwallet->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrase was called.");

    // Note that the walletpassphrase is stored in request.params[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    strWalletPass = request.params[0].get_str().c_str();

    bool stakingOnly = false;
    if (request.params.size() == 3)
        stakingOnly = request.params[2].get_bool();

    if (!pwallet->IsLocked() && pwallet->fWalletUnlockStaking && stakingOnly)
        throw JSONRPCError(RPC_WALLET_ALREADY_UNLOCKED, "Error: Wallet is already unlocked.");

    // Get the timeout
    int64_t nSleepTime = request.params[1].get_int64();
    // Timeout cannot be negative, otherwise it will relock immediately
    if (nSleepTime < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Timeout cannot be negative.");
    }
    // Clamp timeout
    constexpr int64_t MAX_SLEEP_TIME = 100000000; // larger values trigger a macos/libevent bug?
    if (nSleepTime > MAX_SLEEP_TIME) {
        nSleepTime = MAX_SLEEP_TIME;
    }

    if (!pwallet->Unlock(strWalletPass, stakingOnly))
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

    pwallet->TopUpKeyPool();

    if (nSleepTime > 0) {
        pwallet->nRelockTime = GetTime() + nSleepTime;
        RPCRunLater(strprintf("lockwallet(%s)", pwallet->GetName()), boost::bind(LockWallet, pwallet), nSleepTime);
    }

    return NullUniValue;
}


UniValue walletpassphrasechange(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (pwallet->IsCrypted() && (request.fHelp || request.params.size() != 2))
        throw std::runtime_error(
            "walletpassphrasechange \"oldpassphrase\" \"newpassphrase\"\n"
            "\nChanges the wallet passphrase from 'oldpassphrase' to 'newpassphrase'.\n"

            "\nArguments:\n"
            "1. \"oldpassphrase\"      (string) The current passphrase\n"
            "2. \"newpassphrase\"      (string) The new passphrase\n"

            "\nExamples:\n" +
            HelpExampleCli("walletpassphrasechange", "\"old one\" \"new one\"") + HelpExampleRpc("walletpassphrasechange", "\"old one\", \"new one\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (!pwallet->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");

    // TODO: get rid of these .c_str() calls by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = request.params[0].get_str().c_str();

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = request.params[1].get_str().c_str();

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
        throw std::runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!pwallet->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass))
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

    return NullUniValue;
}


UniValue walletlock(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (pwallet->IsCrypted() && (request.fHelp || request.params.size() != 0))
        throw std::runtime_error(
            "walletlock\n"
            "\nRemoves the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletpassphrase again\n"
            "before being able to call any methods which require the wallet to be unlocked.\n"

            "\nExamples:\n"
            "\nSet the passphrase for 2 minutes to perform a transaction\n" +
            HelpExampleCli("walletpassphrase", "\"my pass phrase\" 120") +
            "\nPerform a send (requires passphrase set)\n" +
            HelpExampleCli("sendtoaddress", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\" 1.0") +
            "\nClear the passphrase since we are done before 2 minutes is up\n" +
            HelpExampleCli("walletlock", "") +
            "\nAs json rpc call\n" +
            HelpExampleRpc("walletlock", ""));

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (!pwallet->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletlock was called.");


    pwallet->Lock();
    pwallet->nRelockTime = 0;

    return NullUniValue;
}


UniValue encryptwallet(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (!pwallet->IsCrypted() && (request.fHelp || request.params.size() != 1))
        throw std::runtime_error(
            "encryptwallet \"passphrase\"\n"
            "\nEncrypts the wallet with 'passphrase'. This is for first time encryption.\n"
            "After this, any calls that interact with private keys such as sending or signing \n"
            "will require the passphrase to be set prior the making these calls.\n"
            "Use the walletpassphrase call for this, and then walletlock call.\n"
            "If the wallet is already encrypted, use the walletpassphrasechange call.\n"
            "Note that this will shutdown the server.\n"

            "\nArguments:\n"
            "1. \"passphrase\"    (string) The pass phrase to encrypt the wallet with. It must be at least 1 character, but should be long.\n"

            "\nExamples:\n"
            "\nEncrypt you wallet\n" +
            HelpExampleCli("encryptwallet", "\"my pass phrase\"") +
            "\nNow set the passphrase to use the wallet, such as for signing or sending PIVs\n" +
            HelpExampleCli("walletpassphrase", "\"my pass phrase\"") +
            "\nNow we can so something like sign\n" +
            HelpExampleCli("signmessage", "\"pivxaddress\" \"test message\"") +
            "\nNow lock the wallet again by removing the passphrase\n" +
            HelpExampleCli("walletlock", "") +
            "\nAs a json rpc call\n" +
            HelpExampleRpc("encryptwallet", "\"my pass phrase\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (pwallet->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");

    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = request.params[0].get_str().c_str();

    if (strWalletPass.length() < 1)
        throw std::runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");

    if (!pwallet->EncryptWallet(strWalletPass))
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");

    // BDB seems to have a bad habit of writing old data into
    // slack space in .dat files; that is bad if the old data is
    // unencrypted private keys. So:
    StartShutdown();
    return "wallet encrypted; pivx server stopping, restart to run with encrypted wallet. The keypool has been flushed and a new HD seed was generated (if you are using HD). You need to make a new backup.";
}

UniValue lockunspent(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "lockunspent unlock [{\"txid\":\"txid\",\"vout\":n},...]\n"
            "\nUpdates list of temporarily unspendable outputs.\n"
            "Temporarily lock (unlock=false) or unlock (unlock=true) specified transaction outputs.\n"
            "A locked transaction output will not be chosen by automatic coin selection, when spending PIVs.\n"
            "Locks are stored in memory only. Nodes start with zero locked outputs, and the locked output list\n"
            "is always cleared (by virtue of process exit) when a node stops or fails.\n"
            "Also see the listunspent call\n"

            "\nArguments:\n"
            "1. unlock            (boolean, required) Whether to unlock (true) or lock (false) the specified transactions\n"
            "2. \"transactions\"  (string, required) A json array of objects. Each object the txid (string) vout (numeric)\n"
            "     [           (json array of json objects)\n"
            "       {\n"
            "         \"txid\":\"id\",    (string) The transaction id\n"
            "         \"vout\": n         (numeric) The output number\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"

            "\nResult:\n"
            "true|false    (boolean) Whether the command was successful or not\n"

            "\nExamples:\n"
            "\nList the unspent transactions\n" +
            HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n" +
            HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n" +
            HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n" +
            HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nAs a json rpc call\n" +
            HelpExampleRpc("lockunspent", "false, \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\""));

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.params.size() == 1)
        RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VBOOL));
    else
        RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VBOOL)(UniValue::VARR));

    bool fUnlock = request.params[0].get_bool();

    if (request.params.size() == 1) {
        if (fUnlock)
            pwallet->UnlockAllCoins();
        return true;
    }

    UniValue output_params = request.params[1].get_array();

    // Create and validate the COutPoints first.
    std::vector<COutPoint> outputs;
    outputs.reserve(output_params.size());

    for (unsigned int idx = 0; idx < output_params.size(); idx++) {
        const UniValue& output = output_params[idx];
        if (!output.isObject())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected object");
        const UniValue& o = output.get_obj();

        RPCTypeCheckObj(o, boost::assign::map_list_of("txid", UniValue::VSTR)("vout", UniValue::VNUM));

        const std::string& txid = find_value(o, "txid").get_str();
        if (!IsHex(txid)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected hex txid");
        }

        const int nOutput = find_value(o, "vout").get_int();
        if (nOutput < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");
        }

        const COutPoint outpt(uint256S(txid), nOutput);

        const auto it = pwallet->mapWallet.find(outpt.hash);
        if (it == pwallet->mapWallet.end()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, unknown transaction");
        }

        const CWalletTx& wtx = it->second;

        if (outpt.n >= wtx.vout.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout index out of bounds");
        }

        if (pwallet->IsSpent(outpt.hash, outpt.n)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected unspent output");
        }

        const bool is_locked = pwallet->IsLockedCoin(outpt.hash, outpt.n);

        if (fUnlock && !is_locked) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected locked output");
        }

        if (!fUnlock && is_locked) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, output already locked");
        }

        outputs.push_back(outpt);
    }

    // Atomically set (un)locked status for the outputs.
    for (const COutPoint& outpt : outputs) {
        if (fUnlock) pwallet->UnlockCoin(outpt);
        else pwallet->LockCoin(outpt);
    }

    return true;
}

UniValue listlockunspent(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() > 0)
        throw std::runtime_error(
            "listlockunspent\n"
            "\nReturns list of temporarily unspendable outputs.\n"
            "See the lockunspent call to lock and unlock transactions for spending.\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"txid\" : \"transactionid\",     (string) The transaction id locked\n"
            "    \"vout\" : n                      (numeric) The vout value\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n"
            "\nList the unspent transactions\n" +
            HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n" +
            HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n" +
            HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n" +
            HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nAs a json rpc call\n" +
            HelpExampleRpc("listlockunspent", ""));

    LOCK2(cs_main, pwallet->cs_wallet);

    std::vector<COutPoint> vOutpts;
    pwallet->ListLockedCoins(vOutpts);

    UniValue ret(UniValue::VARR);

    for (COutPoint& outpt : vOutpts) {
        UniValue o(UniValue::VOBJ);

        o.push_back(Pair("txid", outpt.hash.GetHex()));
        o.push_back(Pair("vout", (int)outpt.n));
        ret.push_back(o);
    }

    return ret;
}

UniValue settxfee(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 1)
        throw std::runtime_error(
            "settxfee amount\n"
            "\nSet the transaction fee per kB.\n"

            "\nArguments:\n"
            "1. amount         (numeric, required) The transaction fee in PIV/kB rounded to the nearest 0.00000001\n"

            "\nResult\n"
            "true|false        (boolean) Returns true if successful\n"
            "\nExamples:\n" +
            HelpExampleCli("settxfee", "0.00001") + HelpExampleRpc("settxfee", "0.00001"));

    LOCK2(cs_main, pwallet->cs_wallet);

    // Amount
    CAmount nAmount = 0;
    if (request.params[0].get_real() != 0.0)
        nAmount = AmountFromValue(request.params[0]); // rejects 0.0 amounts

    payTxFee = CFeeRate(nAmount, 1000);
    return true;
}

UniValue getwalletinfo(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getwalletinfo\n"
            "Returns an object containing various wallet state info.\n"

            "\nResult:\n"
            "{\n"
            "  \"walletversion\": xxxxx,                  (numeric) the wallet version\n"
            "  \"balance\": xxxxxxx,                      (numeric) the total PIV balance of the wallet (cold balance excluded)\n"
            "  \"delegated_balance\": xxxxx,              (numeric) the PIV balance held in P2CS (cold staking) contracts\n"
            "  \"cold_staking_balance\": xx,              (numeric) the PIV balance held in cold staking addresses\n"
            "  \"unconfirmed_balance\": xxx,              (numeric) the total unconfirmed balance of the wallet in PIV\n"
            "  \"immature_delegated_balance\": xxxxxx,    (numeric) the delegated immature balance of the wallet in PIV\n"
            "  \"immature_cold_staking_balance\": xxxxxx, (numeric) the cold-staking immature balance of the wallet in PIV\n"
            "  \"immature_balance\": xxxxxx,              (numeric) the total immature balance of the wallet in PIV\n"
            "  \"txcount\": xxxxxxx,                      (numeric) the total number of transactions in the wallet\n"
            "  \"keypoololdest\": xxxxxx,                 (numeric) the timestamp (seconds since GMT epoch) of the oldest pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,        (numeric) how many new keys are pre-generated (only counts external keys)\n"
            "  \"keypoolsize_hd_internal\": xxxx, (numeric) how many new keys are pre-generated for internal use (used for change outputs, only appears if the wallet is using this feature, otherwise external keys are used)\n"
            "  \"unlocked_until\": ttt,                   (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"hdchainid\": \"<hash>\",      (string) the ID of the HD chain\n"
            "  \"hdaccountcount\": xxx,      (numeric) how many accounts of the HD chain are in this wallet\n"
            "    [\n"
            "      {\n"
            "      \"hdaccountindex\": xxx,         (numeric) the index of the account\n"
            "      \"hdexternalkeyindex\": xxxx,    (numeric) current external childkey index\n"
            "      \"hdinternalkeyindex\": xxxx,    (numeric) current internal childkey index\n"
            "      }\n"
            "      ,...\n"
            "    ]\n"
            "  \"paytxfee\": x.xxxx                       (numeric) the transaction fee configuration, set in PIV/kB\n"
            "  \"hdseedid\": \"<hash160>\"            (string, optional) the Hash160 of the HD seed (only present when HD is enabled)\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("getwalletinfo", "") + HelpExampleRpc("getwalletinfo", ""));

    LOCK2(cs_main, pwallet->cs_wallet);

    CHDChain hdChainCurrent;
    bool fHDEnabled = pwallet->GetHDChain(hdChainCurrent);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("walletversion", pwallet->GetVersion()));
    obj.push_back(Pair("balance", ValueFromAmount(pwallet->GetBalance())));
    obj.push_back(Pair("delegated_balance", ValueFromAmount(pwallet->GetDelegatedBalance())));
    obj.push_back(Pair("cold_staking_balance", ValueFromAmount(pwallet->GetColdStakingBalance())));
    obj.push_back(Pair("unconfirmed_balance", ValueFromAmount(pwallet->GetUnconfirmedBalance())));
    obj.push_back(Pair("immature_balance",    ValueFromAmount(pwallet->GetImmatureBalance())));
    obj.push_back(Pair("immature_delegated_balance",    ValueFromAmount(pwallet->GetImmatureDelegatedBalance())));
    obj.push_back(Pair("immature_cold_staking_balance",    ValueFromAmount(pwallet->GetImmatureColdStakingBalance())));
    obj.push_back(Pair("txcount", (int)pwallet->mapWallet.size()));
    obj.push_back(Pair("keypoololdest", pwallet->GetOldestKeyPoolTime()));
    obj.push_back(Pair("keypoolsize",   (int64_t)pwallet->KeypoolCountExternalKeys()));
    if (fHDEnabled) {
        obj.push_back(Pair("keypoolsize_hd_internal",   (int64_t)(pwallet->KeypoolCountInternalKeys())));
    }
    if (pwallet->IsCrypted())
        obj.push_back(Pair("unlocked_until", pwallet->nRelockTime));
    if (fHDEnabled) {
        obj.push_back(Pair("hdchainid", hdChainCurrent.GetID().GetHex()));
        obj.push_back(Pair("hdaccountcount", (int64_t)hdChainCurrent.CountAccounts()));
        UniValue accounts(UniValue::VARR);
        for (size_t i = 0; i < hdChainCurrent.CountAccounts(); ++i)
        {
            CHDAccount acc;
            UniValue account(UniValue::VOBJ);
            account.push_back(Pair("hdaccountindex", (int64_t)i));
            if(hdChainCurrent.GetAccount(i, acc)) {
                account.push_back(Pair("hdexternalkeyindex", (int64_t)acc.nExternalChainCounter));
                account.push_back(Pair("hdinternalkeyindex", (int64_t)acc.nInternalChainCounter));
            } else {
                account.push_back(Pair("error", strprintf("account %d is missing", i)));
            }
            accounts.push_back(account);
        }
        obj.push_back(Pair("hdaccounts", accounts));
    }
    obj.push_back(Pair("paytxfee",      ValueFromAmount(payTxFee.GetFeePerK())));
    return obj;
}

UniValue setstakesplitthreshold(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "setstakesplitthreshold value\n\n"
            "This will set the stake-split threshold value.\n"
            "Whenever a successful stake is found, the stake amount is split across as many outputs (each with a value\n"
            "higher than the threshold) as possible.\n"
            "E.g. If the coinstake input + the block reward is 2000, and the split threshold is 499, the corresponding\n"
            "coinstake transaction will have 4 outputs (of 500 PIV each)."
            + HelpRequiringPassphrase(pwallet) + "\n"

            "\nArguments:\n"
            "1. value                   (numeric, required) Threshold value (in PIV).\n"
            "                                               Set to 0 to disable stake-splitting\n"

            "\nResult:\n"
            "{\n"
            "  \"threshold\": n,        (numeric) Threshold value set\n"
            "  \"saved\": true|false    (boolean) 'true' if successfully saved to the wallet file\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("setstakesplitthreshold", "500.12") + HelpExampleRpc("setstakesplitthreshold", "500.12"));

    EnsureWalletIsUnlocked(pwallet, false);

    CAmount nStakeSplitThreshold = AmountFromValue(request.params[0]);

    CWalletDB walletdb(pwallet->GetDBHandle());
    LOCK(pwallet->cs_wallet);
    {
        UniValue result(UniValue::VOBJ);
        pwallet->nStakeSplitThreshold = nStakeSplitThreshold;
        result.push_back(Pair("threshold", ValueFromAmount(pwallet->nStakeSplitThreshold)));

        walletdb.WriteStakeSplitThreshold(nStakeSplitThreshold);
        result.push_back(Pair("saved", "true"));

        return result;
    }
}

UniValue getstakesplitthreshold(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getstakesplitthreshold\n"
            "Returns the threshold for stake splitting\n"

            "\nResult:\n"
            "n      (numeric) Threshold value\n"

            "\nExamples:\n" +
            HelpExampleCli("getstakesplitthreshold", "") + HelpExampleRpc("getstakesplitthreshold", ""));

    return ValueFromAmount(pwallet->nStakeSplitThreshold);
}

UniValue autocombinerewards(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    bool fEnable;
    if (request.params.size() >= 1)
        fEnable = request.params[0].get_bool();

    if (request.fHelp || request.params.size() < 1 || (fEnable && request.params.size() != 2) || request.params.size() > 2)
        throw std::runtime_error(
            "autocombinerewards enable ( threshold )\n"
            "\nWallet will automatically monitor for any coins with value below the threshold amount, and combine them if they reside with the same PIVX address\n"
            "When autocombinerewards runs it will create a transaction, and therefore will be subject to transaction fees.\n"

            "\nArguments:\n"
            "1. enable          (boolean, required) Enable auto combine (true) or disable (false)\n"
            "2. threshold       (numeric, optional) Threshold amount (default: 0)\n"

            "\nExamples:\n" +
            HelpExampleCli("autocombinerewards", "true 500") + HelpExampleRpc("autocombinerewards", "true 500"));

    CWalletDB walletdb(pwallet->GetDBHandle());
    CAmount nThreshold = 0;

    if (fEnable)
        nThreshold = request.params[1].get_int();

    pwallet->fCombineDust = fEnable;
    pwallet->nAutoCombineThreshold = nThreshold;

    if (!walletdb.WriteAutoCombineSettings(fEnable, nThreshold))
        throw std::runtime_error("Changed settings in wallet but failed to save to database\n");

    return NullUniValue;
}

UniValue printMultiSend(CWallet * const pwallet)
{
    UniValue ret(UniValue::VARR);
    UniValue act(UniValue::VOBJ);
    act.push_back(Pair("MultiSendStake Activated?", pwallet->fMultiSendStake));
    act.push_back(Pair("MultiSendMasternode Activated?", pwallet->fMultiSendMasternodeReward));
    ret.push_back(act);

    if (pwallet->vDisabledAddresses.size() >= 1) {
        UniValue disAdd(UniValue::VOBJ);
        for (unsigned int i = 0; i < pwallet->vDisabledAddresses.size(); i++) {
            disAdd.push_back(Pair("Disabled From Sending", pwallet->vDisabledAddresses[i]));
        }
        ret.push_back(disAdd);
    }

    ret.push_back("MultiSend Addresses to Send To:");

    UniValue vMS(UniValue::VOBJ);
    for (unsigned int i = 0; i < pwallet->vMultiSend.size(); i++) {
        vMS.push_back(Pair("Address " + std::to_string(i), pwallet->vMultiSend[i].first));
        vMS.push_back(Pair("Percent", pwallet->vMultiSend[i].second));
    }

    ret.push_back(vMS);
    return ret;
}

UniValue printAddresses(CWallet * const pwallet)
{
    std::vector<COutput> vCoins;
    pwallet->AvailableCoins(&vCoins);
    std::map<std::string, double> mapAddresses;
    for (const COutput& out : vCoins) {
        CTxDestination utxoAddress;
        ExtractDestination(out.tx->vout[out.i].scriptPubKey, utxoAddress);
        std::string strAdd = CBitcoinAddress(utxoAddress).ToString();

        if (mapAddresses.find(strAdd) == mapAddresses.end()) //if strAdd is not already part of the map
            mapAddresses[strAdd] = (double)out.tx->vout[out.i].nValue / (double)COIN;
        else
            mapAddresses[strAdd] += (double)out.tx->vout[out.i].nValue / (double)COIN;
    }

    UniValue ret(UniValue::VARR);
    for (std::map<std::string, double>::const_iterator it = mapAddresses.begin(); it != mapAddresses.end(); ++it) {
        UniValue obj(UniValue::VOBJ);
        const std::string* strAdd = &(*it).first;
        const double* nBalance = &(*it).second;
        obj.push_back(Pair("Address ", *strAdd));
        obj.push_back(Pair("Balance ", *nBalance));
        ret.push_back(obj);
    }

    return ret;
}

unsigned int sumMultiSend(CWallet * const pwallet)
{
    unsigned int sum = 0;
    for (unsigned int i = 0; i < pwallet->vMultiSend.size(); i++)
        sum += pwallet->vMultiSend[i].second;
    return sum;
}

UniValue multisend(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    CWalletDB walletdb(pwallet->GetDBHandle());
    //MultiSend Commands
    if (request.params.size() == 1) {
        std::string strCommand = request.params[0].get_str();
        UniValue ret(UniValue::VOBJ);
        if (strCommand == "print") {
            return printMultiSend(pwallet);
        } else if (strCommand == "printaddress" || strCommand == "printaddresses") {
            return printAddresses(pwallet);
        } else if (strCommand == "clear") {
            LOCK(pwallet->cs_wallet);
            {
                bool erased = false;
                if (walletdb.EraseMultiSend(pwallet->vMultiSend))
                    erased = true;

                pwallet->vMultiSend.clear();
                pwallet->setMultiSendDisabled();

                UniValue obj(UniValue::VOBJ);
                obj.push_back(Pair("Erased from database", erased));
                obj.push_back(Pair("Erased from RAM", true));

                return obj;
            }
        } else if (strCommand == "enablestake" || strCommand == "activatestake") {
            if (pwallet->vMultiSend.size() < 1)
                throw JSONRPCError(RPC_INVALID_REQUEST, "Unable to activate MultiSend, check MultiSend vector");

            if (CBitcoinAddress(pwallet->vMultiSend[0].first).IsValid()) {
                pwallet->fMultiSendStake = true;
                if (!walletdb.WriteMSettings(true, pwallet->fMultiSendMasternodeReward, pwallet->nLastMultiSendHeight)) {
                    UniValue obj(UniValue::VOBJ);
                    obj.push_back(Pair("error", "MultiSend activated but writing settings to DB failed"));
                    UniValue arr(UniValue::VARR);
                    arr.push_back(obj);
                    arr.push_back(printMultiSend(pwallet));
                    return arr;
                } else
                    return printMultiSend(pwallet);
            }

            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to activate MultiSend, check MultiSend vector");
        } else if (strCommand == "enablemasternode" || strCommand == "activatemasternode") {
            if (pwallet->vMultiSend.size() < 1)
                throw JSONRPCError(RPC_INVALID_REQUEST, "Unable to activate MultiSend, check MultiSend vector");

            if (CBitcoinAddress(pwallet->vMultiSend[0].first).IsValid()) {
                pwallet->fMultiSendMasternodeReward = true;

                if (!walletdb.WriteMSettings(pwallet->fMultiSendStake, true, pwallet->nLastMultiSendHeight)) {
                    UniValue obj(UniValue::VOBJ);
                    obj.push_back(Pair("error", "MultiSend activated but writing settings to DB failed"));
                    UniValue arr(UniValue::VARR);
                    arr.push_back(obj);
                    arr.push_back(printMultiSend(pwallet));
                    return arr;
                } else
                    return printMultiSend(pwallet);
            }

            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to activate MultiSend, check MultiSend vector");
        } else if (strCommand == "disable" || strCommand == "deactivate") {
            pwallet->setMultiSendDisabled();
            if (!walletdb.WriteMSettings(false, false, pwallet->nLastMultiSendHeight))
                throw JSONRPCError(RPC_DATABASE_ERROR, "MultiSend deactivated but writing settings to DB failed");

            return printMultiSend(pwallet);
        } else if (strCommand == "enableall") {
            if (!walletdb.EraseMSDisabledAddresses(pwallet->vDisabledAddresses))
                return "failed to clear old vector from walletDB";
            else {
                pwallet->vDisabledAddresses.clear();
                return printMultiSend(pwallet);
            }
        }
    }
    if (request.params.size() == 2 && request.params[0].get_str() == "delete") {
        int del = std::stoi(request.params[1].get_str().c_str());
        if (!walletdb.EraseMultiSend(pwallet->vMultiSend))
            throw JSONRPCError(RPC_DATABASE_ERROR, "failed to delete old MultiSend vector from database");

        pwallet->vMultiSend.erase(pwallet->vMultiSend.begin() + del);
        if (!walletdb.WriteMultiSend(pwallet->vMultiSend))
            throw JSONRPCError(RPC_DATABASE_ERROR, "walletdb WriteMultiSend failed!");

        return printMultiSend(pwallet);
    }
    if (request.params.size() == 2 && request.params[0].get_str() == "disable") {
        std::string disAddress = request.params[1].get_str();
        if (!CBitcoinAddress(disAddress).IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "address you want to disable is not valid");
        else {
            pwallet->vDisabledAddresses.push_back(disAddress);
            if (!walletdb.EraseMSDisabledAddresses(pwallet->vDisabledAddresses))
                throw JSONRPCError(RPC_DATABASE_ERROR, "disabled address from sending, but failed to clear old vector from walletDB");

            if (!walletdb.WriteMSDisabledAddresses(pwallet->vDisabledAddresses))
                throw JSONRPCError(RPC_DATABASE_ERROR, "disabled address from sending, but failed to store it to walletDB");
            else
                return printMultiSend(pwallet);
        }
    }

    //if no commands are used
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "multisend <command>\n"
            "****************************************************************\n"
            "WHAT IS MULTISEND?\n"
            "MultiSend allows a user to automatically send a percent of their stake reward to as many addresses as you would like\n"
            "The MultiSend transaction is sent when the staked coins mature (100 confirmations)\n"
            "****************************************************************\n"
            "TO CREATE OR ADD TO THE MULTISEND VECTOR:\n"
            "multisend <PIVX Address> <percent>\n"
            "This will add a new address to the MultiSend vector\n"
            "Percent is a whole number 1 to 100.\n"
            "****************************************************************\n"
            "MULTISEND COMMANDS (usage: multisend <command>)\n"
            " print - displays the current MultiSend vector \n"
            " clear - deletes the current MultiSend vector \n"
            " enablestake/activatestake - activates the current MultiSend vector to be activated on stake rewards\n"
            " enablemasternode/activatemasternode - activates the current MultiSend vector to be activated on masternode rewards\n"
            " disable/deactivate - disables the current MultiSend vector \n"
            " delete <Address #> - deletes an address from the MultiSend vector \n"
            " disable <address> - prevents a specific address from sending MultiSend transactions\n"
            " enableall - enables all addresses to be eligible to send MultiSend transactions\n"
            "****************************************************************\n");

    //if the user is entering a new MultiSend item
    std::string strAddress = request.params[0].get_str();
    CBitcoinAddress address(strAddress);
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid PIV address");
    if (std::stoi(request.params[1].get_str().c_str()) < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid percentage");
    if (pwallet->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    unsigned int nPercent = (unsigned int) std::stoul(request.params[1].get_str().c_str());

    LOCK(pwallet->cs_wallet);
    {
        //Error if 0 is entered
        if (nPercent == 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Sending 0% of stake is not valid");
        }

        //MultiSend can only send 100% of your stake
        if (nPercent + sumMultiSend(pwallet) > 100)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to add to MultiSend vector, the sum of your MultiSend is greater than 100%");

        for (unsigned int i = 0; i < pwallet->vMultiSend.size(); i++) {
            if (pwallet->vMultiSend[i].first == strAddress)
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to add to MultiSend vector, cannot use the same address twice");
        }

        walletdb.EraseMultiSend(pwallet->vMultiSend);

        std::pair<std::string, int> newMultiSend;
        newMultiSend.first = strAddress;
        newMultiSend.second = nPercent;
        pwallet->vMultiSend.push_back(newMultiSend);

        if (!walletdb.WriteMultiSend(pwallet->vMultiSend))
            throw JSONRPCError(RPC_DATABASE_ERROR, "walletdb WriteMultiSend failed!");
    }
    return printMultiSend(pwallet);
}


UniValue upgradetohd(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;


    if (request.fHelp || request.params.size() == 0) {
        throw std::runtime_error(
                "upgradetohd ( \"mnemonicwords\" \"password\" )\n"
                "\nNon-HD wallets will not be upgraded to being a HD wallet. Wallets that are already\n"
                "\nNote that you will need to MAKE A NEW BACKUP of your wallet after setting the HD wallet mnemonic.\n"
                "\nArguments:\n"
                "1. \"words\"               (string, optional) The WIF private key to use as the new HD seed; if not provided a random seed will be used.\n"
                "                             The mnemonic value can be retrieved using the dumpwallet command. It is the private key marked hdmaster=1\n"
                "2. \"password\"               (boolean, optional) If your wallet is encrypted you must have your password here\n"

                "\nExamples:\n"
                + HelpExampleCli("upgradetohd", "")
                + HelpExampleCli("upgradetohd", "\"mnemonicwords\"")
                + HelpExampleCli("upgradetohd", "\"mnemonicwords\" \"password\""));
    }

    if (IsInitialBlockDownload()) {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Cannot set a new HD seed while still in Initial Block Download");
    }

    if (request.params.size() == 1 && pwallet->IsLocked()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot upgrade a encrypted wallet to HD without the password");
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    // Do not do anything to HD wallets
    if (pwallet->IsHDEnabled()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot upgrade a wallet to HD if It is already upgraded to HD.");
    }

    EnsureWalletIsUnlocked(pwallet, false);

    std::string words = request.params[0].get_str();

    int prev_version = pwallet->GetVersion();

    int nMaxVersion = GetArg("-upgradewallet", 0);
    if (nMaxVersion == 0) // the -upgradewallet without argument case
    {
        LogPrintf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
        nMaxVersion = CLIENT_VERSION;
        pwallet->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
    } else
        LogPrintf("Allowing wallet upgrade up to %i\n", nMaxVersion);
    if (nMaxVersion < pwallet->GetVersion()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot downgrade wallet");
    }

    pwallet->SetMaxVersion(nMaxVersion);

    // Do not upgrade versions to any version between HD_SPLIT and FEATURE_PRE_SPLIT_KEYPOOL unless already supporting HD_SPLIT
    int max_version = pwallet->GetVersion();
    if (!pwallet->CanSupportFeature(FEATURE_HD) && max_version >=FEATURE_HD && max_version < FEATURE_PRE_SPLIT_KEYPOOL) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot upgrade a non HD split wallet without upgrading to support pre split keypool. Please use -upgradewallet=169900 or -upgradewallet with no version specified.");
    }

    bool hd_upgrade = false;
    bool split_upgrade = false;
    if (pwallet->CanSupportFeature(FEATURE_HD) && !pwallet->IsHDEnabled()) {
        LogPrintf("Upgrading wallet to HD\n");
        pwallet->SetMinVersion(FEATURE_HD);

        // generate a new master key
        SecureString strWalletPass;
        strWalletPass.reserve(100);

        // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
        // Alternately, find a way to make request.params[0] mlock()'d to begin with.
        if (request.params.size() < 2){
            strWalletPass = std::string().c_str();
        } else {
            strWalletPass = request.params[1].get_str().c_str();
        }

        pwallet->GenerateNewHDChain(words, strWalletPass);

        hd_upgrade = true;
    }

    // Upgrade to HD chain split if necessary
    if (pwallet->CanSupportFeature(FEATURE_HD)) {
        LogPrintf("Upgrading wallet to use HD chain split\n");
        pwallet->SetMinVersion(FEATURE_PRE_SPLIT_KEYPOOL);
        split_upgrade = FEATURE_HD > prev_version;
    }

    // Mark all keys currently in the keypool as pre-split
    if (split_upgrade) {
        pwallet->MarkPreSplitKeys();
    }
    // Regenerate the keypool if upgraded to HD
    if (hd_upgrade) {
        if (!pwallet->TopUpKeyPool()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Unable to generate keys\n");
        }
    }

    pwallet->ScanForWalletTransactions(chainActive.Genesis(), true);

    return NullUniValue;
}

UniValue getzerocoinbalance(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}

UniValue listmintedzerocoins(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}

UniValue listzerocoinamounts(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}

UniValue listspentzerocoins(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}

UniValue mintzerocoin(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}

UniValue spendzerocoin(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}


UniValue spendzerocoinmints(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}


extern UniValue DoZpivSpend(const CAmount nAmount, std::vector<CZerocoinMint>& vMintsSelected, std::string address_str)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}


UniValue resetmintzerocoin(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}

UniValue resetspentzerocoin(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}

UniValue getarchivedzerocoin(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}

UniValue exportzerocoins(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}

UniValue importzerocoins(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}

UniValue reconsiderzerocoins(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}

UniValue setzpivseed(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}

UniValue getzpivseed(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}

UniValue generatemintlist(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}

UniValue dzpivstate(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}

UniValue searchdzpiv(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}

UniValue spendrawzerocoin(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_WALLET_ERROR, "zZNZ is permanently disabled");
}


extern UniValue dumpprivkey(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue importprivkey(const JSONRPCRequest& request);
extern UniValue importaddress(const JSONRPCRequest& request);
extern UniValue dumphdinfo(const JSONRPCRequest& request);
extern UniValue dumpwallet(const JSONRPCRequest& request);
extern UniValue importwallet(const JSONRPCRequest& request);

const CRPCCommand vWalletRPCCommands[] =
{
    //  category              name                        actor (function)           okSafeMode
    //  --------------------- ------------------------    -----------------------    ----------
    {"wallet", "addmultisigaddress", &addmultisigaddress, true, false},
    {"wallet", "autocombinerewards", &autocombinerewards, false, false},
    {"wallet", "backupwallet", &backupwallet, true, false},
    {"wallet", "delegatestake", &delegatestake, false, false},
    {"wallet", "dumphdinfo", &dumphdinfo, true, false},
    {"wallet", "dumpprivkey", &dumpprivkey, true, false},
    {"wallet", "dumpwallet", &dumpwallet, true, false},
    {"wallet", "bip38encrypt", &bip38encrypt, true, false},
    {"wallet", "bip38decrypt", &bip38decrypt, true, false},
    {"wallet", "encryptwallet", &encryptwallet, true, false},
    {"wallet", "getaccountaddress", &getaccountaddress, true, false},
    {"wallet", "getaccount", &getaccount, true, false},
    {"wallet", "getaddressesbyaccount", &getaddressesbyaccount, true, false},
    {"wallet", "getbalance", &getbalance, false, false},
    {"wallet", "getcoldstakingbalance", &getcoldstakingbalance, false, false},
    {"wallet", "getdelegatedbalance", &getdelegatedbalance, false, false},
    {"wallet", "getaddressinfo", &getaddressinfo, true, false},
    {"wallet", "getnewaddress", &getnewaddress, true, false},
    {"wallet", "getnewstakingaddress", &getnewstakingaddress, true, false},
    {"wallet", "getrawchangeaddress", &getrawchangeaddress, true, false},
    {"wallet", "getreceivedbyaccount", &getreceivedbyaccount, false, false},
    {"wallet", "getreceivedbyaddress", &getreceivedbyaddress, false, false},
    {"wallet", "getstakingstatus", &getstakingstatus, false, false},
    {"wallet", "getstakesplitthreshold", &getstakesplitthreshold, false, false},
    {"wallet", "gettransaction", &gettransaction, false, false},
    {"wallet", "abandontransaction", &abandontransaction, false, false},
    {"wallet", "getunconfirmedbalance", &getunconfirmedbalance, false, false},
    {"wallet", "getwalletinfo", &getwalletinfo, false, false},
    {"wallet", "importprivkey", &importprivkey, true, false},
    {"wallet", "importwallet", &importwallet, true, false},
    {"wallet", "importaddress", &importaddress, true, false},
    {"wallet", "keypoolrefill", &keypoolrefill, true, false},
    {"wallet", "listaccounts", &listaccounts, false, false},
    {"wallet", "listdelegators", &listdelegators, false, false},
    {"wallet", "liststakingaddresses", &liststakingaddresses, false, false},
    {"wallet", "listaddressgroupings", &listaddressgroupings, false, false},
    {"wallet", "listcoldutxos", &listcoldutxos, false, false},
    {"wallet", "listlockunspent", &listlockunspent, false, false},
    {"wallet", "listreceivedbyaccount", &listreceivedbyaccount, false, false},
    {"wallet", "listreceivedbyaddress", &listreceivedbyaddress, false, false},
    {"wallet", "listsinceblock", &listsinceblock, false, false},
    {"wallet", "listtransactions", &listtransactions, false, false},
    {"wallet", "listunspent", &listunspent, false, false},
    {"wallet", "lockunspent", &lockunspent, true, false},
    {"wallet", "move", &movecmd, false, false},
    {"wallet", "multisend", &multisend, false, false},
    {"wallet", "rawdelegatestake", &rawdelegatestake, false, false},
    {"wallet", "sendfrom", &sendfrom, false, false},
    {"wallet", "sendmany", &sendmany, false, false},
    {"wallet", "sendtoaddress", &sendtoaddress, false, false},
    {"wallet", "sendtoaddressix", &sendtoaddressix, false, false},
    {"wallet", "setaccount", &setaccount, true, false},
    {"wallet", "setstakesplitthreshold", &setstakesplitthreshold, false, false},
    {"wallet", "settxfee", &settxfee, true, false},
    {"wallet", "signmessage", &signmessage, true, false},
    {"wallet", "walletlock", &walletlock, true, false},
    {"wallet", "upgradetohd", &upgradetohd, true, false},
    {"wallet", "walletpassphrasechange", &walletpassphrasechange, true, false},
    {"wallet", "walletpassphrase", &walletpassphrase, true, false},
    {"wallet", "delegatoradd", &delegatoradd, true, false},
    {"wallet", "delegatorremove", &delegatorremove, true, false},

    /* Forge */
    {"forge", "listforgeitems", &listforgeitems, false, false},

    /* Zerocoin (Deprecated) */
    {"zerocoin", "createrawzerocoinspend", &createrawzerocoinspend, false, false},
    {"zerocoin", "getzerocoinbalance", &getzerocoinbalance, false, false},
    {"zerocoin", "listmintedzerocoins", &listmintedzerocoins, false, false},
    {"zerocoin", "listspentzerocoins", &listspentzerocoins, false, false},
    {"zerocoin", "listzerocoinamounts", &listzerocoinamounts, false, false},
    {"zerocoin", "mintzerocoin", &mintzerocoin, false, false},
    {"zerocoin", "spendzerocoin", &spendzerocoin, false, false},
    {"zerocoin", "spendrawzerocoin", &spendrawzerocoin, true, false},
    {"zerocoin", "spendzerocoinmints", &spendzerocoinmints, false, false},
    {"zerocoin", "resetmintzerocoin", &resetmintzerocoin, false, false},
    {"zerocoin", "resetspentzerocoin", &resetspentzerocoin, false, false},
    {"zerocoin", "getarchivedzerocoin", &getarchivedzerocoin, false, false},
    {"zerocoin", "importzerocoins", &importzerocoins, false, false},
    {"zerocoin", "exportzerocoins", &exportzerocoins, false, false},
    {"zerocoin", "reconsiderzerocoins", &reconsiderzerocoins, false, false},
    {"zerocoin", "getspentzerocoinamount", &getspentzerocoinamount, false, false},
    {"zerocoin", "getzpivseed", &getzpivseed, false, false},
    {"zerocoin", "setzpivseed", &setzpivseed, false, false},
    {"zerocoin", "generatemintlist", &generatemintlist, false, false},
    {"zerocoin", "searchdzpiv", &searchdzpiv, false, false},
    {"zerocoin", "dzpivstate", &dzpivstate, false, false},
};

void walletRegisterRPCCommands()
{
    unsigned int vcidx;
    for (vcidx = 0; vcidx < ARRAYLEN(vWalletRPCCommands); vcidx++)
    {
        const CRPCCommand *pcmd;

        pcmd = &vWalletRPCCommands[vcidx];
        tableRPC.appendCommand(pcmd->name, pcmd);
    }
}