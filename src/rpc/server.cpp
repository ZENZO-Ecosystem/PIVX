// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2020 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/server.h"

#include "base58.h"
#include "init.h"
#include "main.h"
#include "random.h"
#include "sync.h"
#include "guiinterface.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/signals2/signal.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/string/case_conv.hpp> // for to_upper()

#include <univalue.h>


static bool fRPCRunning = false;
static bool fRPCInWarmup = true;
static std::string rpcWarmupStatus("RPC server started");
static RecursiveMutex cs_rpcWarmup;

/* Timer-creating functions */
static RPCTimerInterface* timerInterface = NULL;
/* Map of name to timer.
 * @note Can be changed to std::unique_ptr when C++11 */
static std::map<std::string, boost::shared_ptr<RPCTimerBase> > deadlineTimers;

static struct CRPCSignals
{
    boost::signals2::signal<void ()> Started;
    boost::signals2::signal<void ()> Stopped;
    boost::signals2::signal<void (const CRPCCommand&)> PreCommand;
    boost::signals2::signal<void (const CRPCCommand&)> PostCommand;
} g_rpcSignals;

void RPCServer::OnStarted(boost::function<void ()> slot)
{
    g_rpcSignals.Started.connect(slot);
}

void RPCServer::OnStopped(boost::function<void ()> slot)
{
    g_rpcSignals.Stopped.connect(slot);
}

void RPCServer::OnPreCommand(boost::function<void (const CRPCCommand&)> slot)
{
    g_rpcSignals.PreCommand.connect(boost::bind(slot, _1));
}

void RPCServer::OnPostCommand(boost::function<void (const CRPCCommand&)> slot)
{
    g_rpcSignals.PostCommand.connect(boost::bind(slot, _1));
}

void RPCTypeCheck(const UniValue& params,
                  const std::list<UniValue::VType>& typesExpected,
                  bool fAllowNull)
{
    unsigned int i = 0;
    for (UniValue::VType t : typesExpected) {
        if (params.size() <= i)
            break;

        const UniValue& v = params[i];
        if (!((v.type() == t) || (fAllowNull && (v.isNull())))) {
            std::string err = strprintf("Expected type %s, got %s",
                                   uvTypeName(t), uvTypeName(v.type()));
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
        i++;
    }
}

void RPCTypeCheckObj(const UniValue& o,
                  const std::map<std::string, UniValue::VType>& typesExpected,
                  bool fAllowNull)
{
    for (const PAIRTYPE(std::string, UniValue::VType)& t : typesExpected) {
        const UniValue& v = find_value(o, t.first);
        if (!fAllowNull && v.isNull())
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Missing %s", t.first));

        if (!((v.type() == t.second) || (fAllowNull && (v.isNull())))) {
            std::string err = strprintf("Expected type %s for %s, got %s",
                                   uvTypeName(t.second), t.first, uvTypeName(v.type()));
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
    }
}

static inline int64_t roundint64(double d)
{
    return (int64_t)(d > 0 ? d + 0.5 : d - 0.5);
}

CAmount AmountFromValue(const UniValue& value)
{
    if (!value.isNum())
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount is not a number");

    double dAmount = value.get_real();
    if (dAmount <= 0.0 || dAmount > 21000000.0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    CAmount nAmount = roundint64(dAmount * COIN);
    if (!Params().GetConsensus().MoneyRange(nAmount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    return nAmount;
}

UniValue ValueFromAmount(const CAmount& amount)
{
    bool sign = amount < 0;
    int64_t n_abs = (sign ? -amount : amount);
    int64_t quotient = n_abs / COIN;
    int64_t remainder = n_abs % COIN;
    return UniValue(UniValue::VNUM,
            strprintf("%s%d.%08d", sign ? "-" : "", quotient, remainder));
}

uint256 ParseHashV(const UniValue& v, std::string strName)
{
    std::string strHex;
    if (v.isStr())
        strHex = v.get_str();
    if (!IsHex(strHex)) // Note: IsHex("") is false
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName + " must be hexadecimal string (not '" + strHex + "')");
    if (64 != strHex.length())
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be of length %d (not %d)", strName, 64, strHex.length()));
    uint256 result;
    result.SetHex(strHex);
    return result;
}
uint256 ParseHashO(const UniValue& o, std::string strKey)
{
    return ParseHashV(find_value(o, strKey), strKey);
}
std::vector<unsigned char> ParseHexV(const UniValue& v, std::string strName)
{
    std::string strHex;
    if (v.isStr())
        strHex = v.get_str();
    if (!IsHex(strHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName + " must be hexadecimal string (not '" + strHex + "')");
    return ParseHex(strHex);
}
std::vector<unsigned char> ParseHexO(const UniValue& o, std::string strKey)
{
    return ParseHexV(find_value(o, strKey), strKey);
}

int ParseInt(const UniValue& o, std::string strKey)
{
    const UniValue& v = find_value(o, strKey);
    if (v.isNum())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, " + strKey + "is not an int");

    return v.get_int();
}

bool ParseBool(const UniValue& o, std::string strKey)
{
    const UniValue& v = find_value(o, strKey);
    if (v.isBool())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, " + strKey + "is not a bool");

    return v.get_bool();
}


/**
 * Note: This interface may still be subject to change.
 */

std::string CRPCTable::help(std::string strCommand, const JSONRPCRequest& helpreq) const
{
    std::string strRet;
    std::string category;
    std::set<rpcfn_type> setDone;
    std::vector<std::pair<std::string, const CRPCCommand*> > vCommands;

    for (std::map<std::string, const CRPCCommand*>::const_iterator mi = mapCommands.begin(); mi != mapCommands.end(); ++mi)
        vCommands.push_back(std::make_pair(mi->second->category + mi->first, mi->second));
    std::sort(vCommands.begin(), vCommands.end());

    JSONRPCRequest jreq(helpreq);
    jreq.fHelp = true;
    jreq.params = UniValue();

    for (const PAIRTYPE(std::string, const CRPCCommand*) & command : vCommands) {
        const CRPCCommand* pcmd = command.second;
        std::string strMethod = pcmd->name;
        // We already filter duplicates, but these deprecated screw up the sort order
        if (strMethod.find("label") != std::string::npos)
            continue;
        if ((strCommand != "" || pcmd->category == "hidden") && strMethod != strCommand)
            continue;

        jreq.strMethod = strMethod;
        try {
            JSONRPCRequest jreq;
            jreq.fHelp = true;
            rpcfn_type pfn = pcmd->actor;
            if (setDone.insert(pfn).second)
                (*pfn)(jreq);
        } catch (const std::exception& e) {
            // Help text is returned in an exception
            std::string strHelp = std::string(e.what());
            if (strCommand == "") {
                if (strHelp.find('\n') != std::string::npos)
                    strHelp = strHelp.substr(0, strHelp.find('\n'));

                if (category != pcmd->category) {
                    if (!category.empty())
                        strRet += "\n";
                    category = pcmd->category;
                    std::string firstLetter = category.substr(0, 1);
                    boost::to_upper(firstLetter);
                    strRet += "== " + firstLetter + category.substr(1) + " ==\n";
                }
            }
            strRet += strHelp + "\n";
        }
    }
    if (strRet == "")
        strRet = strprintf("help: unknown command: %s\n", strCommand);
    strRet = strRet.substr(0, strRet.size() - 1);
    return strRet;
}

UniValue help(const JSONRPCRequest& jsonRequest)
{
    if (jsonRequest.fHelp || jsonRequest.params.size() > 1)
        throw std::runtime_error(
            "help ( \"command\" )\n"
            "\nList all commands, or get help for a specified command.\n"
            "\nArguments:\n"
            "1. \"command\"     (string, optional) The command to get help on\n"
            "\nResult:\n"
            "\"text\"     (string) The help text\n");

    std::string strCommand;
    if (jsonRequest.params.size() > 0)
        strCommand = jsonRequest.params[0].get_str();

    return tableRPC.help(strCommand, jsonRequest);
}


UniValue stop(const JSONRPCRequest& jsonRequest)
{
    // Accept the deprecated and ignored 'detach' boolean argument
    if (jsonRequest.fHelp || jsonRequest.params.size() > 1)
        throw std::runtime_error(
            "stop\n"
            "\nStop ZENZO server.");
    // Event loop will exit after current HTTP requests have been handled, so
    // this reply will get back to the client.
    StartShutdown();
    return "ZENZO server stopping";
}


/**
 * Call Table
 */
static const CRPCCommand vRPCCommands[] =
    {
        //  category              name                      actor (function)         okSafeMode threadSafe
        //  --------------------- ------------------------  -----------------------  ---------- ----------
        /* Overall control/query calls */
        {"control", "getinfo", &getinfo, true, false}, /* uses wallet if enabled */
        {"control", "help", &help, true, true},
        {"control", "stop", &stop, true, true},

        /* P2P networking */
        {"network", "getnetworkinfo", &getnetworkinfo, true, false},
        {"network", "addnode", &addnode, true, true},
        {"network", "disconnectnode", &disconnectnode, true, true},
        {"network", "getaddednodeinfo", &getaddednodeinfo, true, true},
        {"network", "getconnectioncount", &getconnectioncount, true, false},
        {"network", "getnettotals", &getnettotals, true, true},
        {"network", "getpeerinfo", &getpeerinfo, true, false},
        {"network", "ping", &ping, true, false},
        {"network", "setban", &setban, true, false},
        {"network", "listbanned", &listbanned, true, false},
        {"network", "clearbanned", &clearbanned, true, false},

        /* Block chain and UTXO */
        {"blockchain", "findserial", &findserial, true, false},
        {"blockchain", "getblockindexstats", &getblockindexstats, true, false},
        {"blockchain", "getserials", &getserials, true, false},
        {"blockchain", "getblockchaininfo", &getblockchaininfo, true, false},
        {"blockchain", "getbestblockhash", &getbestblockhash, true, false},
        {"blockchain", "getblockcount", &getblockcount, true, false},
        {"blockchain", "getblock", &getblock, true, false},
        {"blockchain", "getblockhash", &getblockhash, true, false},
        {"blockchain", "getblockheader", &getblockheader, false, false},
        {"blockchain", "getchaintips", &getchaintips, true, false},
        {"blockchain", "getdifficulty", &getdifficulty, true, false},
        {"blockchain", "getfeeinfo", &getfeeinfo, true, false},
        {"blockchain", "getmempoolinfo", &getmempoolinfo, true, true},
        {"blockchain", "getrawmempool", &getrawmempool, true, false},
        {"blockchain", "gettxout", &gettxout, true, false},
        {"blockchain", "gettxoutsetinfo", &gettxoutsetinfo, true, false},
        {"blockchain", "invalidateblock", &invalidateblock, true, true},
        {"blockchain", "reconsiderblock", &reconsiderblock, true, true},
        {"blockchain", "verifychain", &verifychain, true, false},

        /* Mining */
        {"mining", "getblocktemplate", &getblocktemplate, true, false},
        {"mining", "getmininginfo", &getmininginfo, true, false},
        {"mining", "getnetworkhashps", &getnetworkhashps, true, false},
        {"mining", "prioritisetransaction", &prioritisetransaction, true, false},
        {"mining", "submitblock", &submitblock, true, true},

#ifdef ENABLE_WALLET
        /* Coin generation */
        {"generating", "getgenerate", &getgenerate, true, false},
        {"generating", "gethashespersec", &gethashespersec, true, false},
        {"generating", "setgenerate", &setgenerate, true, true},
        {"generating", "generate", &generate, true, true},
#endif

        /* Raw transactions */
        {"rawtransactions", "createrawtransaction", &createrawtransaction, true, false},
        {"rawtransactions", "decoderawtransaction", &decoderawtransaction, true, false},
        {"rawtransactions", "decodescript", &decodescript, true, false},
        {"rawtransactions", "getrawtransaction", &getrawtransaction, true, false},
        {"rawtransactions", "sendrawtransaction", &sendrawtransaction, false, false},
        {"rawtransactions", "signrawtransaction", &signrawtransaction, false, false}, /* uses wallet if enabled */

        /* Utility functions */
        {"util", "createmultisig", &createmultisig, true, true},
        {"util", "validateaddress", &validateaddress, true, false}, /* uses wallet if enabled */
        {"util", "verifymessage", &verifymessage, true, false},
        {"util", "estimatefee", &estimatefee, true, true},
        {"util", "estimatepriority", &estimatepriority, true, true},

        /* Not shown in help */
        {"hidden", "invalidateblock", &invalidateblock, true, true},
        {"hidden", "reconsiderblock", &reconsiderblock, true, true},
        {"hidden", "setmocktime", &setmocktime, true, false},
        { "hidden",             "waitfornewblock",        &waitfornewblock,        true,  true},
        { "hidden",             "waitforblock",           &waitforblock,           true,  true},
        { "hidden",             "waitforblockheight",     &waitforblockheight,     true,  true},

        /* ZENZO features */
        {"zenzo", "listmasternodes", &listmasternodes, true, true},
        {"zenzo", "getmasternodecount", &getmasternodecount, true, true},
        {"zenzo", "masternodeconnect", &masternodeconnect, true, true},
        {"zenzo", "createmasternodebroadcast", &createmasternodebroadcast, true, true},
        {"zenzo", "decodemasternodebroadcast", &decodemasternodebroadcast, true, true},
        {"zenzo", "relaymasternodebroadcast", &relaymasternodebroadcast, true, true},
        {"zenzo", "masternodecurrent", &masternodecurrent, true, true},
        {"zenzo", "masternodedebug", &masternodedebug, true, true},
        {"zenzo", "startmasternode", &startmasternode, true, true},
        {"zenzo", "createmasternodekey", &createmasternodekey, true, true},
        {"zenzo", "getmasternodeoutputs", &getmasternodeoutputs, true, true},
        {"zenzo", "listmasternodeconf", &listmasternodeconf, true, true},
        {"zenzo", "getmasternodestatus", &getmasternodestatus, true, true},
        {"zenzo", "getmasternodewinners", &getmasternodewinners, true, true},
        {"zenzo", "getmasternodescores", &getmasternodescores, true, true},
        {"zenzo", "preparebudget", &preparebudget, true, true},
        {"zenzo", "submitbudget", &submitbudget, true, true},
        {"zenzo", "mnbudgetvote", &mnbudgetvote, true, true},
        {"zenzo", "getbudgetvotes", &getbudgetvotes, true, true},
        {"zenzo", "getnextsuperblock", &getnextsuperblock, true, true},
        {"zenzo", "getbudgetprojection", &getbudgetprojection, true, true},
        {"zenzo", "getbudgetinfo", &getbudgetinfo, true, true},
        {"zenzo", "mnbudgetrawvote", &mnbudgetrawvote, true, true},
        {"zenzo", "mnfinalbudget", &mnfinalbudget, true, true},
        {"zenzo", "checkbudgets", &checkbudgets, true, true},
        {"zenzo", "mnsync", &mnsync, true, true},
        {"zenzo", "spork", &spork, true, true},
        {"zenzo", "getpoolinfo", &getpoolinfo, true, true},
};

CRPCTable::CRPCTable()
{
    unsigned int vcidx;
    for (vcidx = 0; vcidx < (sizeof(vRPCCommands) / sizeof(vRPCCommands[0])); vcidx++) {
        const CRPCCommand* pcmd;

        pcmd = &vRPCCommands[vcidx];
        mapCommands[pcmd->name] = pcmd;
    }
}

const CRPCCommand *CRPCTable::operator[](const std::string &name) const
{
    std::map<std::string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it == mapCommands.end())
        return NULL;
    return (*it).second;
}

bool CRPCTable::appendCommand(const std::string& name, const CRPCCommand* pcmd)
{
    if (IsRPCRunning())
        return false;

    // don't allow overwriting for now
    std::map<std::string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it != mapCommands.end())
        return false;

    mapCommands[name] = pcmd;
    return true;
}

bool StartRPC()
{
    LogPrint("rpc", "Starting RPC\n");
    fRPCRunning = true;
    g_rpcSignals.Started();
    return true;
}

void InterruptRPC()
{
    LogPrint("rpc", "Interrupting RPC\n");
    // Interrupt e.g. running longpolls
    fRPCRunning = false;
}

void StopRPC()
{
    LogPrint("rpc", "Stopping RPC\n");
    deadlineTimers.clear();
    g_rpcSignals.Stopped();
}

bool IsRPCRunning()
{
    return fRPCRunning;
}

void SetRPCWarmupStatus(const std::string& newStatus)
{
    LOCK(cs_rpcWarmup);
    rpcWarmupStatus = newStatus;
}

void SetRPCWarmupFinished()
{
    LOCK(cs_rpcWarmup);
    assert(fRPCInWarmup);
    fRPCInWarmup = false;
}

bool RPCIsInWarmup(std::string* outStatus)
{
    LOCK(cs_rpcWarmup);
    if (outStatus)
        *outStatus = rpcWarmupStatus;
    return fRPCInWarmup;
}

void JSONRPCRequest::parse(const UniValue& valRequest)
{
    // Parse request
    if (!valRequest.isObject())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
    const UniValue& request = valRequest.get_obj();

    // Parse id now so errors from here on will have the id
    id = find_value(request, "id");

    // Parse method
    UniValue valMethod = find_value(request, "method");
    if (valMethod.isNull())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
    if (!valMethod.isStr())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    strMethod = valMethod.get_str();
    if (strMethod != "getblocktemplate")
        LogPrint("rpc", "ThreadRPCServer method=%s\n", SanitizeString(strMethod));

    // Parse params
    UniValue valParams = find_value(request, "params");
    if (valParams.isArray())
        params = valParams.get_array();
    else if (valParams.isNull())
        params = UniValue(UniValue::VARR);
    else
        throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array");
}


static UniValue JSONRPCExecOne(const UniValue& req)
{
    UniValue rpc_result(UniValue::VOBJ);

    JSONRPCRequest jreq;
    try {
        jreq.parse(req);

        UniValue result = tableRPC.execute(jreq);
        rpc_result = JSONRPCReplyObj(result, NullUniValue, jreq.id);
    } catch (const UniValue& objError) {
        rpc_result = JSONRPCReplyObj(NullUniValue, objError, jreq.id);
    } catch (const std::exception& e) {
        rpc_result = JSONRPCReplyObj(NullUniValue,
            JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
    }

    return rpc_result;
}

std::string JSONRPCExecBatch(const UniValue& vReq)
{
    UniValue ret(UniValue::VARR);
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); reqIdx++)
        ret.push_back(JSONRPCExecOne(vReq[reqIdx]));

    return ret.write() + "\n";
}

UniValue CRPCTable::execute(const JSONRPCRequest &request) const
{
    // Find method
    const CRPCCommand* pcmd = tableRPC[request.strMethod];
    if (!pcmd)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");

    g_rpcSignals.PreCommand(*pcmd);

    try {
        // Execute
        return pcmd->actor(request);
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_MISC_ERROR, e.what());
    }

    g_rpcSignals.PostCommand(*pcmd);
}

std::vector<std::string> CRPCTable::listCommands() const
{
    std::vector<std::string> commandList;
    typedef std::map<std::string, const CRPCCommand*> commandMap;

    std::transform( mapCommands.begin(), mapCommands.end(),
                   std::back_inserter(commandList),
                   boost::bind(&commandMap::value_type::first,_1) );
    return commandList;
}

std::string HelpExampleCli(std::string methodname, std::string args)
{
    return "> zenzo-cli " + methodname + " " + args + "\n";
}

std::string HelpExampleRpc(std::string methodname, std::string args)
{
    return "> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", "
           "\"method\": \"" +
           methodname + "\", \"params\": [" + args + "] }' -H 'content-type: text/plain;' http://127.0.0.1:26211/\n";
}

void RPCSetTimerInterfaceIfUnset(RPCTimerInterface *iface)
{
    if (!timerInterface)
        timerInterface = iface;
}

void RPCSetTimerInterface(RPCTimerInterface *iface)
{
    timerInterface = iface;
}

void RPCUnsetTimerInterface(RPCTimerInterface *iface)
{
    if (timerInterface == iface)
        timerInterface = NULL;
}

void RPCRunLater(const std::string& name, boost::function<void(void)> func, int64_t nSeconds)
{
    if (!timerInterface)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No timer handler registered for RPC");
    deadlineTimers.erase(name);
    LogPrint("rpc", "queue run of timer %s in %i seconds (using %s)\n", name, nSeconds, timerInterface->Name());
    deadlineTimers.insert(std::make_pair(name, boost::shared_ptr<RPCTimerBase>(timerInterface->NewTimer(func, nSeconds*1000))));
}

CRPCTable tableRPC;
