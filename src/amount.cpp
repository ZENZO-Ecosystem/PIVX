// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2017-2024 The PIVX Core developers
// Copyright (c) 2018-2024 The ZENZO Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"

#include "tinyformat.h"

/*
   The smallest denomination of a ZNZ is known as:
   zen (or zens), ex: 56 zens-per-byte fee
*/

const std::string CURRENCY_UNIT = "ZNZ";

CFeeRate::CFeeRate(const CAmount& nFeePaid, size_t nSize)
{
    if (nSize > 0)
        nZensPerK = nFeePaid * 1000 / nSize;
    else
        nZensPerK = 0;
}

CAmount CFeeRate::GetFee(size_t nSize) const
{
    CAmount nFee = nZensPerK * nSize / 1000;

    if (nFee == 0 && nZensPerK > 0)
        nFee = nZensPerK;

    return nFee;
}

std::string CFeeRate::ToString() const
{
    return strprintf("%d.%08d %s/kB", nSatoshisPerK / COIN, nSatoshisPerK % COIN, CURRENCY_UNIT);
}
