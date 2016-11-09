//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2016 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#include <ripple/app/misc/detail/WorkSSL.h>
#include <boost/bind.hpp>

namespace ripple {

namespace detail {

WorkSSL::WorkSSL(
    std::string const& method, std::string const& body,
    std::string const& host, std::string const& path,
    std::string const& port, bool verify, boost::asio::io_service& ios,
    callback_type cb)
    : WorkBase(method, body, host, path, port, ios, cb)
    , context_()
    , stream_ (socket_, context_)
{
    stream_.set_verify_mode (verify ? boost::asio::ssl::verify_peer :
        boost::asio::ssl::verify_none);
    stream_.set_verify_callback (
        std::bind (
            &WorkSSL::rfc2818_verify, host_,
            std::placeholders::_1, std::placeholders::_2));
}

void
WorkSSL::onConnect(error_code const& ec)
{
    if (ec)
        return fail(ec);

    stream_.async_handshake(
        boost::asio::ssl::stream_base::client,
        strand_.wrap (boost::bind(&WorkSSL::onHandshake, shared_from_this(),
            boost::asio::placeholders::error)));
}

void
WorkSSL::onHandshake(error_code const& ec)
{
    if (ec)
        return fail(ec);

    onStart ();
}

} // detail

} // ripple
