/*
 * Copyright (C) 2013  微蔡 <microcai@fedoraproject.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once
#include <boost/asio/io_service.hpp>

namespace decaptcha{
namespace decoder{

template<class Sender>
class channel_friend_decoder_t{
public:
	channel_friend_decoder_t(boost::asio::io_service & io_service, Sender sender)
	  : m_io_service(io_service), m_sender(sender)
	{
	}

	template <class Handler>
	void operator()(boost::asio::streambuf &buffer, Handler handler)
	{

	}

private:
	boost::asio::io_service & m_io_service;
	Sender m_sender;
};

template<class Sender> channel_friend_decoder_t<Sender>
channel_friend_decoder(boost::asio::io_service & io_service, Sender sender)
{
	return channel_friend_decoder_t<Sender>(io_service, sender);
}

}
}
