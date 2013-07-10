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
#include <string>
#include <fstream>
#include <boost/make_shared.hpp>
#include <boost/asio.hpp>

#include <avproxy.hpp>

namespace decaptcha{
namespace decoder{
namespace detail{

template<class Handler>
class avplayer_free_decoder_op : boost::asio::coroutine {
public:
	avplayer_free_decoder_op(boost::asio::io_service & io_service,
			const std::string &buffer, Handler handler)
		: m_io_service(io_service),
		  m_handler(handler),
		  m_vercodebuf(buffer),
		  m_socket(boost::make_shared<boost::asio::ip::tcp::socket>(boost::ref(m_io_service))),
		  m_buffers(boost::make_shared<boost::asio::streambuf>())
	{
		avproxy::async_connect(*m_socket, boost::asio::ip::tcp::resolver::query("avlog.avplayer.org", "8013"), *this);
	};

	// 开始!
	void operator()(boost::system::error_code ec, std::size_t bytes_transfered = 0)
	{
		using namespace boost::system::errc;
		using namespace boost::asio;
		if (ec){
			m_handler(ec, 0, std::string());
			return;
		}

		boost::uint32_t	l;
		std::string strbuf;

 		BOOST_ASIO_CORO_REENTER(this)
 		{
			BOOST_ASIO_CORO_YIELD
				async_write(*m_socket, buffer("3bc49260524f3d1a5e535e8ac785766b\n", 33), transfer_exactly(33), *this);

			l = htonl(m_vercodebuf.length());
			buffer_copy(m_buffers->prepare(4), buffer(&l, 4));

			m_buffers->consume(bytes_transfered);

			buffer_copy( m_buffers->prepare(m_vercodebuf.length()), buffer(m_vercodebuf, m_vercodebuf.length()));
			m_buffers->commit(m_vercodebuf.length());

			BOOST_ASIO_CORO_YIELD
				async_write(*m_socket, *m_buffers, transfer_all(), *this);

			BOOST_ASIO_CORO_YIELD
				async_read(*m_socket, *m_buffers, transfer_all(), *this);

			// 获取
			strbuf.resize(bytes_transfered);
			m_buffers->sgetn(&strbuf[0], bytes_transfered);

			if (strbuf.empty())
				ec = make_error_code(bad_message);
			m_handler(ec, 0, strbuf);
 		}
	}

private:
	boost::asio::io_service & m_io_service;

	boost::shared_ptr<boost::asio::ip::tcp::socket> m_socket;

	boost::shared_ptr<boost::asio::streambuf> m_buffers;
	std::string m_vercodebuf;

	Handler m_handler;
};

}

class avplayer_free_decoder{
public:
	avplayer_free_decoder(boost::asio::io_service & io_service)
	  : m_io_service(io_service)
	{
	}

	template <class Handler>
	void operator()(const std::string &buffer, Handler handler)
	{
		detail::avplayer_free_decoder_op<Handler>
				op(m_io_service, buffer, handler);
	}
private:
	boost::asio::io_service & m_io_service;
};

}
}
