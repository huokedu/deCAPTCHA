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
#include <boost/random.hpp>
#include <boost/format.hpp>
#include <boost/make_shared.hpp>
#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <avhttp.hpp>
#include <avhttp/async_read_body.hpp>

#include <boost/property_tree/ptree.hpp>
namespace pt = boost::property_tree;
#include <boost/property_tree/json_parser.hpp>
namespace js = boost::property_tree::json_parser;

#include <boost/timedcall.hpp>

namespace decaptcha{
namespace decoder{
namespace detail{

inline std::string generate_boundary()
{
	boost::rand48 p(time(NULL));
	return  boost::str(boost::format("%06x%06x") % p() %  p()  ).substr(0, 12);
}

template<class Handler>
class deathbycaptcha_decoder_op : boost::asio::coroutine {
public:
	deathbycaptcha_decoder_op(boost::asio::io_service & io_service,
			std::string username, std::string password,
			const std::string &buffer, Handler handler)
		: m_io_service(io_service),
		  m_username(username), m_password(password),
		  m_handler(handler),
		  m_stream(boost::make_shared<avhttp::http_stream>(boost::ref(m_io_service))),
		  m_location(boost::make_shared<std::string>()),
		  m_buffers(boost::make_shared<boost::asio::streambuf>()),
		  m_tries(boost::make_shared<int>(0))
	{
		std::string boundary = generate_boundary();
 		std::string content = build_multipart_formdata(buffer, boundary);
 		std::string content_type = boost::str(boost::format("multipart/form-data; boundary=----------------------------%s") % boundary);

		m_stream->request_options(
			avhttp::request_opts()
				(avhttp::http_options::request_method, "POST" )
				(avhttp::http_options::accept, "application/json")
				(avhttp::http_options::connection, "close" )
				(avhttp::http_options::content_length, boost::lexical_cast<std::string>(content.length()) )
				(avhttp::http_options::content_type, content_type )
				(avhttp::http_options::request_body, content )
		);
		// 处理.
		m_stream->async_open("http://api.dbcapi.me/api/captcha", *this);
	};

	void operator()(boost::system::error_code ec)
	{
		// 判断 ec
		// 根据要求, ec 必须得是 303
		if ( ec == avhttp::errc::see_other){
			// 获取 url
			*m_location = m_stream->location();

			// 继续读取,
			boost::asio::async_read(*m_stream, *m_buffers, avhttp::detail::read_all(m_stream->content_length()), *this);

		}else{
			m_handler(ec, 0, std::string(""));
		}
	}

	// 这里是 json 格式的数据
	void operator()(boost::system::error_code ec, std::size_t bytes_transfered)
	{
		using namespace boost::system::errc;

 		BOOST_ASIO_CORO_REENTER(this)
 		{
			if (ec){
				m_handler(ec, 0, std::string(""));
				return;
			}else if (process_result(ec, bytes_transfered))
			{
				return;
			}

			// 延时 8s 然后重试.
			BOOST_ASIO_CORO_YIELD
					boost::delayedcallsec(m_io_service, 8, boost::asio::detail::bind_handler(*this, ec, 0) );

			do{
				// 延时 3s 然后重试.
				BOOST_ASIO_CORO_YIELD
					boost::delayedcallsec(m_io_service, 3, boost::asio::detail::bind_handler(*this, ec, 0) );

				// 这样第一次就总共延时了 11s,  正好是平均解码时间.
				// 获取一下结果
				m_stream = boost::make_shared<avhttp::http_stream>(boost::ref(m_io_service));
				m_buffers = boost::make_shared<boost::asio::streambuf>();

				m_stream->request_options(
					avhttp::request_opts()
						(avhttp::http_options::accept, "application/json")
				);

				BOOST_ASIO_CORO_YIELD avhttp::async_read_body(*m_stream, *m_location, *m_buffers, *this);

				if (process_result(ec, bytes_transfered))
					return;
			}while (should_try(ec));

			m_handler(make_error_code(operation_canceled), 0, std::string(""));
 		}
	}
private:
	bool process_result(boost::system::error_code ec, std::size_t bytes_transfered)
	{
		// 读取 json
		try
		{
			std::istream is(m_buffers.get());
			pt::ptree result;
			js::read_json(is, result);
			if (result.get<bool>("is_correct"))
			{
				std::string text = result.get<std::string>("text");
				if (text.empty())
					return false;
				std::size_t  captchaid = result.get<std::size_t>("captcha");
				m_handler(boost::system::error_code(),captchaid, text);
				return true;
			}
		}
		catch(const pt::ptree_error & error)
		{
		}
		return false;
	}

	// 神码叫应该继续呢?  就是返回没错误, 也没有超过 1min
	bool should_try(boost::system::error_code ec) const
	{
		return (*m_tries) ++ < 20;
	}

private:
	std::string build_multipart_formdata(const std::string &buffer, const std::string & boundary) const
	{
		std::stringstream content_body;
		content_body << "------------------------------" << boundary <<  "\r\n"
					 << "Content-Disposition: form-data; name=\"username\"" <<  "\r\n\r\n"
					 << m_username << "\r\n";
		content_body << "------------------------------" <<  boundary <<  "\r\n"
					 << "Content-Disposition: form-data; name=\"password\"" <<  "\r\n\r\n"
					 << m_password << "\r\n";
		content_body << "------------------------------" <<  boundary <<  "\r\n"
					 << "Content-Disposition: form-data; name=\"captchafile\"; filename=\"vercode.jpeg\"" << "\r\n"
					 << "Content-Type: image/jpeg" <<  "\r\n\r\n";

		content_body.write(buffer.data(), buffer.length());
			content_body << "\r\n";

		content_body << "------------------------------" <<  boundary << "--" << "\r\n";

		return content_body.str();
	}

private:
	boost::asio::io_service & m_io_service;

	boost::shared_ptr<int>	m_tries;
	boost::shared_ptr<avhttp::http_stream> m_stream;
	boost::shared_ptr<std::string> m_location;
	boost::shared_ptr<boost::asio::streambuf> m_buffers;

	Handler m_handler;

	const std::string m_username, m_password;
};

}

class deathbycaptcha_decoder{
public:
	deathbycaptcha_decoder(boost::asio::io_service & io_service, std::string username, std::string password)
	  : m_io_service(io_service), m_username(username), m_password(password)
	{
	}

	template <class Handler>
	void operator()(const std::string &buffer, Handler handler)
	{
		detail::deathbycaptcha_decoder_op<Handler>
				op(m_io_service, m_username, m_password, buffer, handler);
	}

private:
	boost::asio::io_service & m_io_service;
	const std::string m_username, m_password;
};

}
}
