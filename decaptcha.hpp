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
#include <boost/asio.hpp>
#include <boost/function.hpp>

namespace decaptcha{

class deCAPTCHA;

namespace detail{

template<class DecoderOp, class Handler >
class async_decaptcha_op : boost::asio::coroutine {
public:
	async_decaptcha_op(boost::asio::io_service & io_service, std::vector<DecoderOp>	decoder,
						const std::string & buf, Handler handler)
		:m_io_service(io_service), m_decoder(decoder), m_buffer(buf),
		m_handler(handler)
	{
		using namespace boost::asio::detail;
		// TODO 使用机器识别算法
		// TODO 使用人肉识别服务

		// 让 XMPP/IRC 的聊友版面
		m_io_service.post(
			bind_handler(*this, boost::system::error_code(), 0, std::string())
		);
	}

	void operator()(boost::system::error_code ec, std::size_t id, std::string result)
	{
		int & i = m_index_decoder;

		BOOST_ASIO_CORO_REENTER(this)
		{
			// 遍历所有的 decoder, 一个一个试过.
			for( i = 0 ; i < m_decoder.size(); i ++)
			{
				BOOST_ASIO_CORO_YIELD m_decoder[i](m_buffer, *this);
				if (!ec)
				{
					m_io_service.post(
						boost::asio::detail::bind_handler(m_handler, ec, id, result));
					return;
				}
			}

		}
	}

private:
	boost::asio::io_service & m_io_service;
	std::vector<DecoderOp>	m_decoder;
	const std::string m_buffer;
	Handler m_handler;
private:                                                    // value used in coroutine
	int m_index_decoder;

};

template<class DecoderOp, class Handler > async_decaptcha_op<DecoderOp, Handler>
	make_async_decaptcha_op(boost::asio::io_service & io_service,
			const std::vector<DecoderOp> & decoder, const std::string & buf, Handler handler)
{
	return detail::async_decaptcha_op<DecoderOp, Handler>(
				io_service, decoder, buf, handler);
}
}

class deCAPTCHA{
	typedef boost::function<
			void (boost::system::error_code ec, std::size_t id, std::string result)
		> decoder_handler;
	typedef boost::function<
			void (const std::string & buffer, decoder_handler)
		> decoder_op_t;

public:
	deCAPTCHA(boost::asio::io_service & io_service)
		:m_io_service(io_service)
	{
	}

	/*
	 * add_decoder 向系统添加验证码解码器.
	 * 
	 * 目前实现的解码器是 channel_friend_decoder 和 deathbycaptcha_decoder
	 * channel_friend_decoder 利用其他频道的聊友进行解码.
	 * deathbycaptcha_decoder 则是印度阿三开的一家人肉解码服务公司
	 */
	template<class DecoderClass>
	void add_decoder(DecoderClass decoder)
	{
		m_decoder.push_back(decoder);
	}

	/*
	* async_decaptcha 用于将 buf 表示的一个缓冲区(jpeg数据) 识别为一个文字,
	* 识别完成后调用 handler 返回识别结果.
	* 
	* handler 的签名如下
	* 
	* void decaptcha_handler(boost::system::error_code ec, std::size_t id, std::string result)
	* {
	* 		
	* }
	*/
	template<class Handler>
	void async_decaptcha(const std::string & buf, Handler handler)
	{
		detail::make_async_decaptcha_op(m_io_service, m_decoder, buf, handler);
	}
private:
	boost::asio::io_service & m_io_service;
	std::vector<decoder_op_t>	m_decoder;
};

}
