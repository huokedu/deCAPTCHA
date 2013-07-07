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

#include "channel_friend_decoder.hpp"

namespace decaptcha{

class deCAPTCHA;

template<class ConstBuffer, class Handler >
class async_decaptcha_op : boost::asio::coroutine {
public:
	async_decaptcha_op(boost::asio::io_service & io_service, deCAPTCHA & decaptcha,
					const ConstBuffer & buf, Handler handler)
		:m_io_service(io_service), m_buffer(buf), m_handler(handler), m_decaptcha(decaptcha)
	{
		// TODO 使用机器识别算法
		// TODO 使用人肉识别服务

		// 让 XMPP/IRC 的聊友版面
		io_service.post(boost::asio::detail::bind_handler(*this,boost::system::error_code(), 0, 0));
	}

	void operator()(boost::system::error_code ec, std::size_t id, std::string result);

private:
	boost::asio::io_service & m_io_service;
	deCAPTCHA & m_decaptcha;
	const ConstBuffer & m_buffer;
	Handler m_handler;
};

class deCAPTCHA{
	typedef boost::function<void ()>	decoder_op_t;
public:
	deCAPTCHA(boost::asio::io_service & io_service)
		:m_io_service(io_service)
	{
	}

	/*
	 * add_decoder 向系统添加验证码解码器.
	 * 
	 * 目前实现的解码器是 channel_friend_decoder , 利用其他频道的聊友进行解码.
	 */
	template<class DecoderClass>
	void add_decoder(DecoderClass decoder)
	{
	}

	/*
	* async_decaptcha 用于将 buf 表示的一个缓冲区(jpeg数据) 识别为一个文字,
	* 如果有可能的话, 还需要用到 sender 发送一些数据.
	* 识别完成后调用 handler 返回识别结果.
	* 
	* handler 的签名如下
	* 
	* void decaptcha_handler(boost::system::error_code ec, std::size_t id, std::string result)
	* {
	* 		
	* }
	*/
	template<class ConstBuffer, class Handler>
	void async_decaptcha(const ConstBuffer & buf, Handler handler)
	{
		async_decaptcha_op<ConstBuffer,Handler>
							op(m_io_service, *this, buf, handler);
	}
private:
	boost::asio::io_service & m_io_service;
};

template<class ConstBuffer, class Handler >
void async_decaptcha_op<ConstBuffer, Handler>::operator()(boost::system::error_code ec, std::size_t id, std::string result)
{
	BOOST_ASIO_CORO_REENTER(this)
	{
		// 遍历所有的 decoder, 一个一个试过.

	}
}


}
