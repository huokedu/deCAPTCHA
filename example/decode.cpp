
#include <boost/log/trivial.hpp>

#include <boost/regex.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/format.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
namespace fs = boost::filesystem;
#include <boost/program_options.hpp>
namespace po = boost::program_options;
#include <boost/make_shared.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <boost/noncopyable.hpp>
#include <boost/foreach.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/locale.hpp>
#include <boost/signals2.hpp>
#include <boost/lambda/lambda.hpp>
#include <locale.h>
#include <cstring>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <wchar.h>

#include "boost/consolestr.hpp"
#include "boost/acceptor_server.hpp"
#include "boost/avloop.hpp"

#include "deCAPTCHA/decaptcha.hpp"
#include "deCAPTCHA/deathbycaptcha_decoder.hpp"
#include "deCAPTCHA/channel_friend_decoder.hpp"
#include "deCAPTCHA/antigate_decoder.hpp"
#include "deCAPTCHA/avplayer_free_decoder.hpp"
#include "deCAPTCHA/jsdati_decoder.hpp"
#include "deCAPTCHA/hydati_decoder.hpp"

static void vc_code_decoded(boost::system::error_code ec, std::string provider, std::string vccode, boost::function<void()> reportbadvc)
{
	BOOST_LOG_TRIVIAL(info) << console_out_str("使用 ") <<  console_out_str(provider) << console_out_str(" 成功解码验证码!");

	BOOST_LOG_TRIVIAL(info) << console_out_str("验证码是 ") << vccode;
}

static void decode_verify_code(boost::asio::io_service & io_service, const boost::filesystem::path vcodeimgfile, decaptcha::deCAPTCHA & decaptcha)
{
	std::string buffer;
	std::size_t imgsize = boost::filesystem::file_size(vcodeimgfile);
	buffer.resize(imgsize);
	// 保存文件.
	std::ifstream img(vcodeimgfile.string().c_str(), std::ifstream::openmode(std::ofstream::binary | std::ofstream::in) );

	img.read(&buffer[0], imgsize);

	decaptcha.async_decaptcha(
		buffer,
		boost::bind(&vc_code_decoded, _1, _2, _3, _4)
	);
}

int main( int argc, char *argv[] )
{
	std::string jsdati_username, jsdati_password;
	std::string hydati_key;
	std::string deathbycaptcha_username, deathbycaptcha_password;
	//http://api.dbcapi.me/in.php
	//http://antigate.com/in.php
	std::string antigate_key, antigate_host;
	bool use_avplayer_free_vercode_decoder(false);

	po::variables_map vm;
	po::options_description desc( "qqbot options" );
	desc.add_options()
	( "help,h", 	"produce help message" )

	( "jsdati_username", po::value<std::string>( &jsdati_username ),	console_out_str("联众打码服务账户").c_str() )
	( "jsdati_password", po::value<std::string>( &jsdati_password ),	console_out_str("联众打码服务密码").c_str() )

	( "hydati_key", po::value<std::string>( &hydati_key ),	console_out_str("慧眼答题服务key").c_str() )

	( "deathbycaptcha_username", po::value<std::string>( &deathbycaptcha_username ),	console_out_str("阿三解码服务账户").c_str() )
	( "deathbycaptcha_password", po::value<std::string>( &deathbycaptcha_password ),	console_out_str("阿三解码服务密码").c_str() )

	( "antigate_key", po::value<std::string>( &antigate_key ),	console_out_str("antigate解码服务key").c_str() )
	( "antigate_host", po::value<std::string>( &antigate_host )->default_value("http://antigate.com/"),	console_out_str("antigate解码服务器地址").c_str() )

	( "use_avplayer_free_vercode_decoder", po::value<bool>( &use_avplayer_free_vercode_decoder ), "don't use" )
	;

	po::store( po::parse_command_line( argc, argv, desc ), vm );
	po::notify( vm );

	if( vm.count( "help" ) ) {
		std::cerr <<  desc <<  std::endl;
		return 1;
	}

	boost::asio::io_service io_service;

	decaptcha::deCAPTCHA decaptcha(io_service);

	if(!hydati_key.empty())
	{
		decaptcha.add_decoder(
			decaptcha::decoder::hydati_decoder(
				io_service, hydati_key
			)
		);
	}

	if(!jsdati_username.empty() && !jsdati_password.empty())
	{
		decaptcha.add_decoder(
			decaptcha::decoder::jsdati_decoder(
				io_service, jsdati_username, jsdati_password
			)
		);
	}

	if (!deathbycaptcha_username.empty() && !deathbycaptcha_password.empty())
	{
		decaptcha.add_decoder(
			decaptcha::decoder::deathbycaptcha_decoder(
				io_service, deathbycaptcha_username, deathbycaptcha_password
			)
		);
	}

	if(!antigate_key.empty())
	{
		decaptcha.add_decoder(
			decaptcha::decoder::antigate_decoder(io_service, antigate_key, antigate_host)
		);
	}

	if(use_avplayer_free_vercode_decoder)
	{
		decaptcha.add_decoder(
			decaptcha::decoder::avplayer_free_decoder(io_service)
		);
	}

	decode_verify_code(io_service, "vercode.jpeg", decaptcha);

	avloop_run( io_service);
	return 0;
}
