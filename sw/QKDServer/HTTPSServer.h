#pragma once
#include "server/http/https_server.h"

namespace QKD {
	class HTTPSServer : public CppServer::HTTP::HTTPSServer
	{
	public:
		using CppServer::HTTP::HTTPSServer::HTTPSServer;

	protected:
		std::shared_ptr<CppServer::Asio::SSLSession> CreateSession(const std::shared_ptr<CppServer::Asio::SSLServer>& server) override;

	protected:
		void onError(int error, const std::string& category, const std::string& message) override;
	};
}
