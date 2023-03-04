#pragma once
#include <string>
#include "combaseapi.h"
#include "server/http/https_server.h"

namespace QKD {
	class HTTPSSession : public CppServer::HTTP::HTTPSSession
	{
		std::string callerSAEId = "";
		std::string EVP_PKEY_to_PEM(EVP_PKEY* key);

	public:
		using CppServer::HTTP::HTTPSSession::HTTPSSession;

	protected:
		std::string getCallerPublicKey();
		void onReceivedRequest(const CppServer::HTTP::HTTPRequest& request) override;
		void onReceivedRequestError(const CppServer::HTTP::HTTPRequest& request, const std::string& error) override;
		void onError(int error, const std::string& category, const std::string& message) override;
	};
}