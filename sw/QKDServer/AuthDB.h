#pragma once
#include <string>

namespace QKD {
	class AuthDB
	{
	public:
		virtual bool GetAuthValue(std::string publicKey, std::string& SAE_ID) = 0;
		virtual void PutAuthValue(std::string publicKey, std::string SAE_ID) = 0;
	};
}
