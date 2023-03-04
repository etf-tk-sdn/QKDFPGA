#pragma once
#include "AuthDB.h"
#include <map>

namespace QKD {
	class AuthDBMemImpl : public AuthDB
	{
	public:
		bool GetAuthValue(std::string publicKey, std::string& SAE_ID);
		void PutAuthValue(std::string publicKey, std::string SAE_ID);

	private:
		std::map<std::string, std::string, std::less<>> _authDB;
	};
}