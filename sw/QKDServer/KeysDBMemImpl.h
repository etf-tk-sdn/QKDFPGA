#pragma once
#include "KeysDB.h"
#include <map>

namespace QKD {
	class KeysDBMemImpl : public KeysDB
	{
	public:
		bool GetKeyConteinerValue(std::pair<std::string, std::string> keyID_SlaveSAE, std::pair<std::string, std::string>& MasterSAE_Key);
		void PutKeyContainerValue(std::pair<std::string, std::string> keyID_SlaveSAE, std::pair<std::string, std::string> MasterSAE_Key);
		bool DeleteKeyContainerValue(std::pair<std::string, std::string> keyID_SlaveSAE, std::pair<std::string, std::string> MasterSAE_Key);

	private:
		std::map <std::pair<std::string, std::string>, std::pair<std::string, std::string>, std::less<>> _keysDB;
	};
}

