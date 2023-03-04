#pragma once
#include <string>

namespace QKD {
	class KeysDB
	{
	public:
		virtual bool GetKeyConteinerValue(std::pair<std::string, std::string> keyID_SlaveSAE, std::pair<std::string, std::string>& MasterSAE_Key) = 0;
		virtual void PutKeyContainerValue(std::pair<std::string, std::string> keyID_SlaveSAE, std::pair<std::string, std::string> MasterSAE_Key) = 0;
		virtual bool DeleteKeyContainerValue(std::pair<std::string, std::string> keyID_SlaveSAE, std::pair<std::string, std::string> MasterSAE_Key) = 0;
	};
}
