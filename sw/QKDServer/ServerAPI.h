#pragma once
#include <string>
#include "AuthDB.h"
#include "StatusDB.h"
#include "KeysDB.h"
#include "server/http/https_server.h"

namespace QKD {
	class ServerAPI : public CppCommon::Singleton<ServerAPI>
	{
	private:
		AuthDB* _authDB;
		StatusDB* _statusDB;
		KeysDB* _keysDB;
		std::mutex _server_lock;

	public:
		static const int RESPONSE_OK = 0;
		static const int RESPONSE_NOT_FOUND = 1;
		static const int RESPONSE_UNAUTHORIZED = 2;
		static const int RESPONSE_NOT_ENOUGH_MATERIAL = 3;
		static const int RESPONSE_SIZE_SHALL_BE_MULTIPLE_OF_8 = 4;

		AuthDB* GetAuthDB();
		StatusDB* GetStatusDB();
		KeysDB* GetKeysDB();
		void SetAuthDB(AuthDB* authDB);
		void SetStatusDB(StatusDB* statusDB);
		void SetKeysDB(KeysDB* keysDB);

		std::string GetSAEID(std::string publicKey);
		int GetStatus(std::string SlaveSAEID, std::string callerSAEId, Status** Status);
		int GetKeys(std::string callerSAEId, GetKeysRequest getKeyRequest, KeyContainer** KeyContainer);
		int GetKeysWithId(std::string callerSAEId, GetKeysWithIDRequest getKeyWithIDRequest, KeyContainer** KeyContainer);
	};
}
