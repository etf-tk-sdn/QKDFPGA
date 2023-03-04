#pragma once

/*#include "server/http/https_server.h"
#include "string/string_utils.h"
#include "utility/singleton.h"

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <cstdint>
#include "qkdtypes.h"

#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <bitset>

using namespace boost::multi_index;

using statusEntry_map = multi_index_container<StatusEntry, indexed_by<
    hashed_unique<tag<struct by_key1>, member<StatusEntry, std::string, &StatusEntry::key1>>,
    hashed_unique<tag<struct by_key2>, member<StatusEntry, std::string, &StatusEntry::key2>>>>;


class SAEPStorage : public CppCommon::Singleton<SAEPStorage>   //baza ID-eva i PublicKey-eva - QKDAuthDB
{
    friend CppCommon::Singleton<SAEPStorage>;

public:
    bool GetSaepValue(std::string callerPublicKey, std::string& callerSAEID);
    void PutSaepValue(std::string callerPublicKey, std::string callerSAEID);

private:
    std::mutex _saepStorage_lock;
    std::map<std::string, std::string, std::less<>> _saepStorage;
};


class NewStatusStorage : public CppCommon::Singleton<NewStatusStorage>   //baza parova Master-Slave, Status-a i RawKey  QKDStatusDB
{
    friend CppCommon::Singleton<NewStatusStorage>;

public:
    bool getStatusEntry(statusEntry_map& m, std::string key, StatusEntry** entry);
    void PutStatusEntry(StatusEntry entry);

private:
    std::mutex _newStatusStorage_lock;
    statusEntry_map _newStatusStorage;
};

class NewKeyStorage : public CppCommon::Singleton<NewKeyStorage>    //QKDKeysDB
{
    friend CppCommon::Singleton<NewKeyStorage>;

public:
    bool GetNewKeyConteinerValue(std::pair<std::string, std::string> keyID_SlaveSAE, std::pair<std::string, std::string>& MasterSAE_Key);
    void PutNewKeyContainerValue(std::pair<std::string, std::string> keyID_SlaveSAE, std::pair<std::string, std::string> MasterSAE_Key);
    bool DeleteNewKeyContainerValue(std::pair<std::string, std::string> keyID_SlaveSAE, std::pair<std::string, std::string> MasterSAE_Key);

private:
    std::mutex _newKeyStorage_lock;
    std::map <std::pair<std::string, std::string>, std::pair<std::string, std::string>, std::less<>> _newKeyStorage;
};*/

