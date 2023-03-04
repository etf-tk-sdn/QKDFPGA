/*#include "QKDKeysDB.h"

bool QKDKeysDB::GetKeyConteinerValue(std::pair<std::string, std::string> keyID_SlaveSAE, std::pair<std::string, std::string>& MasterSAE_Key)
{
    //std::scoped_lock locker(_newKeyStorage_lock);
    auto it = _qkdKeysDB.find(keyID_SlaveSAE);
    if (it != _qkdKeysDB.end())
    {
        MasterSAE_Key = it->second;
        return true;
    }
    else
        return false;
}

void QKDKeysDB::PutKeyContainerValue(std::pair<std::string, std::string> keyID_SlaveSAE, std::pair<std::string, std::string> MasterSAE_Key)
{
    //std::scoped_lock locker(_newKeyStorage_lock);
    auto it = _qkdKeysDB.emplace(keyID_SlaveSAE, MasterSAE_Key);
    if (!it.second)
        it.first->second = MasterSAE_Key;
}

bool QKDKeysDB::DeleteKeyContainerValue(std::pair<std::string, std::string> keyID_SlaveSAE, std::pair<std::string, std::string> MasterSAE_Key)
{
   // std::scoped_lock locker(_newKeyStorage_lock);
    auto it = _qkdKeysDB.find(keyID_SlaveSAE);
    if (it != _qkdKeysDB.end())
    {
        MasterSAE_Key = it->second;
        _qkdKeysDB.erase(it);
        return true;
    }
    else
        return false;
}
*/