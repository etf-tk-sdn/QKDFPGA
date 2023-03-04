#include "KeysDBMemImpl.h"

bool QKD::KeysDBMemImpl::GetKeyConteinerValue(std::pair<std::string, std::string> keyID_SlaveSAE, std::pair<std::string, std::string>& MasterSAE_Key)
{
    auto it = _keysDB.find(keyID_SlaveSAE);
    if (it != _keysDB.end())
    {
        MasterSAE_Key = it->second;
        return true;
    }
    else
        return false;
}

void QKD::KeysDBMemImpl::PutKeyContainerValue(std::pair<std::string, std::string> keyID_SlaveSAE, std::pair<std::string, std::string> MasterSAE_Key)
{
    auto it = _keysDB.emplace(keyID_SlaveSAE, MasterSAE_Key);
    if (!it.second)
        it.first->second = MasterSAE_Key;
}

bool QKD::KeysDBMemImpl::DeleteKeyContainerValue(std::pair<std::string, std::string> keyID_SlaveSAE, std::pair<std::string, std::string> MasterSAE_Key)
{
    auto it = _keysDB.find(keyID_SlaveSAE);
    if (it != _keysDB.end())
    {
        MasterSAE_Key = it->second;
        _keysDB.erase(it);
        return true;
    }
    else
        return false;
}
