#include "AuthDBMemImpl.h"

bool QKD::AuthDBMemImpl::GetAuthValue(std::string publicKey, std::string& SAE_ID)
{
    auto it = _authDB.find(publicKey);
    if (it != _authDB.end())
    {
        SAE_ID = it->second;
        return true;
    }
    else
        return false;
}

void QKD::AuthDBMemImpl::PutAuthValue(std::string publicKey, std::string SAE_ID)
{
    auto it = _authDB.emplace(publicKey, SAE_ID);
    if (!it.second)
        it.first->second = SAE_ID;
}
