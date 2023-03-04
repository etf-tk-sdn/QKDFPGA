/*#include "QKDDatabase.h"

bool SAEPStorage::GetSaepValue(std::string callerPublicKey, std::string& callerSAEID)
{
    std::scoped_lock locker(_saepStorage_lock);
    auto it = _saepStorage.find(callerPublicKey);
    if (it != _saepStorage.end())
    {
        callerSAEID = it->second;
        return true;
    }
    else
        return false;
}

void SAEPStorage::PutSaepValue(std::string callerPublicKey, std::string callerSAEID)
{
    std::scoped_lock locker(_saepStorage_lock);
    auto it = _saepStorage.emplace(callerPublicKey, callerSAEID);
    if (!it.second)
        it.first->second = callerSAEID;
}

bool NewStatusStorage::getStatusEntry(statusEntry_map& m, std::string key, StatusEntry** entry) {
    //getStatusEntry se uvijek poziva nad Slave_SAE_ID
    std::scoped_lock locker(_newStatusStorage_lock);
    m = _newStatusStorage;
    auto& key2_map = m.get<by_key2>();
    auto e2 = key2_map.find(key);
    if (e2 != key2_map.end()) {
        *entry = const_cast<StatusEntry*>(&(*e2));
        // int key_size = (*entry)->status.getKey_Size();
        int key_size = (*entry)->status.key_size;
        int stored_key_count = int((*entry)->rawKeys.size()) * 8 / key_size;
        // (*entry)->status.setStored_Key_Count(stored_key_count);
        (*entry)->status.stored_key_count = stored_key_count;
        return true;
    }
    return false;
}


void NewStatusStorage::PutStatusEntry(StatusEntry entry)
{
    std::scoped_lock locker(_newStatusStorage_lock);

    auto& key1_map = _newStatusStorage.get<by_key1>();
    auto& key2_map = _newStatusStorage.get<by_key2>();

    auto e1 = key1_map.find(entry.key1);
    auto e2 = key2_map.find(entry.key2);
    if (!(e1 != key1_map.end() && e2 != key2_map.end())) {
        _newStatusStorage.insert(entry);
    }
    else {
        _newStatusStorage.replace(e1, entry);
    }
}

bool NewKeyStorage::GetNewKeyConteinerValue(std::pair<std::string, std::string> keyID_SlaveSAE, std::pair<std::string, std::string>& MasterSAE_Key)
{
    std::scoped_lock locker(_newKeyStorage_lock);
    auto it = _newKeyStorage.find(keyID_SlaveSAE);
    if (it != _newKeyStorage.end())
    {
        MasterSAE_Key = it->second;
        return true;
    }
    else
        return false;
}

void NewKeyStorage::PutNewKeyContainerValue(std::pair<std::string, std::string> keyID_SlaveSAE, std::pair<std::string, std::string> MasterSAE_Key)
{
    std::scoped_lock locker(_newKeyStorage_lock);
    auto it = _newKeyStorage.emplace(keyID_SlaveSAE, MasterSAE_Key);
    if (!it.second)
        it.first->second = MasterSAE_Key;
}

bool NewKeyStorage::DeleteNewKeyContainerValue(std::pair<std::string, std::string> keyID_SlaveSAE, std::pair<std::string, std::string> MasterSAE_Key)
{
    std::scoped_lock locker(_newKeyStorage_lock);
    auto it = _newKeyStorage.find(keyID_SlaveSAE);
    if (it != _newKeyStorage.end())
    {
        MasterSAE_Key = it->second;
        _newKeyStorage.erase(it);
        return true;
    }
    else
        return false;
}
*/