/*#include "QKDStatusDB.h"

bool QKDStatusDB::getStatusEntry(statusEntry_map& m, std::string key, StatusEntry** entry) {
    //getStatusEntry se uvijek poziva nad Slave_SAE_ID
    //std::scoped_lock locker(_newStatusStorage_lock);
    m = _qkdStatusDB;
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


void QKDStatusDB::PutStatusEntry(StatusEntry entry)
{
    //std::scoped_lock locker(_newStatusStorage_lock);

    auto& key1_map = _qkdStatusDB.get<by_key1>();
    auto& key2_map = _qkdStatusDB.get<by_key2>();

    auto e1 = key1_map.find(entry.key1);
    auto e2 = key2_map.find(entry.key2);
    if (!(e1 != key1_map.end() && e2 != key2_map.end())) {
        _qkdStatusDB.insert(entry);
    }
    else {
        _qkdStatusDB.replace(e1, entry);
    }
}*/
