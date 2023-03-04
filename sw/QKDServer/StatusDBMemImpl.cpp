#include "StatusDBMemImpl.h"

bool QKD::StatusDBMemImpl::GetStatusEntry(std::string key, StatusEntry** entry) {
    auto& key2_map = _statusDB.get<by_key2>();
    auto e2 = key2_map.find(key);
    if (e2 != key2_map.end()) {
        *entry = const_cast<StatusEntry*>(&(*e2));
        int key_size = (*entry)->status.key_size;
        int stored_key_count = int((*entry)->rawKeys.size()) * 8 / key_size;
        (*entry)->status.stored_key_count = stored_key_count;
        return true;
    }
    return false;
}


void QKD::StatusDBMemImpl::PutStatusEntry(StatusEntry entry)
{
    auto& key1_map = _statusDB.get<by_key1>();
    auto& key2_map = _statusDB.get<by_key2>();

    auto e1 = key1_map.find(entry.key1);
    auto e2 = key2_map.find(entry.key2);
    if (!(e1 != key1_map.end() && e2 != key2_map.end())) {
        _statusDB.insert(entry);
    }
    else {
        _statusDB.replace(e1, entry);
    }
}
