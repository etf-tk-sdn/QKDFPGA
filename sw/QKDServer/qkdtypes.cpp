#include "qkdtypes.h"
#include "json.hpp"

qkdtypes::Status::Status()
{

}

qkdtypes::Status::Status(std::string source_KME_ID, std::string target_KME_ID, std::string master_SAE_ID, std::string slave_SAE_ID, int key_size, int stored_key_count, int max_key_count, int max_key_per_request, int max_key_size, int min_key_size, int max_SAE_ID_count)
{
    this->source_KME_ID = source_KME_ID;
    this->target_KME_ID = target_KME_ID;
    this->master_SAE_ID = master_SAE_ID;
    this->slave_SAE_ID = slave_SAE_ID;
    this->key_size = key_size;
    this->stored_key_count = stored_key_count;
    this->max_key_count = max_key_count;
    this->max_key_per_request = max_key_per_request;
    this->max_key_size = max_key_size;
    this->min_key_size = min_key_size;
    this->max_SAE_ID_count = max_SAE_ID_count;
}

qkdtypes::Key::Key() 
{

}

qkdtypes::Key::Key(std::string key_ID, std::string key)
{
    this->key_ID = key_ID;
    this->key = key;
}


qkdtypes::KeyContainer::KeyContainer()
{

}

qkdtypes::KeyContainer::KeyContainer(std::list<qkdtypes::Key> keys)
{
    this->keys = keys;
}

