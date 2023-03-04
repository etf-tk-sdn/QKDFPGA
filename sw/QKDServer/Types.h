#include <string>
#include "json.hpp"
#include <queue>
#include <vector>

using json = nlohmann::json;

#define AS_JSON(Type, ...)                                                     \
  friend void to_json(nlohmann::ordered_json &nlohmann_json_j,                 \
                      const Type &nlohmann_json_t) {                           \
    NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_TO, __VA_ARGS__))   \
  }                                                                            \
  friend void from_json(const nlohmann::ordered_json &nlohmann_json_j,         \
                        Type &nlohmann_json_t) {                               \
    NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_FROM, __VA_ARGS__)) \
  }

namespace QKD
{
    struct Status
    {
        std::string source_KME_ID;
        std::string target_KME_ID;
        std::string master_SAE_ID;
        std::string slave_SAE_ID;
        int key_size = 0;
        int stored_key_count = 0;
        int max_key_count = 0;
        int max_key_per_request = 0;
        int max_key_size = 0;
        int min_key_size = 0;
        int max_SAE_ID_count = 0;
        AS_JSON(Status, source_KME_ID, target_KME_ID, master_SAE_ID, slave_SAE_ID, key_size, stored_key_count, max_key_count, max_key_per_request, max_key_size, min_key_size, max_SAE_ID_count);
    };

    struct Key 
    {
   
        std::string key_ID;
        std::string key;
        AS_JSON(Key, key_ID, key);
    };

    struct KeyContainer
    {
        std::list<Key> keys;
        AS_JSON(KeyContainer, keys);
    };

    struct GetKeysRequest
    {
        std::string slave_SAE_ID;
        int number;
        int size;
        json additional_slave_IDs;
    };

    struct GetKeysWithIDRequest
    {
        std::string master_SAE_ID;
        json key_IDs;
    };

    struct StatusEntry {
        std::string key1; //Master SAE ID
        std::string key2; //Slave SAE ID
        Status status;
        std::queue<uint8_t> rawKeys;
        //std::vector<uint8_t> rawKeys;
    };
}


