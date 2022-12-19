/*!
    \file https_server.cpp
    \brief HTTPS server example
    \author Ivan Shynkarenka
    \date 30.04.2019
    \copyright MIT License
*/

#include "asio_service.h"
#include "json.hpp"
#include "base64.h"
#include "combaseapi.h"

#include "server/http/https_server.h"
#include "string/string_utils.h"
#include "utility/singleton.h"

#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <bitset>



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

//Za BASE64 Encoding
static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";


static inline bool is_base64(uint8_t c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(uint8_t const* buf, unsigned int bufLen) {
    std::string ret;
    int i = 0;
    int j = 0;
    uint8_t char_array_3[3];
    uint8_t char_array_4[4];

    while (bufLen--) {
        char_array_3[i++] = *(buf++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';
    }
    return ret;
}

namespace qkdtypes 
{
    class Status {
    private:
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
    public:
        Status()
        {
        
        }
        Status(std::string source_KME_ID, std::string target_KME_ID, std::string master_SAE_ID, std::string slave_SAE_ID, int key_size, int stored_key_count, int max_key_count, int max_key_per_request, int max_key_size, int min_key_size, int max_SAE_ID_count)
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
        std::string& getSource_KME_ID()
        {
            return source_KME_ID;
        }
        std::string& getTarget_KME_ID()
        {
            return target_KME_ID;
        }
        std::string& getMaster_SAE_ID()
        {
            return master_SAE_ID;
        }
        std::string& getSlave_SAE_ID()
        {
            return slave_SAE_ID;
        }
        int& getKey_Size()
        {
            return key_size;
        }
        int& getStored_Key_Count()
        {
            return stored_key_count;
        }
        void setStored_Key_Count(int st_key_count)
        {
            stored_key_count = st_key_count;
        }
        int& getMax_Key_Count()
        {
            return max_key_count;
        }
        int& getMax_Key_Per_Request()
        {
            return max_key_per_request;
        }
        int& getMax_Key_Size()
        {
            return max_key_size;
        }
        int& getMin_Key_Size()
        {
            return min_key_size;
        }
        int& getMax_SAE_ID_Count()
        {
            return max_SAE_ID_count;
        }
        AS_JSON(Status, source_KME_ID, target_KME_ID, master_SAE_ID, slave_SAE_ID, key_size, stored_key_count, max_key_count, max_key_per_request, max_key_size, min_key_size, max_SAE_ID_count)
    };

    class Key {
    private:
        std::string key_ID;
        std::string key;
    public:
        Key()
        {

        }
        Key(std::string key_ID, std::string key)
        {
            this->key_ID = key_ID;
            this->key = key;
        }
        std::string& getKey()
        {
            return key;
        }
        std::string& getKey_ID()
        {
            return key_ID;
        }
        void setKey(std::string key1)
        {
            key = key1;
        }
        void setKeyID(std::string key_ID1)
        {
            key_ID = key_ID1;
        }
        AS_JSON(Key, key_ID, key)
    };

    class Key_ID {
    private:
        std::string key_ID;
    public:
        Key_ID()
        {

        }
        Key_ID(std::string key_ID)
        {
            this->key_ID = key_ID;
        }
        std::string& getKey_ID()
        {
            return key_ID;
        }
        AS_JSON(Key_ID, key_ID)
    };

    class KeyContainer 
    {
    private:
        std::list<Key> keys;
    public:
        KeyContainer()
        {

        }
        KeyContainer(std::list<Key> keys) 
        {
            this->keys = keys;
        }
        std::list<Key> &getKeys()
        {
            return keys;
        }
        AS_JSON(KeyContainer, keys);
    };

    class KeyRequest
    {
    private:
        int number;
        int size;
        std::list<std::string> additional_slave_SAE_IDs;
    public:
        KeyRequest()
        {

        }
        KeyRequest(int number, int size, std::list<std::string> additional_slave_SAE_IDs)
        {
            this->number = number;
            this->size = size;
            this->additional_slave_SAE_IDs = additional_slave_SAE_IDs;
        }
        int &getNumber()
        {
            return number;
        }
        int &getSize()
        {
            return size;
        }
        std::list<std::string> &getAdditional_slave_SAE_IDs()
        {
            return additional_slave_SAE_IDs;
        }
        AS_JSON(KeyRequest, number, size, additional_slave_SAE_IDs);
    };
}

class RawKeyStorage : public CppCommon::Singleton<RawKeyStorage>
{
    friend CppCommon::Singleton<RawKeyStorage>;

public:
    bool GetRawKeyValue(std::pair <std::string, std::string> KME_IDs, std::queue<uint8_t>& value)
    {
        std::scoped_lock locker(_rawKeyStorage_lock);
        auto it = _rawKeyStorage.find(KME_IDs);
        if (it != _rawKeyStorage.end())
        {
            value = it->second;
            return true;
        }
        else
            return false;
    }

    void PutRawKeyValue(std::pair <std::string, std::string> KME_IDs, std::queue<uint8_t> value)
    {
        std::scoped_lock locker(_rawKeyStorage_lock);
        auto it = _rawKeyStorage.emplace(KME_IDs, value);
        if (!it.second)
            it.first->second = value;
    }

private:
    std::mutex _rawKeyStorage_lock;
    std::map<std::pair<std::string, std::string>, std::queue<uint8_t>> _rawKeyStorage;
};

class KeyStorage : public CppCommon::Singleton<KeyStorage>
{
    friend CppCommon::Singleton<KeyStorage>;

public:
    bool GetKeyConteinerValue(std::string SAE_ID, qkdtypes::KeyContainer& value)
    {
        std::scoped_lock locker(_keyStorage_lock);
        auto it = _keyStorage.find(SAE_ID);
        if (it != _keyStorage.end())
        {
            value = it->second;
            return true;
        }
        else
            return false;
    }

    void PutKeyContainerValue(std::string_view SAE_ID, qkdtypes::KeyContainer value)
    {
        std::scoped_lock locker(_keyStorage_lock);
        auto it = _keyStorage.emplace( SAE_ID, value );
        if (!it.second)
            it.first->second = value;
    }

    bool DeleteKeyContainerValue(std::string SAE_ID, qkdtypes::KeyContainer value)
    {
        std::scoped_lock locker(_keyStorage_lock);
        auto it = _keyStorage.find(SAE_ID);
        if (it != _keyStorage.end())
        {
            value = it->second;
            _keyStorage.erase(it);
            return true;
        }
        else
            return false;
    }

private:
    std::mutex _keyStorage_lock;
    std::map<std::string, qkdtypes::KeyContainer, std::less<>> _keyStorage;
};

class StatusStorage : public CppCommon::Singleton<StatusStorage>
{
    friend CppCommon::Singleton<StatusStorage>;

public:
    bool GetStatusValue(std::string SAE_ID, qkdtypes::Status& value)
    {
        std::scoped_lock locker(_statusStorage_lock);
        qkdtypes::Status oldstatus;
        std::pair<std::string, std::string> KME_ID;
        std::queue<uint8_t> q;
        auto it = _statusStorage.find(SAE_ID);
        if (it != _statusStorage.end())
        {
            value = it->second;
            KME_ID = std::make_pair(value.getSource_KME_ID(), value.getTarget_KME_ID());

            // calc stored_key_count
            if (RawKeyStorage::GetInstance().GetRawKeyValue(KME_ID, q)) q = q;
            int key_size = (it->second).getKey_Size();
            int stored_key_count = int(q.size()) * 8 / key_size;    //potrebna konverzija u int jer je size() size_t

           //update stored_key_count
            value.setStored_Key_Count(stored_key_count);
            return true;
        }
        else
            return false;
    }

    void PutStatusValue(std::string_view SAE_ID, qkdtypes::Status value)
    {
        std::scoped_lock locker(_statusStorage_lock);
        auto it = _statusStorage.emplace(SAE_ID, value);
        if (!it.second)
            it.first->second = value;
    }

    bool DeleteStatusValue(std::string SAE_ID, qkdtypes::Status value)
    {
        std::scoped_lock locker(_statusStorage_lock);
        auto it = _statusStorage.find(SAE_ID);
        if (it != _statusStorage.end())
        {
            value = it->second;
            _statusStorage.erase(it);
            return true;
        }
        else
            return false;
    }

private:
    std::mutex _statusStorage_lock;
    std::map<std::string, qkdtypes::Status, std::less<>> _statusStorage;
};


class HTTPSQKDSession : public CppServer::HTTP::HTTPSSession
{
public:
    using CppServer::HTTP::HTTPSSession::HTTPSSession;
   
protected:
    void onReceivedRequest(const CppServer::HTTP::HTTPRequest& request) override
    {
        // Show HTTP request content
        std::cout << std::endl << request;

        // Process HTTP request methods
        if (request.method() == "HEAD")
            SendResponseAsync(response().MakeHeadResponse());
        else if (request.method() == "GET")
        {
            std::string url(request.url());
            std::string SAE_ID;
            int number = 0, size=0;
            
            if (url.ends_with("/status")) 
            {
                SAE_ID = CppCommon::Encoding::URLDecode(url);                     
                CppCommon::StringUtils::ReplaceFirst(SAE_ID, "/api/v1/keys/", "");
                CppCommon::StringUtils::ReplaceFirst(SAE_ID, "/status", "");
                qkdtypes::Status status;

                if (StatusStorage::GetInstance().GetStatusValue(SAE_ID, status))                   
                {                                                                          
                    nlohmann::ordered_json jsonStatus = status;
                    SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));
                }
                else
                    SendResponseAsync(response().MakeErrorResponse(404, "Required Status value was not found for the SAE ID: " + SAE_ID));
            }
            else if (url.find("/enc_keys") != std::string::npos)
            {   
                url = CppCommon::Encoding::URLDecode(url);
                CppCommon::StringUtils::ReplaceFirst(url, "/api/v1/keys/", "");
                CppCommon::StringUtils::ReplaceFirst(url, "/enc_keys", "");

                //Definisanje velicina "size" i "number" u zavisnosti od toga sta je zadano kroz URL
                    if (url.find("size=") != std::string::npos && url.find("number=") != std::string::npos)
                    {
                        std::vector<std::string> url1 = CppCommon::StringUtils::Split(url, "?number=");
                        SAE_ID = url1[0];
                        std::vector<std::string> url2 = CppCommon::StringUtils::Split(url1[1], "&size=");
                        number = std::stoi(url2[0]);
                        size = std::stoi(url2[1]);
                    }
                    else if (url.find("number=") != std::string::npos)
                    {
                        std::vector<std::string> url1 = CppCommon::StringUtils::Split(url, "?number=");
                        SAE_ID = url1[0];
                        number = std::stoi(url1[1]);
                        qkdtypes::Status status;
                        if (StatusStorage::GetInstance().GetStatusValue(SAE_ID, status)) status = status;
                        size = status.getKey_Size();                    
                    }
                    else if (url.find("size=") != std::string::npos)
                    {
                        std::vector<std::string> url1 = CppCommon::StringUtils::Split(url, "?size=");
                        SAE_ID = url1[0];
                        size = std::stoi(url1[1]);
                        number = 1;
                    }
                    else //Ukoliko nisu zadani ni size ni number, uzimaju se defaultne vrijednosti - 1 kljuc, velicine Key_Size definisane u Status-u
                    {
                        SAE_ID = url;
                        number = 1; //default-na vrijednost
                        qkdtypes::Status status1;
                        if (StatusStorage::GetInstance().GetStatusValue(SAE_ID, status1)) status1 = status1;
                        size = status1.getKey_Size();
                    }


                    qkdtypes::Status status;
                    if (!StatusStorage::GetInstance().GetStatusValue(SAE_ID, status)) 
                    {
                        SendResponseAsync(response().MakeErrorResponse(404, "SAE_ID not found."));
                    }
                    else 
                    {
                        status = status;
                        std::pair<std::string, std::string> KME_ID = std::make_pair(status.getSource_KME_ID(), status.getTarget_KME_ID());
                        std::queue<uint8_t> raw_key, key; 
                        RawKeyStorage::GetInstance().GetRawKeyValue(KME_ID, raw_key);
                        if (size % 8 != 0) 
                        {
                            SendResponseAsync(response().MakeErrorResponse(400, "Size shall be a multiple of 8."));
                        }
                        else if (size * number > int(raw_key.size()) * 8) //Provjera da li ima dovoljno materijala za trazene kljuceve
                        {
                            SendResponseAsync(response().MakeErrorResponse(400, "There is not enough key material for requested parameters."));
                        }
                        else
                        {
                            qkdtypes::KeyContainer keyContainer, keyContainer1;
                            for (int z = 0; z < number; z++)  //Proces kreiranja kljuca, kodiranja i generisanja njegovog ID-a ponavlja se onoliko puta koliko je zahtjevano kljuceva
                            {        
                                for (int i = 0; i < size/8; i++)  //Kreiranje pojedinacnih kljuceva zadane velicine
                                {  
                                    key.push(raw_key.front());
                                    raw_key.pop();               //Brisanje preuzetih kljuceva iz baze
                                }

                                //Generisanje Key ID-a za prethodno kreirani kljuc
                                GUID guid = { 0 };
                                char szGuid[36] = { 0 };
                                CoCreateGuid(&guid);
                                sprintf(szGuid, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
                                std::string key_ID = "";
                                for (int j = 0; j < (sizeof(szGuid) / sizeof(char)); j++) {
                                    key_ID = key_ID + szGuid[j];
                                }

                                //Base64 encoding kljuca
                                std::string encodedData = base64_encode(&key.front(), int(key.size()));

                                //keyContainer1 je novi key+key ID koji ce se ispisati
                                //keyContainer uzima u obzir ako je prethodno vec bilo key+key ID-eva vezanih za trazeni SAE_ID, i dodaje na njih novi key+key ID
                                if (KeyStorage::GetInstance().GetKeyConteinerValue(status.getMaster_SAE_ID(), keyContainer)) keyContainer = keyContainer;
                                keyContainer.getKeys().push_back(qkdtypes::Key(key_ID, encodedData));
                                keyContainer1.getKeys().push_back(qkdtypes::Key(key_ID, encodedData));

                                for (int j = 0; j<int(key.size()); j++) //Praznjenje kljuca kako prethodne vrijednosti ne bi uticale na novi kljuc (zbog push)
                                {
                                    key.pop();
                                }
                            }

                            RawKeyStorage::GetInstance().PutRawKeyValue(KME_ID, raw_key); //Azuriranje raw-key-a u storage-u
                            KeyStorage::GetInstance().PutKeyContainerValue(status.getMaster_SAE_ID(), keyContainer); //Azuriranje kljuceva u bazi kljuceva sa ID-evima
                            nlohmann::ordered_json jsonStatus = keyContainer1; //keyContainer1 (set key + key ID-eva) se vraca kao odgovor
                            SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));
                        }
                    }
            }
            else if (url.find("/dec_keys") != std::string::npos)
            {
                url = CppCommon::Encoding::URLDecode(url);
                CppCommon::StringUtils::ReplaceFirst(url, "/api/v1/keys/", "");
                CppCommon::StringUtils::ReplaceFirst(url, "/dec_keys?", "");
                std::vector<std::string> url1 = CppCommon::StringUtils::Split(url, "key_ID=");
                SAE_ID = url1[0];
                std::string key_ID_url = url1[1]; //Key_ID mora biti specificiran, nema defaultnih vrijednosti kao za number i size
                bool exist_key_ID = false;        
                qkdtypes::KeyContainer keyContainer, keyContainer1;
               
                if (KeyStorage::GetInstance().GetKeyConteinerValue(SAE_ID, keyContainer)) //Ukoliko se master_SAE_ID nalazi u KeyStorage-u jer prethodno nije bilo GetKeys zahtjeva?
                {
                    keyContainer = keyContainer;
                    auto it = keyContainer.getKeys().begin();
                    for (auto i = keyContainer.getKeys().begin(); i != keyContainer.getKeys().end(); i++) 
                    {
                        if (i->getKey_ID() == key_ID_url)
                        {
                            exist_key_ID = true;
                            keyContainer1.getKeys().push_back(qkdtypes::Key(i->getKey(), i->getKey_ID()));
                            nlohmann::ordered_json jsonStatus = keyContainer1;
                            SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));
                            it = i;
                            break;
                        }
                    }
                    if (exist_key_ID == true) {
                        keyContainer.getKeys().erase(it);
                        KeyStorage::GetInstance().PutKeyContainerValue(SAE_ID, keyContainer);  //azurira bazu sa izbrisanim ID-em
                    }
                    else if (exist_key_ID == false)
                    {
                        SendResponseAsync(response().MakeErrorResponse(400, "One or more keys specified are not found on KME."));
                    }
                    
                }
                else //ukoliko se master_SAE_ID ne nalazi u KeyStorage-u jer prethodno nije bilo GetKeys zahtjeva?
                {
                    SendResponseAsync(response().MakeErrorResponse(400, "One or more keys specified are not found on KME."));
                }
            }
        }
        else if ((request.method() == "POST"))
        {
            std::string url(request.url());
            if (url.find("/enc_keys") != std::string::npos)
            {
                url = CppCommon::Encoding::URLDecode(url);
                CppCommon::StringUtils::ReplaceFirst(url, "/api/v1/keys/", "");
                std::vector<std::string> url1 = CppCommon::StringUtils::Split(url, "/enc_keys");
                std::string SAE_ID = url1[0];
                qkdtypes::Status status;
                int number, size;
                json slave_IDs;
                if (StatusStorage::GetInstance().GetStatusValue(SAE_ID, status)) status = status;
                int default_size = status.getKey_Size();
                if (request.body_length() != 0)   //Ako POST request ima tijelo, onda pokupi iz njeg number, size i slave_IDs
                {
                   json data = json::parse(request.body());
                   number = data.value("number", 1);
                   size = data.value("size", default_size);
                   slave_IDs = data["additional_slave_SAE_IDs"];
                }
                else                             //Ako POST request nema tijelo, onda radi kao zahtjev sa default-nim parametrima
                {
                   number = 1;
                   size = default_size;
                }

                std::pair<std::string, std::string> KME_ID = std::make_pair(status.getSource_KME_ID(), status.getTarget_KME_ID());
                std::queue<uint8_t> raw_key, raw_key_additional,raw_key_1,key;
                RawKeyStorage::GetInstance().GetRawKeyValue(KME_ID, raw_key);
                if (size % 8 != 0)
                {
                   SendResponseAsync(response().MakeErrorResponse(400, "Size shall be a multiple of 8."));
                }
                else if (size * number > int(raw_key.size()) * 8)
                {
                   SendResponseAsync(response().MakeErrorResponse(400, "There is not enough key material for requested parameters."));
                }
                else
                {
                   qkdtypes::KeyContainer keyContainer, keyContainer1, keyContainer_additional;
                   std::string key_ID = "", encodedData;
                   for (int z = 0; z < number; z++) 
                   {       
                       for (int i = 0; i < size / 8; i++) 
                       {   
                            key.push(raw_key.front());
                            raw_key.pop();
                       }

                       GUID guid = { 0 };
                       char szGuid[36] = { 0 };
                       CoCreateGuid(&guid);
                       sprintf(szGuid, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
                       for (int j = 0; j < (sizeof(szGuid) / sizeof(char)); j++) 
                       {
                        key_ID = key_ID + szGuid[j];
                       }

                       encodedData = base64_encode(&key.front(), int(key.size()));

                       if (KeyStorage::GetInstance().GetKeyConteinerValue(status.getMaster_SAE_ID(), keyContainer)) keyContainer = keyContainer;
                       keyContainer.getKeys().push_back(qkdtypes::Key(key_ID, encodedData));
                       keyContainer1.getKeys().push_back(qkdtypes::Key(key_ID, encodedData));

                       for (int j = 0; j<int(key.size()); j++) //Praznjenje kljuca kako nove vrijednosti ne bi uticale na novi kljuc
                       {
                           key.pop();
                       }
                   }
                
                   RawKeyStorage::GetInstance().PutRawKeyValue(KME_ID, raw_key); //Azuriranje raw-key-a u storage-u
                   KeyStorage::GetInstance().PutKeyContainerValue(status.getMaster_SAE_ID(), keyContainer); //Azuriranje kljuceva u bazi kljuceva sa ID-evima
                   nlohmann::ordered_json jsonStatus = keyContainer1; //keyContainer1 (set key + key ID-eva  )se vraca kao odgovor
                   SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));

                   if (slave_IDs.size() != 0) //Ukoliko su definisani i dodatni ID-evi, upisuje kreirane kljuceve i za njih
                   {
                      for (int j = 0; j < slave_IDs.size(); j++)
                      {
                           qkdtypes::Status status_additional;
                           if (StatusStorage::GetInstance().GetStatusValue(slave_IDs[j], status_additional)) status_additional = status_additional;
                           if (KeyStorage::GetInstance().GetKeyConteinerValue(status_additional.getMaster_SAE_ID(), keyContainer_additional)) keyContainer_additional = keyContainer_additional;
                           keyContainer_additional.getKeys().push_back(qkdtypes::Key(key_ID, encodedData));
                           (KeyStorage::GetInstance().PutKeyContainerValue(status_additional.getMaster_SAE_ID(), keyContainer_additional));
                      }
                   }
                }                        
            }
            else if(url.find("/dec_keys") != std::string::npos)
            {
                url = CppCommon::Encoding::URLDecode(url);
                CppCommon::StringUtils::ReplaceFirst(url, "/api/v1/keys/", "");
                std::vector<std::string> url1 = CppCommon::StringUtils::Split(url, "/dec_keys");
                std::string SAE_ID = url1[0];
                qkdtypes::KeyContainer keyContainer, keyContainer1;
                json data = json::parse(request.body());
                json key_IDs = data["key_IDs"];
                bool exist_key_ID = false;

                if (KeyStorage::GetInstance().GetKeyConteinerValue(SAE_ID, keyContainer))
                {
                    keyContainer = keyContainer;
                    auto it = keyContainer.getKeys().begin();
                    for (int j = 0; j < key_IDs.size(); j++) //Za svaki key_ID iz tijela zahtjeva radi isto kao u slucaju GET zahtjeva kada je specificiran jedan ID
                    {
                        exist_key_ID = false;
                        for (auto i = keyContainer.getKeys().begin(); i != keyContainer.getKeys().end(); i++)
                        {
                            if (i->getKey_ID() == key_IDs[j])
                            {
                                exist_key_ID = true;
                                keyContainer1.getKeys().push_back(qkdtypes::Key(i->getKey(), i->getKey_ID()));
                                it = i;
                                break;
                            }
                        }
                        if (exist_key_ID == true) {
                            keyContainer.getKeys().erase(it);
                            KeyStorage::GetInstance().PutKeyContainerValue(SAE_ID, keyContainer);  //azurira bazu sa izbrisanim ID-em
                        }
                        else if (exist_key_ID == false)  //Cim nadje prvi da ne postoji, vraca odgovor da bar jedan key nije pronadjen
                        {
                            SendResponseAsync(response().MakeErrorResponse(400, "One or more keys specified are not found on KME."));
                        }
                    }
                    nlohmann::ordered_json jsonStatus = keyContainer1;
                    SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));
                }
                else //ukoliko se master_SAE_ID ne nalazi u KeyStorage-u jer prethodno nije bilo GetKeys zahtjeva?
                {
                    SendResponseAsync(response().MakeErrorResponse(400, "One or more keys specified are not found on KME."));
                }
            }
        }
        else if (request.method() == "OPTIONS")
            SendResponseAsync(response().MakeOptionsResponse());
        else if (request.method() == "TRACE")
            SendResponseAsync(response().MakeTraceResponse(request.cache()));
        else
            SendResponseAsync(response().MakeErrorResponse("Unsupported HTTP method: " + std::string(request.method())));
    }

    void onReceivedRequestError(const CppServer::HTTP::HTTPRequest& request, const std::string& error) override
    {
        std::cout << "Request error: " << error << std::endl;
    }

    void onError(int error, const std::string& category, const std::string& message) override
    {
        std::cout << "HTTPS session caught an error with code " << error << " and category '" << category << "': " << message << std::endl;
    }
};


class HTTPSQKDServer : public CppServer::HTTP::HTTPSServer
{
public:
    using CppServer::HTTP::HTTPSServer::HTTPSServer;

protected:
    std::shared_ptr<CppServer::Asio::SSLSession> CreateSession(const std::shared_ptr<CppServer::Asio::SSLServer>& server) override
    {
        return std::make_shared<HTTPSQKDSession>(std::dynamic_pointer_cast<CppServer::HTTP::HTTPSServer>(server));
    }

protected:
    void onError(int error, const std::string& category, const std::string& message) override
    {
        std::cout << "HTTPS server caught an error with code " << error << " and category '" << category << "': " << message << std::endl;
    }
};



int main(int argc, char** argv)
{
    StatusStorage::GetInstance().PutStatusValue("JJJJKKKKLLLL", { "AAAABBBBCCCC", "DDDDEEEEFFFF", "GGGGHHHHIIII", "JJJJKKKKLLLL", 8, 25000, 100000, 128, 1024, 64, 0});
    StatusStorage::GetInstance().PutStatusValue("JJKKLL", { "AABBCC", "DDEEFF", "GGHHII", "JJKKLL", 8, 25000, 100000, 128, 1024, 64, 0 });
    StatusStorage::GetInstance().PutStatusValue("JJJKKKLLL", { "AAABBBCCC", "DDDEEEFFF", "GGGHHHIII", "JJJKKKLLL", 8, 25000, 100000, 128, 1024, 64, 0 });

    std::pair<std::string, std::string> KME_IDs = { "AAAABBBBCCCC","DDDDEEEEFFFF" };
    std::queue<std::uint8_t> raw_key;
    raw_key.push(0b00000011);
    raw_key.push(0b01101010);
    raw_key.push(0b10001011);
    std::string x;
    RawKeyStorage::GetInstance().PutRawKeyValue(KME_IDs, raw_key);    
    // HTTPS server port
    int port = 8443;
    if (argc > 1)
        port = std::atoi(argv[1]);
    // HTTPS server content path
    std::string www = "./www/api/v1/keys";
    if (argc > 2)
        www = argv[2];

    std::cout << "HTTPS server port: " << port << std::endl;
    std::cout << "HTTPS server static content path: " << www << std::endl;
    std::cout << "HTTPS server website: " << "https://localhost:" << port << "/api/v1/keys/index.html" << std::endl;

    std::cout << std::endl;

    // Create a new Asio service
    auto service = std::make_shared<AsioService>();

    // Start the Asio service
    std::cout << "Asio service starting...";
    service->Start();
    std::cout << "Done!" << std::endl;

    // Create and prepare a new SSL server context
    auto context = std::make_shared<CppServer::Asio::SSLContext>(asio::ssl::context::tlsv12);
    context->set_password_callback([](size_t max_length, asio::ssl::context::password_purpose purpose) -> std::string { return "qwerty"; });
    context->use_certificate_chain_file("../CppServer/tools/certificates/server.pem");
    context->use_private_key_file("../CppServer/tools/certificates/server.pem", asio::ssl::context::pem);
    context->use_tmp_dh_file("../CppServer/tools/certificates/dh4096.pem");

    // Create a new HTTPS server
    //auto server = std::make_shared<HTTPSCacheServer>(service, context, port);
    auto server = std::make_shared<HTTPSQKDServer>(service, context, port);
    server->AddStaticContent(www, "/api/v1/keys");

    // Start the server
    std::cout << "Server starting...";
    server->Start();
    std::cout << "Done!" << std::endl;

    std::cout << "Press Enter to stop the server or '!' to restart the server..." << std::endl;

    // Perform text input
    std::string line;
    while (getline(std::cin, line))
    {
        if (line.empty())
            break;

        // Restart the server
        if (line == "!")
        {
            std::cout << "Server restarting...";
            server->Restart();
            std::cout << "Done!" << std::endl;
            continue;
        }
    }

    // Stop the server
    std::cout << "Server stopping...";
    server->Stop();
    std::cout << "Done!" << std::endl;

    // Stop the Asio service
    std::cout << "Asio service stopping...";
    service->Stop();
    std::cout << "Done!" << std::endl;

    return 0;
}
