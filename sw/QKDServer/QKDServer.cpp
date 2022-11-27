/*!
    \file https_server.cpp
    \brief HTTPS server example
    \author Ivan Shynkarenka
    \date 30.04.2019
    \copyright MIT License
*/

#include "asio_service.h"
#include "json.hpp"

#include "server/http/https_server.h"
#include "string/string_utils.h"
#include "utility/singleton.h"

#include <iostream>
#include <map>
#include <mutex>

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

class StatusStorage : public CppCommon::Singleton<StatusStorage>
{
    friend CppCommon::Singleton<StatusStorage>;

public:
    bool GetStatusValue(std::string SAE_ID, qkdtypes::Status& value)
    {
        std::scoped_lock locker(_statusStorage_lock);
        auto it =_statusStorage.find(SAE_ID);     
        if (it != _statusStorage.end())
        {
            value = it->second;
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
        auto it = _keyStorage.emplace(SAE_ID, value);
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
 //  std::string ID{ "EEEEFFFFFGGGGHHHH" };
    std::map<std::string, qkdtypes::KeyContainer, std::less<>> _keyStorage;
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
            
            if (url.ends_with("/status")) 
            {
                std::string SAE_ID = CppCommon::Encoding::URLDecode(url);                     
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
                    if (url.find("size=") != std::string::npos && url.find("number=") != std::string::npos)
                    {
                        url = CppCommon::Encoding::URLDecode(url);
                        CppCommon::StringUtils::ReplaceFirst(url, "/api/v1/keys/", "");
                        CppCommon::StringUtils::ReplaceFirst(url, "/enc_keys?", "");
                        std::vector<std::string> url1 = CppCommon::StringUtils::Split(url, "number=");
                        std::string SAE_ID = url1[0];
                        std::vector<std::string> url2 = CppCommon::StringUtils::Split(url1[1], "&size=");
                        int number = std::stoi(url2[0]);
                        int size = std::stoi(url2[1]);
                        if (size % 8 != 0) 
                        {
                            SendResponseAsync(response().MakeErrorResponse(400, "Size shall be a multiple of 8."));
                        }
                        else 
                        {
                            qkdtypes::KeyContainer keyContainer;
                            KeyStorage::GetInstance().GetKeyConteinerValue(SAE_ID, keyContainer);
                            qkdtypes::KeyContainer keyContainer1;
                            for (auto i = keyContainer.getKeys().begin(); i != keyContainer.getKeys().end(); i++)
                            {
                                if (i->getKey().size() == size) keyContainer1.getKeys().push_back(*i);
                                if (keyContainer1.getKeys().size() == number) break;
                            }
                            nlohmann::ordered_json jsonStatus = keyContainer1;
                            SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));
                        }
                    }
                    else if (url.find("number=") != std::string::npos)
                    {
                        url = CppCommon::Encoding::URLDecode(url);
                        CppCommon::StringUtils::ReplaceFirst(url, "/api/v1/keys/", "");
                        CppCommon::StringUtils::ReplaceFirst(url, "/enc_keys?", "");
                        std::vector<std::string> url1 = CppCommon::StringUtils::Split(url, "number=");
                        std::string SAE_ID = url1[0];
                        int number = std::stoi(url1[1]);

                        qkdtypes::KeyContainer keyContainer;
                        KeyStorage::GetInstance().GetKeyConteinerValue(SAE_ID, keyContainer);
                        qkdtypes::KeyContainer keyContainer1 = keyContainer;
                        std::list<qkdtypes::Key> lista1 = keyContainer1.getKeys();
                        if (number < lista1.size())
                        {
                            lista1.resize(number);
                        }
                        nlohmann::ordered_json jsonStatus = lista1;
                        SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));                        
                    }
                    else if (url.find("size=") != std::string::npos)
                    {
                        url = CppCommon::Encoding::URLDecode(url);
                        CppCommon::StringUtils::ReplaceFirst(url, "/api/v1/keys/", "");
                        CppCommon::StringUtils::ReplaceFirst(url, "/enc_keys?", "");
                        std::vector<std::string> url1 = CppCommon::StringUtils::Split(url, "size=");
                        std::string SAE_ID = url1[0];
                        int size = std::stoi(url1[1]);
                        if (size % 8 != 0)
                        {
                            SendResponseAsync(response().MakeErrorResponse(400, "Size shall be a multiple of 8."));
                        }
                        else
                        {
                            qkdtypes::KeyContainer keyContainer, keyContainer1;
                            KeyStorage::GetInstance().GetKeyConteinerValue(SAE_ID, keyContainer);
                            for (auto i = keyContainer.getKeys().begin(); i != keyContainer.getKeys().end(); i++)
                            {
                                if (i->getKey().size() == size)
                                {
                                    keyContainer1.getKeys().push_back(*i);
                                    break;
                                }
                            }
                            nlohmann::ordered_json jsonStatus = keyContainer1;
                            SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));
                        }
                    }
                    else
                    {
                        url = CppCommon::Encoding::URLDecode(url);
                        CppCommon::StringUtils::ReplaceFirst(url, "/api/v1/keys/", "");
                        CppCommon::StringUtils::ReplaceFirst(url, "/enc_keys", "");
                        qkdtypes::KeyContainer keyContainer;
                        KeyStorage::GetInstance().GetKeyConteinerValue(url, keyContainer);
                        nlohmann::ordered_json jsonStatus = keyContainer;
                        SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));
                    }
            }  
        }
        else if ((request.method() == "POST"))
        {
            std::string key(request.url());
            if (key.find("/enc_keys") != std::string::npos){
            key = CppCommon::Encoding::URLDecode(key);
            CppCommon::StringUtils::ReplaceFirst(key, "/api/v1/keys/", "");
            std::vector<std::string> url1 = CppCommon::StringUtils::Split(key, "/enc_keys");
            std::string SAE_ID = url1[0];
            if (request.body_length() != 0) 
            {
                json data = json::parse(request.body());
                int number = data.value("number", 0);
                int size = data.value("size", 0);
                json slave_IDs = data["additional_slave_SAE_IDs"];

                if (number != 0 && size != 0 && slave_IDs.size() != 0)
                {
                    if (size % 8 != 0)
                    {
                        SendResponseAsync(response().MakeErrorResponse(400, "Size shall be a multiple of 8."));
                    }
                    else
                    {
                        qkdtypes::KeyContainer keyContainer;
                        KeyStorage::GetInstance().GetKeyConteinerValue(SAE_ID, keyContainer);
                        qkdtypes::KeyContainer keyContainer1;
                        for (auto i = keyContainer.getKeys().begin(); i != keyContainer.getKeys().end(); i++)
                        {   // (i->key.size())
                            if (i->getKey().size() == size) 
                            {
                                keyContainer1.getKeys().push_back(*i);
                                keyContainer.getKeys().erase(i);
                            }
                            if (keyContainer1.getKeys().size() == number) break;
                        }
                        for (int i = 0; i < slave_IDs.size(); i++) 
                        {
                           KeyStorage::GetInstance().PutKeyContainerValue(slave_IDs[i], keyContainer1);
                        }
                        nlohmann::ordered_json jsonStatus = keyContainer1;
                        SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));

                    }
                }
                else if (number != 0 && slave_IDs.size() != 0)
                {
                    qkdtypes::KeyContainer keyContainer;
                    KeyStorage::GetInstance().GetKeyConteinerValue(SAE_ID, keyContainer);
                    qkdtypes::KeyContainer keyContainer1 = keyContainer;
                    std::list<qkdtypes::Key> lista1 = keyContainer1.getKeys();
                    if (number < lista1.size())
                    {
                        lista1.resize(number);
                    }
                    for (int i = 0; i < slave_IDs.size(); i++)
                    {
                        KeyStorage::GetInstance().PutKeyContainerValue(slave_IDs[i], lista1);
                    }
                    nlohmann::ordered_json jsonStatus = lista1;
                    SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));
                }
                else if (size != 0 && slave_IDs.size() != 0)
                {
                    if (size % 8 != 0)
                    {
                        SendResponseAsync(response().MakeErrorResponse(400, "Size shall be a multiple of 8."));
                    }
                    else
                    {
                        qkdtypes::KeyContainer keyContainer, keyContainer1;
                        KeyStorage::GetInstance().GetKeyConteinerValue(SAE_ID, keyContainer);
                        for (auto i = keyContainer.getKeys().begin(); i != keyContainer.getKeys().end(); i++)
                        {
                            if (i->getKey().size() == size)
                            {
                                keyContainer1.getKeys().push_back(*i);
                                break;
                            }
                        }
                        for (int i = 0; i < slave_IDs.size(); i++)
                        {
                            KeyStorage::GetInstance().PutKeyContainerValue(slave_IDs[i], keyContainer1);
                        }
                        nlohmann::ordered_json jsonStatus = keyContainer1;
                        SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));
                    }
                }
                else if (number != 0 && size != 0) 
                {
                    CppServer::HTTP::HTTPRequest request1;
                    request1.SetBegin("GET", "/api/v1/keys/" + SAE_ID + "/enc_keys?number=" + std::to_string(number) + "&size=" + std::to_string(size));
                    onReceivedRequest(request1);
                }
                else if (number != 0)
                {
                    CppServer::HTTP::HTTPRequest request1;
                    request1.SetBegin("GET", "/api/v1/keys/" + SAE_ID + "/enc_keys?number=" + std::to_string(number));
                    onReceivedRequest(request1);
                }
                else if (size != 0)
                {
                    CppServer::HTTP::HTTPRequest request1;
                    request1.SetBegin("GET", "/api/v1/keys/" + SAE_ID + "/enc_keys?size=" + std::to_string(size));
                    onReceivedRequest(request1);
                }
                else if (slave_IDs.size() != 0)
                {
                    
                }                
            }
            else 
            {
                key = CppCommon::Encoding::URLDecode(key);
                CppCommon::StringUtils::ReplaceFirst(key, "/api/v1/keys/", "");
                CppCommon::StringUtils::ReplaceFirst(key, "/enc_keys", "");

                qkdtypes::KeyContainer keyContainer;
                KeyStorage::GetInstance().GetKeyConteinerValue(key, keyContainer);
                nlohmann::ordered_json jsonStatus = keyContainer;
                SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));
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
    StatusStorage::GetInstance().PutStatusValue("JJJJKKKKLLLL", { "AAAABBBBCCCC", "DDDDEEEEFFFF", "GGGGHHHHIIII", "JJJJKKKKLLLL", 512, 25000, 100000, 128, 1024, 64, 0});
    
    qkdtypes::KeyContainer keyContainer;
    keyContainer.getKeys().push_back(qkdtypes::Key("id1", "key1"));
    keyContainer.getKeys().push_back(qkdtypes::Key("id2", "key2"));
    keyContainer.getKeys().push_back(qkdtypes::Key("id3", "key33456"));
    KeyStorage::GetInstance().PutKeyContainerValue("JJJJKKKKLLLL", keyContainer);
    
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
