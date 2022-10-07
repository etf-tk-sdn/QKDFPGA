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
        // int stored_key_count{ 25000 };
        // int max_key_count{ 100000 };
        // int max_key_per_request{ 128 };
        // int max_key_size{ 1024 };
        // int min_key_size{ 64 };
        // int max_SAE_ID_count{ 0 };
    public:
        Status()
        {
        
        }
        Status(std::string source_KME_ID, std::string target_KME_ID, std::string master_SAE_ID, std::string slave_SAE_ID, int key_size)
        {
            this->source_KME_ID = source_KME_ID;
            this->target_KME_ID = target_KME_ID;
            this->master_SAE_ID = master_SAE_ID;
            this->slave_SAE_ID = slave_SAE_ID;
            this->key_size = key_size;
        }
        AS_JSON(Status, source_KME_ID, target_KME_ID, master_SAE_ID, slave_SAE_ID, key_size)
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
        AS_JSON(Key, key_ID, key)
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
}

class StatusStorage : public CppCommon::Singleton<StatusStorage>
{
    friend CppCommon::Singleton<StatusStorage>;

public:
    bool GetStatusValue(std::string SAE_ID, qkdtypes::Status& value)
    {
        std::scoped_lock locker(_statusStorage_lock);
        auto it =_statusStorage.find(SAE_ID);    //U prvim elementima mape _statusStorage, koji su stringovi, pronadji da li ima SAE_ID 
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
    std::string ID{ "EEEEFFFFFGGGGHHHH" };
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

    bool DeleteStatusValue(std::string SAE_ID, qkdtypes::KeyContainer value)
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
    std::string ID{ "EEEEFFFFFGGGGHHHH" };
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
            std::string key(request.url());
            std::string value;
            
            if (key.ends_with("/status")) 
            {
                key = CppCommon::Encoding::URLDecode(key);                     // Izdvaja key iz URL-a, tj u nasem slucaju SAE_ID
                CppCommon::StringUtils::ReplaceFirst(key, "/api/v1/keys/", "");
                CppCommon::StringUtils::ReplaceFirst(key, "/status", "");

                qkdtypes::Status status;

                if (StatusStorage::GetInstance().GetStatusValue(key, status))                   //Provjerava da li je postoji taj SAE_ID, ukoliko postoji vraca true (pogledati funkciju GetStatusValue)
                {                                                                           // I vraca status za taj SAE_ID
                    nlohmann::ordered_json jsonStatus = status;
                    SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));
                }
                else
                    SendResponseAsync(response().MakeErrorResponse(404, "Required cache value was not found for the key: " + key));
            }
            else if (key.ends_with("/key"))
            {
                key = CppCommon::Encoding::URLDecode(key);                     // Izdvaja key iz URL-a, tj u nasem slucaju SAE_ID
                CppCommon::StringUtils::ReplaceFirst(key, "/api/v1/keys/", "");
                CppCommon::StringUtils::ReplaceFirst(key, "/key", "");

                qkdtypes::KeyContainer keyContainer;
                KeyStorage::GetInstance().GetKeyConteinerValue(key, keyContainer);
                nlohmann::ordered_json jsonStatus = keyContainer;
                SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));
            }
            
        }
        else if ((request.method() == "POST") || (request.method() == "PUT"))
        {
            std::string key(request.url());
            std::string value(request.body());
            qkdtypes::Status status;

            // Decode the key value
            key = CppCommon::Encoding::URLDecode(key);
            CppCommon::StringUtils::ReplaceFirst(key, "/api/v1/cache", "");
            CppCommon::StringUtils::ReplaceFirst(key, "?key=", "");

            // Put the cache value
            StatusStorage::GetInstance().PutStatusValue(key, status);

            // Response with the cache value
            SendResponseAsync(response().MakeOKResponse());
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
    StatusStorage::GetInstance().PutStatusValue("JJJJKKKKLLLL", { "AAAABBBBCCCC", "DDDDEEEEFFFF", "GGGGHHHHIIII", "JJJJKKKKLLLL", 512});
    
    qkdtypes::KeyContainer keyContainer;
    keyContainer.getKeys().push_back(qkdtypes::Key("id1", "key1"));
    keyContainer.getKeys().push_back(qkdtypes::Key("id2", "key2"));
    keyContainer.getKeys().push_back(qkdtypes::Key("id3", "key3"));
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
