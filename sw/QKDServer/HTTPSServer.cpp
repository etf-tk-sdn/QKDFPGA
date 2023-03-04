#include "HTTPSServer.h"
#include "HTTPSSession.h"

std::shared_ptr<CppServer::Asio::SSLSession> QKD::HTTPSServer::CreateSession(const std::shared_ptr<CppServer::Asio::SSLServer>& server) 
{
    std::shared_ptr<CppServer::Asio::SSLSession> sslSession = std::make_shared<HTTPSSession>(std::dynamic_pointer_cast<CppServer::HTTP::HTTPSServer>(server));
    return sslSession;
}


void QKD::HTTPSServer::onError(int error, const std::string& category, const std::string& message) 
{
    std::cout << "HTTPS server caught an error with code " << error << " and category '" << category << "': " << message << std::endl;
}
