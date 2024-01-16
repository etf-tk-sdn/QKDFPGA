#include "HTTPSSession.h"
#include "ServerAPI.h"
#include "string/string_utils.h"
#include <algorithm>

std::string QKD::HTTPSSession::EVP_PKEY_to_PEM(EVP_PKEY* key) {

	BIO* bio = NULL;
	char* pem = NULL;

	if (NULL == key) {
		return NULL;
	}

	bio = BIO_new(BIO_s_mem());
	if (NULL == bio) {
		return NULL;
	}

	if (0 == PEM_write_bio_PUBKEY(bio, key)) {
		BIO_free(bio);
		return NULL;
	}

	pem = (char*)malloc(BIO_number_written(bio) + 1);
	if (NULL == pem) {
		BIO_free(bio);
		return NULL;
	}

	memset(pem, 0, BIO_number_written(bio) + 1);
	BIO_read(bio, pem, int(BIO_number_written(bio)));
	BIO_free(bio);
	return pem;
}

std::string QKD::HTTPSSession::getCallerPublicKey() {
	std::string callerPublicKey = "";
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	this->stream().handshake(asio::ssl::stream<asio::ip::tcp::socket>::client);
	X509* cert = SSL_get_peer_certificate(this->stream().native_handle());
	//BIO* bp = BIO_new_fp(stdout, BIO_NOCLOSE);

	if (cert) {
		if (SSL_get_verify_result(this->stream().native_handle()) == X509_V_OK) {
			EVP_PKEY* pubkey = X509_get_pubkey(cert);
			if (pubkey) {
				switch (EVP_PKEY_id(pubkey)) {
				case EVP_PKEY_RSA:
					//BIO_printf(bp, "%d bit RSA Key\n\n", EVP_PKEY_bits(pubkey));
					break;
				case EVP_PKEY_DSA:
					//BIO_printf(bp, "%d bit DSA Key\n\n", EVP_PKEY_bits(pubkey));
					break;
				default:
					//BIO_printf(bp, "%d bit non-RSA/DSA Key\n\n", EVP_PKEY_bits(pubkey));
					break;
				}
			}

			callerPublicKey = EVP_PKEY_to_PEM(pubkey);
			EVP_PKEY_free(pubkey);
		}
	}

	return callerPublicKey;
}

void QKD::HTTPSSession::onReceivedRequest(const CppServer::HTTP::HTTPRequest& request)
{
	asio::socket_base::send_buffer_size sbs(8192000);
	asio::socket_base::receive_buffer_size rbs(8192000);
	this->stream().lowest_layer().set_option(sbs);
	this->stream().lowest_layer().set_option(rbs);

	/*if (this->option_send_buffer_limit() != 0)
		std::cout << "option_send_buffer_limit = " << this->option_send_buffer_limit() << std::endl;*/
	/*if (this->option_send_buffer_size() != 0)
		std::cout << "option_send_buffer_size = " << this->option_send_buffer_size() << std::endl;*/
	/*if (this->server()->option_no_delay() != 0)
		std::cout << "option_no_delay = " << this->server()->option_no_delay() << std::endl;
	std::cout << "----------------------------------------------------" << std::endl;*/

	/*if (!this->server()->option_no_delay())
		this->server()->SetupNoDelay(true);*/
	/*asio::socket_base::send_buffer_size option(1000000);
	this->socket().set_option(option);*/

	if (callerSAEId == "")
	{
		callerSAEId = ServerAPI::GetInstance().GetSAEID(getCallerPublicKey());
	}

	if (callerSAEId == "")
	{
		SendResponseAsync(response().MakeErrorResponse(401, "Unauthorized"));
		return;
	}

	// Show HTTP request content
	//std::cout << std::endl << request;

	// Process HTTP request methods
	if (request.method() == "HEAD")
		SendResponseAsync(response().MakeHeadResponse());
	else if (request.method() == "GET")
	{
		std::string url(request.url());
		std::string SAE_ID;
		unsigned long int number = 1, size = 0;

		if (url.ends_with("/status"))
		{
			SAE_ID = CppCommon::Encoding::URLDecode(url);    //GetStatus - Slave_SAE_ID u URL
			CppCommon::StringUtils::ReplaceFirst(SAE_ID, "/api/v1/keys/", "");
			CppCommon::StringUtils::ReplaceFirst(SAE_ID, "/status", "");

			Status* status;
			int Status_Response = ServerAPI::GetInstance().GetStatus(SAE_ID, callerSAEId, &status);

			switch (Status_Response) {
			case ServerAPI::RESPONSE_NOT_FOUND:
				SendResponseAsync(response().MakeErrorResponse(404, "Required Status value was not found for the SAE ID: " + SAE_ID));
				delete status;
				break;
			case ServerAPI::RESPONSE_UNAUTHORIZED:
				SendResponseAsync(response().MakeErrorResponse(401, "Unauthorized"));
				delete status;
				break;
			case ServerAPI::RESPONSE_OK:
				nlohmann::ordered_json jsonStatus = *status;
				SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));
				delete status;
			}
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
			}
			else if (url.find("size=") != std::string::npos)
			{
				std::vector<std::string> url1 = CppCommon::StringUtils::Split(url, "?size=");
				SAE_ID = url1[0];
				size = std::stoi(url1[1]);
			}
			else //Ukoliko nisu zadani ni size ni number, uzimaju se defaultne vrijednosti - 1 kljuc, velicine Key_Size definisane u Status-u
			{
				SAE_ID = url;
			}

			GetKeysRequest getKeyRequest = { SAE_ID,number,size };

			KeyContainer* keyContainer;
			int GetKeys_Response = ServerAPI::GetInstance().GetKeys(callerSAEId, getKeyRequest, &keyContainer);
			switch (GetKeys_Response) {
			case ServerAPI::RESPONSE_NOT_FOUND:
				SendResponseAsync(response().MakeErrorResponse(404, "Required Key value was not found for the SAE ID: " + SAE_ID));
				delete keyContainer;
				break;
			case ServerAPI::RESPONSE_UNAUTHORIZED:
				SendResponseAsync(response().MakeErrorResponse(401, "Unauthorized"));
				delete keyContainer;
				break;
			case ServerAPI::RESPONSE_SIZE_SHALL_BE_MULTIPLE_OF_8:
				SendResponseAsync(response().MakeErrorResponse(400, "Size shall be a multiple of 8."));
				delete keyContainer;
				break;
			case ServerAPI::RESPONSE_NOT_ENOUGH_MATERIAL:
				SendResponseAsync(response().MakeErrorResponse(400, "There is not enough key material for requested parameters."));
				delete keyContainer;
				break;
			case ServerAPI::RESPONSE_OK:
				nlohmann::ordered_json jsonStatus = *keyContainer;
				CppServer::HTTP::HTTPResponse resp = response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8");
				SendResponseAsync(resp);
				/*std::cout << "=============" << std::endl;
				std::cout << "SIZE = " << resp.cache().size() << std::endl;
				std::cout << "-------------" << std::endl;
				std::cout << resp.cache() << std::endl;
				std::cout << "-------------" << std::endl;
				std::string rawdata = resp.cache();
				std::replace(rawdata.begin(), rawdata.end(), '\r', 'R');
				std::replace(rawdata.begin(), rawdata.end(), '\n', 'N');
				std::cout << rawdata << std::endl;*/
				delete keyContainer;
			}
		}
		else if (url.find("/dec_keys") != std::string::npos)
		{
			url = CppCommon::Encoding::URLDecode(url);
			CppCommon::StringUtils::ReplaceFirst(url, "/api/v1/keys/", "");
			CppCommon::StringUtils::ReplaceFirst(url, "/dec_keys?", "");
			std::vector<std::string> url1 = CppCommon::StringUtils::Split(url, "key_ID=");
			SAE_ID = url1[0];
			json key_ID_url = { url1[1] }; //definisano kao json i niz da bi se moglo indeksirati, i raditi i sa POST metodom kada moze biti definisano vise ID-eva

			GetKeysWithIDRequest getKeyWithIDRequest = { SAE_ID, key_ID_url };
			KeyContainer* keyContainer;
			int GetKeysWithID_Response = ServerAPI::GetInstance().GetKeysWithId(callerSAEId, getKeyWithIDRequest, &keyContainer);

			switch (GetKeysWithID_Response) {
			case ServerAPI::RESPONSE_NOT_FOUND:
				SendResponseAsync(response().MakeErrorResponse(404, "Required Key value was not found for the SAE ID: " + SAE_ID));
				delete keyContainer;
				break;
			case ServerAPI::RESPONSE_UNAUTHORIZED:
				SendResponseAsync(response().MakeErrorResponse(401, "Unauthorized"));
				delete keyContainer;
				break;
			case ServerAPI::RESPONSE_OK:
				nlohmann::ordered_json jsonStatus = *keyContainer;
				SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));
				delete keyContainer;
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
			Status status;
			unsigned long int number = 0, size = 0, default_size = 0;
			json slave_IDs, data;

			if (request.body_length() != 0)   //Ako POST request ima tijelo, onda pokupi iz njeg number, size i slave_IDs
			{
				data = json::parse(request.body());
				number = data.value("number", 1);
				size = data.value("size", default_size);
				slave_IDs = data["additional_slave_SAE_IDs"];
			}

			GetKeysRequest getKeyRequest = { SAE_ID,number,size,slave_IDs };
			KeyContainer* keyContainer;
			int GetKeys_Response = ServerAPI::GetInstance().GetKeys(callerSAEId, getKeyRequest, &keyContainer);

			switch (GetKeys_Response) {
			case ServerAPI::RESPONSE_NOT_FOUND:
				SendResponseAsync(response().MakeErrorResponse(404, "Required Key value was not found for the SAE ID: " + SAE_ID));
				delete keyContainer;
				break;
			case ServerAPI::RESPONSE_UNAUTHORIZED:
				SendResponseAsync(response().MakeErrorResponse(401, "Unauthorized"));
				delete keyContainer;
				break;
			case ServerAPI::RESPONSE_SIZE_SHALL_BE_MULTIPLE_OF_8:
				SendResponseAsync(response().MakeErrorResponse(400, "Size shall be a multiple of 8."));
				delete keyContainer;
				break;
			case ServerAPI::RESPONSE_NOT_ENOUGH_MATERIAL:
				SendResponseAsync(response().MakeErrorResponse(400, "There is not enough key material for requested parameters."));
				delete keyContainer;
				break;
			case ServerAPI::RESPONSE_OK:
				nlohmann::ordered_json jsonStatus = *keyContainer;
				SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));
			}
		}
		else if (url.find("/dec_keys") != std::string::npos)
		{
			url = CppCommon::Encoding::URLDecode(url);
			CppCommon::StringUtils::ReplaceFirst(url, "/api/v1/keys/", "");
			std::vector<std::string> url1 = CppCommon::StringUtils::Split(url, "/dec_keys");
			std::string SAE_ID = url1[0];
			//KeyContainer keyContainer;
			json data = json::parse(request.body());
			json key_IDs = data["key_IDs"];

			GetKeysWithIDRequest getKeyWithIDRequest = { SAE_ID, {key_IDs} };
			KeyContainer* keyContainer;
			int GetKeysWithID_Response = ServerAPI::GetInstance().GetKeysWithId(callerSAEId, getKeyWithIDRequest, &keyContainer);

			switch (GetKeysWithID_Response) {
			case ServerAPI::RESPONSE_NOT_FOUND:
				SendResponseAsync(response().MakeErrorResponse(404, "Required Key value was not found for the SAE ID: " + SAE_ID));
				delete keyContainer;
				break;
			case ServerAPI::RESPONSE_UNAUTHORIZED:
				SendResponseAsync(response().MakeErrorResponse(401, "Unauthorized"));
				delete keyContainer;
				break;
			case ServerAPI::RESPONSE_OK:
				nlohmann::ordered_json jsonStatus = *keyContainer;
				SendResponseAsync(response().MakeGetResponse(jsonStatus.dump(), "application/json; charset=UTF-8"));
				delete keyContainer;
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

void QKD::HTTPSSession::onReceivedRequestError(const CppServer::HTTP::HTTPRequest& request, const std::string& error)
{
	std::cout << "Request error: " << error << std::endl;
}

void QKD::HTTPSSession::onError(int error, const std::string& category, const std::string& message)
{
	std::cout << "HTTPS session caught an error with code " << error << " and category '" << category << "': " << message << std::endl;
}
