#include "asio_service.h"
#include "ServerAPI.h"
#include "HTTPSServer.h"
#include "AuthDBMemImpl.h"
#include "KeysDBMemImpl.h"
#include "StatusDBMemImpl.h"
#include <ctime>

int main(int argc, char** argv)
{

    //raw_key.push(3); raw_key.push(106); raw_key.push(139);
    std::queue<uint8_t> raw_key;
    srand((unsigned int)time(NULL)); //definisanje seed-a za random broj
    for (int i = 0; i < 1000000; i++)
    {
        raw_key.push(rand() % 255);  //brojevi moraju biti u opsegu 0-255
    }

    std::string pubkey =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyG7fNpmwFMip2daVMWle\n"
        "NfQ4djHJpAD3CY4PFL+CDU3MRwveQWyX04iOpInhRk8pTsPisWCqouBxmo14jprA\n"
        "Ov5XVEm4eHTcvxQ1UsUBPSzF3h1oUy2PuOnd803N1ja239z2jAMbdNwnihz9SoNT\n"
        "9i5wD3rDUK3vbUx1i8ixC/wX0RMIVb1RtE+dCbyhsiXTesotB2uqzd4cDl0gLBmD\n"
        "9+lOlPKA5Qx3bzFJAjr7YlPEBL7JCL+bj+fC2lX7Hbn3tj3fPtgHjuglIL26WM8K\n"
        "8OYDdM2fq2X0XfPTcJasqxxs3+Bw5P/7hXRx+Su2gEaNa0TlAwa+PL28TKmGYppP\n"
        "6mEKG97P/fR45Uw1Nv7SNFXP8awQ3T610ViLm+krj3AsE7hr5JwRCPbedQvHm2mr\n"
        "Q+onv6Xtm8PDzbuqpAHltUQWBmncdcByH42ugeGQmajwM/4hZVPpPhk7+67HFCUN\n"
        "/Qs1HX2KnJJ9M++sMt5Le6nk9bVoYSoKXwmlDPvBiT43gcL+ckk+QjbrpJ6hZFRd\n"
        "PAIJzjFSvsFbAi5Qaxam6J3OWiTq3wDqO/GnPFtFvtmpUc9iExRBy772u8mNb2Bn\n"
        "EPD2rDnw0bTxuWHkWIo6iQljl8z+PxLWtMyxBbcQpa46JrS6Tcdx2WpGSOGOdCpm\n"
        "Q+O2qe2B4u2+/GRJTP5bwQ8CAwEAAQ==\n"
        "-----END PUBLIC KEY-----\n";
    std::string pubkey1 =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmxV4hPJ63Klr4Kc3iM3D\n"
        "8XNF0yCxHhXOdA4KE8rH9OhLmnudD7aN7zOfZrMKJEDU2smwdijpYNouyPElU/JL\n"
        "wbvofA7whoEK6fR6DmgoReD5RUJbgBVy1ucJ7XFkGmv+1X41GmWKZYw+3NwbPSLK\n"
        "j7U0hq2tgGYkwKBVm3fbtkrQ/N/VvolNuGgZDuFQdWnEncPTH0h2bCNVPHwPa7ZI\n"
        "9OarhtDhRD0RhFcN+NxxUZpDS/y9AAYOhNDzWsUvgDc9hs1EMmo6OD+2Y/9824yJ\n"
        "n6myrQLHLf8iV0qTGXUdZjWHqNGZMQTxENkdZnkqlmJpC3c84n8kfrCPxbDzuQwv\n"
        "hpP23xDUbUYK9IJPtBKe9Dldu4SDtTZexFC9SVhChk1JFW5rKKhDWMyaY9qAr2if\n"
        "UgzRA88vcsIDPruF0WrPt/7fN41AIVGpAO/WgXPHAcpwQg8B79Rz/nvFiL1qC8KL\n"
        "wiGvjHF5B0mFw5Nmo+uZOJiVxlAGphpLaHLcn9E5InxZWgnROKWuxOPeiH1cfGVu\n"
        "m5Q2csnCkuV7rhP6Dg6Qffp0VHeb9Ud8KtLFdaOM1KHQQKzcGwnUUcdpGjm4CdCK\n"
        "ZBbrTZ3V6k9tGCP7QMAYgjIEf9oFfL1Ogp8K1WIhPBKrGcakcPzpG1sWR9HjRITX\n"
        "OY7bQgAeW9WlsNIPPTHdiUMCAwEAAQ==\n" //== prije \n
        "-----END PUBLIC KEY-----\n";
    std::string pubkey2 =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAu1uzDdTEkldkeT1Ajp5W\n"
        "6KoQNil32Ar8E1xbmNcAxnVFNAUfzS4I6WH4koxzl+z5Bb5calerqfnArW32Ymlp\n"
        "VDdpuEwLyamzmAS3KlaVyLjcN6kXuvghq0im0hvURj+JQOcOAgXYOx2bVrbtFt4f\n"
        "HJ2cw5BvvFWYzXTg5wRqjXDdi56yVYeTEsV75WX3pDAPMZ1Eh9rCWogimFVNek3E\n"
        "OWCYjVkmtPta+dGQZ8AkSijyZi5lJGgxiQfJVLOsni73U3mzaTXGak90I3g7qimI\n"
        "X10caAnBiAVEpdWyJ/sagKR10Abtf6c9xG4Rfd1hE2yZqlSoS0N7Dbz5w9X8oxoN\n"
        "7eYSWAC+dn4813XVWQSF+aBCl572RKD2NiMisG0TTDTB4DELaeBpk5I5CBh9Uduq\n"
        "qtbYESMYhfWYi0pA2Xm6IY44URJRpQUos7iFRmq2S4qyp3VtklDk7fntVdGmWwfR\n"
        "AeBofgc5p6Hoco4TLjHC1ph9+OXUjPe+p6z28zkt1YwsrKHlWw29u/FSFiriHgOH\n"
        "rRa2b7H1Xodzc+T6V33mqC3vH8BrG11D7Vj+KAwGtqu6LGUnYwhNMUaYGIxOdye6\n"
        "d4NJbSafUIEJi5k/pNz1NFvG6YWag5mbKNoGN7406BKti4P6zU0WGF0WJRewmtpD\n"
        "l2mkkQbR4lmGUp380t9nlokCAwEAAQ==\n"
        "-----END PUBLIC KEY-----\n";
    /*std::ifstream f("pubkey.txt"); //taking file as inputstream
    std::string pubkey;
    std::ostringstream ss;
    if (f) {
        ss << f.rdbuf(); // reading data
        pubkey = ss.str();
    }*/
    QKD::StatusEntry e = { "GGGGHHHHIIII", "JJJJKKKKLLLL", {"AAAABBBBCCCC", "DDDDEEEEFFFF", "GGGGHHHHIIII", "JJJJKKKKLLLL", 128, 25000, 100000, 128, 1024, 64, 0 }, raw_key};

    QKD::ServerAPI::GetInstance().SetAuthDB(new QKD::AuthDBMemImpl());
    QKD::ServerAPI::GetInstance().SetStatusDB(new QKD::StatusDBMemImpl());
    QKD::ServerAPI::GetInstance().SetKeysDB(new QKD::KeysDBMemImpl());

    QKD::ServerAPI::GetInstance().GetAuthDB()->PutAuthValue(pubkey, "JJJJKKKKLLLL");
    QKD::ServerAPI::GetInstance().GetAuthDB()->PutAuthValue(pubkey1, "GGGGHHHHIIII");
    QKD::ServerAPI::GetInstance().GetAuthDB()->PutAuthValue(pubkey2, "AAAA");
    QKD::ServerAPI::GetInstance().GetStatusDB()->PutStatusEntry(e);

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
    context->set_verify_mode(asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert);
    context->load_verify_file("../CppServer/tools/certificates/ca.pem");
  
    //context->set_verify_callback(asio::ssl::rfc2818_verification("*.example.com"));

    // Create a new HTTPS server
    auto server = std::make_shared<QKD::HTTPSServer>(service, context, port);
    server->AddStaticContent(www, "/api/v1/keys");
   // SSL_CTX_set_session_cache_mode(context->native_handle(), SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(context->native_handle(), SSL_OP_NO_TICKET);

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
