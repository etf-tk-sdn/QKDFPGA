@echo off

rem Certificate Authority (CA)
..\..\modules\OpenSSL\VS\bin\openssl genrsa -passout pass:qwerty -out eve-ca-secret.key 4096
..\..\modules\OpenSSL\VS\bin\openssl rsa -passin pass:qwerty -in eve-ca-secret.key -out eve-ca.key
..\..\modules\OpenSSL\VS\bin\openssl req -new -x509 -days 3650 -subj "/C=BY/ST=Belarus/L=Minsk/O=Example root CA/OU=Example CA unit/CN=example.com" -key eve-ca.key -out eve-ca.crt
..\..\modules\OpenSSL\VS\bin\openssl pkcs12 -export -passout pass:qwerty -inkey eve-ca.key -in eve-ca.crt -out eve-ca.pfx
..\..\modules\OpenSSL\VS\bin\openssl pkcs12 -passin pass:qwerty -passout pass:qwerty -in eve-ca.pfx -out eve-ca.pem

rem SSL Client certificate
..\..\modules\OpenSSL\VS\bin\openssl genrsa -passout pass:qwerty -out eve-client-secret.key 4096
..\..\modules\OpenSSL\VS\bin\openssl rsa -passin pass:qwerty -in eve-client-secret.key -out eve-client.key
..\..\modules\OpenSSL\VS\bin\openssl req -new -subj "/C=BY/ST=Belarus/L=Minsk/O=Example client/OU=Example client unit/CN=client.example.com" -key eve-client.key -out eve-client.csr
..\..\modules\OpenSSL\VS\bin\openssl x509 -req -days 3650 -in eve-client.csr -CA eve-ca.crt -CAkey eve-ca.key -set_serial 01 -out eve-client.crt
..\..\modules\OpenSSL\VS\bin\openssl pkcs12 -export -passout pass:qwerty -inkey eve-client.key -in eve-client.crt -out eve-client.pfx
..\..\modules\OpenSSL\VS\bin\openssl pkcs12 -passin pass:qwerty -passout pass:qwerty -in eve-client.pfx -out eve-client.pem

rem Diffie–Hellman (D-H) key exchange
..\..\modules\OpenSSL\VS\bin\openssl dhparam -out eve-dh4096.pem 4096
