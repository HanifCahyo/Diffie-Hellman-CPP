#include <iostream>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/dh.h>
#include <openssl/rand.h>
#include <openssl/err.h>   // For error handling

using namespace std;

int main() {
    cout << "Creating socket..." << endl;
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        cerr << "Failed to create socket." << endl;
        return -1;
    }

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);

    if (inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr) <= 0) {
        cerr << "Invalid address." << endl;
        close(clientSocket);
        return -1;
    }

    cout << "Connecting to server..." << endl;
    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1) {
        cerr << "Failed to connect to server." << endl;
        close(clientSocket);
        return -1;
    }

    cout << "Connected to server." << endl;

    // Generate client's Diffie-Hellman key pair
    // Gantikan pembuatan objek DH dengan menggunakan parameter standar
    DH* dh = DH_get_2048_256();
    if (!dh) {
        cerr << "Failed to create Diffie-Hellman object." << endl;
        close(clientSocket);
        return -1;
    }

    if (DH_generate_key(dh) != 1) {
        cerr << "Failed to generate DH key pair." << endl;
        DH_free(dh);
        close(clientSocket);
        return -1;
    }

    const BIGNUM *pub_key = nullptr;
    DH_get0_key(dh, &pub_key, nullptr);

    // Send client's public key to the server
    int pub_key_len = BN_num_bytes(pub_key);
    unsigned char *pub_key_bytes = new unsigned char[pub_key_len];
    BN_bn2bin(pub_key, pub_key_bytes);

    ssize_t sentBytes = send(clientSocket, pub_key_bytes, pub_key_len, 0);
    if (sentBytes == -1) {
        cerr << "Failed to send public key to server." << endl;
        delete[] pub_key_bytes;
        DH_free(dh);
        close(clientSocket);
        return -1;
    }

    cout << "Sent client's public key to server." << endl;

    // Receive server's public key
    unsigned char buffer[2048];
    ssize_t bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived <= 0) {
        cerr << "Failed to receive public key from server." << endl;
        delete[] pub_key_bytes;
        DH_free(dh);
        close(clientSocket);
        return -1;
    }
    cout << "Received server's public key." << endl;

    // Compute shared secret
    BIGNUM *server_pub_key = BN_bin2bn(buffer, bytesReceived, nullptr);
    unsigned char shared_secret[EVP_MAX_KEY_LENGTH];

    int secret_len = DH_compute_key(shared_secret, server_pub_key, dh);
    if (secret_len <= 0) {
        cerr << "Failed to compute shared secret." << endl;
        delete[] pub_key_bytes;
        DH_free(dh);
        close(clientSocket);
        return -1;
    }

    // Print shared secret for debugging
    cout << "Server's shared secret: ";
    for (int i = 0; i < secret_len; i++) {
        printf("%02x", shared_secret[i]);
    }
    cout << endl;

    cout << "Shared secret computed." << endl;

    // Encrypt a message using the shared secret
    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        cerr << "Failed to generate IV." << endl;
        delete[] pub_key_bytes;
        DH_free(dh);
        close(clientSocket);
        return -1;
    }

    EVP_CIPHER_CTX *encrypt_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(encrypt_ctx, EVP_aes_256_cbc(), nullptr, shared_secret, iv);

    unsigned char encrypted_message[128];
    int len, encrypted_len;
    if (EVP_EncryptUpdate(encrypt_ctx, encrypted_message, &len, (unsigned char *)"Hello, Server!", 15) != 1) {
        cerr << "Encryption failed during update." << endl;
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(encrypt_ctx);
        delete[] pub_key_bytes;
        DH_free(dh);
        close(clientSocket);
        return -1;
    }
    encrypted_len = len;

    if (EVP_EncryptFinal_ex(encrypt_ctx, encrypted_message + len, &len) != 1) {
        cerr << "Encryption failed during finalization." << endl;
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(encrypt_ctx);
        delete[] pub_key_bytes;
        DH_free(dh);
        close(clientSocket);
        return -1;
    }

    encrypted_len += len;

    // Send IV and encrypted message
    if (send(clientSocket, iv, sizeof(iv), 0) == -1) {
        cerr << "Failed to send IV." << endl;
        EVP_CIPHER_CTX_free(encrypt_ctx);
        delete[] pub_key_bytes;
        DH_free(dh);
        close(clientSocket);
        return -1;
    }

    if (send(clientSocket, encrypted_message, encrypted_len, 0) == -1) {
        cerr << "Failed to send encrypted message." << endl;
        EVP_CIPHER_CTX_free(encrypt_ctx);
        delete[] pub_key_bytes;
        DH_free(dh);
        close(clientSocket);
        return -1;
    }

    cout << "Sent encrypted message to server." << endl;

    // Cleanup
    EVP_CIPHER_CTX_free(encrypt_ctx);
    delete[] pub_key_bytes;
    DH_free(dh);
    close(clientSocket);

    return 0;
}
