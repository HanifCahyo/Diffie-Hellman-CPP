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
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        cerr << "Failed to create socket." << endl;
        return -1;
    }

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    cout << "Binding socket..." << endl;
    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1) {
        cerr << "Failed to bind socket." << endl;
        close(serverSocket);
        return -1;
    }

    cout << "Listening on port 8080..." << endl;
    if (listen(serverSocket, 1) == -1) {
        cerr << "Failed to listen on socket." << endl;
        close(serverSocket);
        return -1;
    }

    sockaddr_in clientAddress;
    socklen_t clientAddressLen = sizeof(clientAddress);
    cout << "Waiting for a connection..." << endl;
    int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddressLen);
    if (clientSocket == -1) {
        cerr << "Failed to accept client connection." << endl;
        close(serverSocket);
        return -1;
    }

    cout << "Client connected!" << endl;

    // Receive client's public key
    unsigned char buffer[2048];
    ssize_t bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived <= 0) {
        cerr << "Failed to receive public key from client." << endl;
        close(clientSocket);
        close(serverSocket);
        return -1;
    }
    cout << "Received public key from client." << endl;

    // Generate server's Diffie-Hellman key pair
    DH* dh = DH_get_2048_256();
    if (!dh) {
        cerr << "Failed to create Diffie-Hellman object." << endl;
        close(clientSocket);
        close(serverSocket);
        return -1;
    }

    if (DH_generate_key(dh) != 1) {
        cerr << "Failed to generate DH key pair." << endl;
        DH_free(dh);
        close(clientSocket);
        close(serverSocket);
        return -1;
    }

    const BIGNUM *pub_key = nullptr;
    DH_get0_key(dh, &pub_key, nullptr);

    // Send server's public key to client
    int pub_key_len = BN_num_bytes(pub_key);
    unsigned char *pub_key_bytes = new unsigned char[pub_key_len];
    BN_bn2bin(pub_key, pub_key_bytes);

    ssize_t sentBytes = send(clientSocket, pub_key_bytes, pub_key_len, 0);
    if (sentBytes == -1) {
        cerr << "Failed to send public key to client." << endl;
        delete[] pub_key_bytes;
        DH_free(dh);
        close(clientSocket);
        close(serverSocket);
        return -1;
    }

    cout << "Sent server's public key to client." << endl;

    // Compute shared secret
    BIGNUM *client_pub_key = BN_bin2bn(buffer, bytesReceived, nullptr);
    unsigned char shared_secret[EVP_MAX_KEY_LENGTH];

    int secret_len = DH_compute_key(shared_secret, client_pub_key, dh);
    if (secret_len <= 0) {
        cerr << "Failed to compute shared secret." << endl;
        delete[] pub_key_bytes;
        DH_free(dh);
        close(clientSocket);
        close(serverSocket);
        return -1;
    }

    // Print shared secret for debugging
    cout << "Client's shared secret: ";
    for (int i = 0; i < secret_len; i++) {
        printf("%02x", shared_secret[i]);
    }
    cout << endl;

    cout << "Shared secret computed." << endl;

    // Receive IV and encrypted message
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char encrypted_message[128];

    ssize_t ivReceived = recv(clientSocket, iv, sizeof(iv), 0);
    if (ivReceived <= 0) {
        cerr << "Failed to receive IV from client." << endl;
        delete[] pub_key_bytes;
        DH_free(dh);
        close(clientSocket);
        close(serverSocket);
        return -1;
    }

    ssize_t encrypted_len = recv(clientSocket, encrypted_message, sizeof(encrypted_message), 0);
    if (encrypted_len <= 0) {
        cerr << "Failed to receive encrypted message from client." << endl;
        delete[] pub_key_bytes;
        DH_free(dh);
        close(clientSocket);
        close(serverSocket);
        return -1;
    }

    // Decrypt the message using the shared secret and received IV
    unsigned char decrypted_message[128];
    EVP_CIPHER_CTX *decrypt_ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(decrypt_ctx, EVP_aes_256_cbc(), nullptr, shared_secret, iv);

    int len, decrypted_len;
    if (EVP_DecryptUpdate(decrypt_ctx, decrypted_message, &len, encrypted_message, encrypted_len) != 1) {
        cerr << "Decryption failed during update." << endl;
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(decrypt_ctx);
        delete[] pub_key_bytes;
        DH_free(dh);
        close(clientSocket);
        close(serverSocket);
        return -1;
    }
    decrypted_len = len;

    if (EVP_DecryptFinal_ex(decrypt_ctx, decrypted_message + len, &len) != 1) {
        cerr << "Decryption failed during finalization." << endl;
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(decrypt_ctx);
        delete[] pub_key_bytes;
        DH_free(dh);
        close(clientSocket);
        close(serverSocket);
        return -1;
    }

    decrypted_len += len;
    decrypted_message[decrypted_len] = '\0'; // Null-terminate decrypted message

    cout << "Decrypted message: " << decrypted_message << endl;

    // Cleanup
    EVP_CIPHER_CTX_free(decrypt_ctx);
    delete[] pub_key_bytes;
    DH_free(dh);
    close(clientSocket);
    close(serverSocket);

    return 0;
}
