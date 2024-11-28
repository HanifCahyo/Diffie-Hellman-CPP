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
#include <openssl/err.h>

using namespace std;

int main() {`
    cout << "Creating socket..." << endl; // Print a message to the console
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0); // Create a new socket using IPv4 and TCP 
    if (clientSocket == -1) { // Check if the socket was created successfully
        cerr << "Failed to create socket." << endl;
        return -1;
    }

    sockaddr_in serverAddress; // Create a new sockaddr_in struct
    serverAddress.sin_family = AF_INET; // Set the address family to IPv4
    serverAddress.sin_port = htons(8080);  // Set the port to 8080
    inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr); // Set the IP address to localhost

    cout << "Connecting to server..." << endl; // Print a message to the console
    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1) { // Connect to the server
        cerr << "Failed to connect to server." << endl;
        close(clientSocket);
        return -1;
    }

    cout << "Connected to server." << endl;

    // Diffie-Hellman key exchange
    DH* dh = DH_get_2048_256(); // Create a new Diffie-Hellman key exchange object
    DH_generate_key(dh); // Generate the DH keys

    const BIGNUM *client_pub_key = nullptr; // Create a new BIGNUM pointer
    DH_get0_key(dh, &client_pub_key, nullptr); // Get the client's public key
    int pub_key_len = BN_num_bytes(client_pub_key); // Get the length of the public key
    unsigned char *client_pub_key_bytes = new unsigned char[pub_key_len]; // Create a new byte array to store the public key
    BN_bn2bin(client_pub_key, client_pub_key_bytes); // Convert the public key to bytes

    // Send client's public key to server
    send(clientSocket, client_pub_key_bytes, pub_key_len, 0); // Send the public key to the server

    // Receive server's public key
    unsigned char server_pub_key_bytes[2048]; // Create a new byte array to store the server's public key
    ssize_t bytesReceived = recv(clientSocket, server_pub_key_bytes, sizeof(server_pub_key_bytes), 0); // Receive the server's public key
    BIGNUM *server_pub_key = BN_bin2bn(server_pub_key_bytes, bytesReceived, nullptr); // Convert the server's public key to a BIGNUM

    // Compute shared secret
    unsigned char shared_secret[EVP_MAX_KEY_LENGTH]; // Create a new byte array to store the shared secret
    DH_compute_key(shared_secret, server_pub_key, dh); // Compute the shared secret using the server's public key and the DH object

    cout << "Shared secret computed." << endl; // Print a message to the console
    delete[] client_pub_key_bytes; // Delete the client's public key bytes

    // Main chat loop
    while (true) { // Loop until the user types "exit"
        // Get client message
        cout << "Client: "; // Print a message to the console
        string message; // Create a new string to store the message
        getline(cin, message); // Get a line of input from the user

        if (message == "exit") break;

        // Encrypt and send message
        unsigned char iv[EVP_MAX_IV_LENGTH]; // Create a new byte array to store the Initialization Vector
        RAND_bytes(iv, sizeof(iv)); // Generate a random IV
        EVP_CIPHER_CTX *encrypt_ctx = EVP_CIPHER_CTX_new(); // Create a new EVP cipher context
        EVP_EncryptInit_ex(encrypt_ctx, EVP_aes_256_cbc(), nullptr, s hared_secret, iv); // Initialize the encryption context

        unsigned char encrypted_message[128]; // Create a new byte array to store the encrypted message
        int encrypted_len; // Create a new integer to store the length of the message
        int len; // Create a new integer to store the length of the message
        EVP_EncryptUpdate(encrypt_ctx, encrypted_message, &len, (unsigned char*)message.c_str(), message.size()); // Encrypt the message
        encrypted_len = len; // Set the encrypted length

        EVP_EncryptFinal_ex(encrypt_ctx, encrypted_message + len, &len); // Finalize the encryption
        encrypted_len += len; // Update the encrypted length

        send(clientSocket, iv, sizeof(iv), 0); // Send the IV to the server
        send(clientSocket, encrypted_message, encrypted_len, 0); // Send the encrypted message to the server

        EVP_CIPHER_CTX_free(encrypt_ctx); // Free the encryption context

        // Receive and decrypt message from server
        unsigned char iv_in[EVP_MAX_IV_LENGTH]; // Create a new byte array to store the Initialization Vector
        ssize_t ivReceived = recv(clientSocket, iv_in, sizeof(iv_in), 0); // Receive the IV from the server
        if (ivReceived <= 0) break; // Check if the IV was received successfully

        unsigned char encrypted_in[128]; // Create a new byte array to store the encrypted message
        ssize_t encrypted_in_len = recv(clientSocket, encrypted_in, sizeof(encrypted_in), 0); // Receive the encrypted message from the server
        if (encrypted_in_len <= 0) break; // Check if the encrypted message was received successfully

        unsigned char decrypted_message[128]; // Create a new byte array to store the decrypted message
        EVP_CIPHER_CTX *decrypt_ctx = EVP_CIPHER_CTX_new(); // Create a new EVP cipher context
        EVP_DecryptInit_ex(decrypt_ctx, EVP_aes_256_cbc(), nullptr, shared_secret, iv_in); // Initialize the decryption context

        if (EVP_DecryptUpdate(decrypt_ctx, decrypted_message, &len, encrypted_in, encrypted_in_len) == 1) { // Decrypt the message
            int decrypted_len = len;    // Store the length of the decrypted message
            if (EVP_DecryptFinal_ex(decrypt_ctx, decrypted_message + len, &len) == 1) { // Finalize the decryption process
                decrypted_len += len; // Update the length of the decrypted message
                decrypted_message[decrypted_len] = '\0'; // Add a null terminator to the decrypted message
                cout << "Server: " << decrypted_message << endl; // Print the decrypted message to the console
            } 
        }
        EVP_CIPHER_CTX_free(decrypt_ctx);
    }

    // Cleanup
    DH_free(dh);
    close(clientSocket);

    return 0;
}
