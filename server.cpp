#include <iostream> // Include the necessary libraries
#include <cstring> // Include the necessary libraries
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

int main() { // Create the main function 
    cout << "Creating socket..." << endl; // Print a message to the console 
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0); // Create a new socket using IPv4 and TCP 
    if (serverSocket == -1) { // Check if the socket was created successfully 
        cerr << "Failed to create socket." << endl; // Print an error message
        return -1; // Return an error code
    }

    sockaddr_in serverAddress; // Create a new sockaddr_in struct
    serverAddress.sin_family = AF_INET; // Menentukan keluarga alamat sebagai AF_INET (IPv4).
    serverAddress.sin_port = htons(8080); // Menentukan port server (8080). Fungsi htons() digunakan untuk mengonversi port ke urutan byte yang benar.
    serverAddress.sin_addr.s_addr = INADDR_ANY; // Membuat server mendengarkan pada semua antarmuka jaringan yang tersedia.

    cout << "Binding socket..." << endl; // Print a message to the console
    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1) { // Bind the socket to the address
        cerr << "Failed to bind socket." << endl;  // Print an error message
        close(serverSocket);  // Close the socket
        return -1; 
    }

    cout << "Listening on port 8080..." << endl; // Print a message to the console
    if (listen(serverSocket, 1) == -1) { // Memulai server untuk mendengarkan koneksi masuk. Jumlah koneksi yang diizinkan adalah 1.
        cerr << "Failed to listen on socket." << endl; // Print an error message
        close(serverSocket);
        return -1;
    }

    sockaddr_in clientAddress; // Create a new sockaddr_in struct for the client address 
    socklen_t clientAddressLen = sizeof(clientAddress); // Get the size of the client address struct 
    cout << "Waiting for a connection..." << endl; // Print a message to the console 
    int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddressLen); // Accept a new connection from a client
    if (clientSocket == -1) { // Check if the connection was accepted successfully 
        cerr << "Failed to accept client connection." << endl;  // Print an error message
        close(serverSocket); // Close the server socket
        return -1;
    }

    cout << "Client connected!" << endl; // Print a message to the console 

    // Diffie-Hellman key exchange
    DH* dh = DH_get_2048_256(); // Create a new Diffie-Hellman key exchange object
    if (!dh || DH_generate_key(dh) != 1) { // Generate the DH keys
        cerr << "Failed to create or generate DH keys." << endl; // Print an error message
        close(clientSocket); 
        close(serverSocket); 
        return -1;
    }

    const BIGNUM *server_pub_key = nullptr; // Create a new BIGNUM pointer
    DH_get0_key(dh, &server_pub_key, nullptr); // Get the server's public key
    int pub_key_len = BN_num_bytes(server_pub_key); // Get the length of the public key
    unsigned char *server_pub_key_bytes = new unsigned char[pub_key_len]; // Create a new byte array to store the public key
    BN_bn2bin(server_pub_key, server_pub_key_bytes); // Convert the public key to bytes

    // Send server's public key to client
    send(clientSocket, server_pub_key_bytes, pub_key_len, 0); // Send the public key to the client

    // Receive client's public key
    unsigned char client_pub_key_bytes[2048]; // Create a new byte array to store the client's public key
    ssize_t bytesReceived = recv(clientSocket, client_pub_key_bytes, sizeof(client_pub_key_bytes), 0); // Receive the client's public key
    if (bytesReceived <= 0) { // Check if the public key was received successfully
        cerr << "Failed to receive public key from client." << endl; // Print an error message
        close(clientSocket); 
        close(serverSocket);
        return -1;
    }
    BIGNUM *client_pub_key = BN_bin2bn(client_pub_key_bytes, bytesReceived, nullptr); // Convert the client's public key to a BIGNUM

    // Compute shared secret
    unsigned char shared_secret[EVP_MAX_KEY_LENGTH]; // Create a new byte array to store the shared secret
    int secret_len = DH_compute_key(shared_secret, client_pub_key, dh); // Compute the shared secret using the client's public key and the DH object 
    if (secret_len <= 0) { // Check if the shared secret was computed successfully
        cerr << "Failed to compute shared secret." << endl; // Print an error message
        close(clientSocket);
        close(serverSocket);
        return -1;
    }

    cout << "Shared secret computed." << endl; // Print a message to the console 
    delete[] server_pub_key_bytes; // Delete the server's public key bytes 

    // Main chat loop
    while (true) {
        // Receive IV and encrypted message from client
        unsigned char iv[EVP_MAX_IV_LENGTH]; // Create a new byte array to store the  Initialization Vector
        ssize_t ivReceived = recv(clientSocket, iv, sizeof(iv), 0); // Receive the Initialization Vector from the client
        if (ivReceived <= 0) break; // Check if the IV was received successfully

        unsigned char encrypted_message[128]; // Create a new byte array to store the encrypted message
        ssize_t encrypted_len = recv(clientSocket, encrypted_message, sizeof(encrypted_message), 0); // Receive the encrypted message from the client
        if (encrypted_len <= 0) break; // Check if the encrypted message was received successfully

        // Decrypt the message
        unsigned char decrypted_message[128]; // Create a new byte array to store the decrypted message
        EVP_CIPHER_CTX *decrypt_ctx = EVP_CIPHER_CTX_new(); // Create a new EVP cipher context 
        EVP_DecryptInit_ex(decrypt_ctx, EVP_aes_256_cbc(), nullptr, shared_secret, iv); // Initialize the decryption context 
        int len, decrypted_len; // Create variables to store the length of the decrypted message

        if (EVP_DecryptUpdate(decrypt_ctx, decrypted_message, &len, encrypted_message, encrypted_len) == 1) { // Decrypt the message
            decrypted_len = len; // Store the length of the decrypted message
            if (EVP_DecryptFinal_ex(decrypt_ctx, decrypted_message + len, &len) == 1) { // Finalize the decryption process 
                decrypted_len += len; // Update the length of the decrypted message
                decrypted_message[decrypted_len] = '\0'; // Add a null terminator to the decrypted message
                cout << "Client: " << decrypted_message << endl; // Print the decrypted message to the console
            } 
        } 
        EVP_CIPHER_CTX_free(decrypt_ctx); // Free the decryption context

        // Get server message and send to client
        cout << "Server: "; // Print a message to the console 
        string message; // Create a new string to store the message 
        getline(cin, message); 

        if (message == "exit") break; // Check if the user wants to exit

        // Encrypt and send the server message to the client
        unsigned char iv_out[EVP_MAX_IV_LENGTH]; // Create a new byte array to store the Initialization Vector
        RAND_bytes(iv_out, sizeof(iv_out)); // Generate a random IV 
        EVP_CIPHER_CTX *encrypt_ctx = EVP_CIPHER_CTX_new(); // Create a new EVP cipher context 
        EVP_EncryptInit_ex(encrypt_ctx, EVP_aes_256_cbc(), nullptr, shared_secret, iv_out); // Initialize the encryption context

        unsigned char encrypted_out[128]; // Create a new byte array to store the encrypted message
        int encrypted_out_len; // Create a variable to store the length of the encrypted message
        EVP_EncryptUpdate(encrypt_ctx, encrypted_out, &len, (unsigned char*)message.c_str(), message.size()); // Encrypt the message
        encrypted_out_len = len; // Store the length of the encrypted message

        EVP_EncryptFinal_ex(encrypt_ctx, encrypted_out + len, &len); // Finalize the encryption
        encrypted_out_len += len; // Update the length of the encrypted message

        send(clientSocket, iv_out, sizeof(iv_out), 0); // Send the IV to the client
        send(clientSocket, encrypted_out, encrypted_out_len, 0); // Send the encrypted message to the client

        EVP_CIPHER_CTX_free(encrypt_ctx); // Free the encryption context
    } 

    // Cleanup
    DH_free(dh); // Free the DH object
    close(clientSocket); // Close the client socket
    close(serverSocket); // Close the server socket

    return 0;
}
