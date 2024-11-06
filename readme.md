> g++ -o server server.cpp -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -Wno-deprecated-declarations

> ./server

> g++ -o client client.cpp -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -Wno-deprecated-declarations

> ./client

Kode ini adalah contoh sederhana dari komunikasi aman antara klien dan server menggunakan algoritma pertukaran kunci Diffie-Hellman (DH) untuk membentuk kunci bersama. Klien dan server ini bertukar kunci DH, kemudian menggunakan kunci bersama untuk enkripsi pesan menggunakan algoritma AES (Advanced Encryption Standard) dalam mode CBC (Cipher Block Chaining). Mari kita uraikan prosesnya secara bertahap:

Bagian Server

1. **Membuat Socket Server**:

- Server pertama kali membuat *socket* yang memungkinkan komunikasi jaringan di port 8080.
- *Socket* ini diikat ke alamat lokal dan port tertentu, lalu mendengarkan koneksi dari klien.

2. **Menunggu dan Menerima Koneksi dari Klien**:

- Server menunggu hingga klien mencoba terhubung, lalu menerima koneksi klien.

3. **Menerima Kunci Publik Klien**:

- Server menerima kunci publik dari klien (yaitu, bagian dari informasi kunci Diffie-Hellman klien) yang dikirimkan sebagai *byte array*.

4. **Membuat dan Mengirim Kunci Publik Server**:

- Server juga membuat pasangan kunci DH-nya sendiri.
- Kunci publik ini kemudian dikirimkan ke klien agar mereka berdua bisa membentuk kunci bersama.

5. **Menghitung Kunci Bersama**:

- Server dan klien menggunakan kunci publik yang diterima untuk menghitung kunci bersama yang nantinya digunakan untuk enkripsi dan dekripsi.

6. **Menerima IV (Initialization Vector) dan Pesan yang Terenkripsi**:

- Klien mengirimkan sebuah IV dan pesan terenkripsi ke server.
- IV digunakan sebagai bagian dari enkripsi AES CBC untuk memastikan bahwa pesan yang sama akan terlihat berbeda setiap kali dienkripsi.

7. **Mendekripsi Pesan**:

- Server menggunakan kunci bersama dan IV untuk mendekripsi pesan terenkripsi yang diterima dari klien dan mencetaknya.

Bagian Klien

1. **Membuat Socket Klien dan Terhubung ke Server**:

- Klien membuat *socket* dan mencoba terhubung ke server pada alamat IP tertentu (dalam hal ini, localhost "127.0.0.1" pada port 8080).

2. **Membuat dan Mengirim Kunci Publik Klien**:

- Klien juga membuat pasangan kunci DH-nya sendiri, lalu mengirim kunci publiknya ke server.

3. **Menerima Kunci Publik Server**:

- Klien menerima kunci publik dari server.

4. **Menghitung Kunci Bersama**:

- Sama seperti di server, klien menghitung kunci bersama menggunakan kunci publik server.

5. **Mengenkripsi Pesan**:

- Klien memilih pesan untuk dienkripsi, dalam hal ini "Hello, Server!".
- Klien membuat sebuah IV acak menggunakan RAND_bytes yang digunakan dalam enkripsi AES.
- Klien menggunakan kunci bersama dan IV untuk mengenkripsi pesan menggunakan AES-256 dalam mode CBC.

6. **Mengirim IV dan Pesan Terenkripsi ke Server**:

- Klien mengirimkan IV dan pesan terenkripsi ke server.

Konsep Kunci Utama

- **Diffie-Hellman (DH)**: Merupakan algoritma yang memungkinkan kedua pihak untuk membentuk kunci bersama meskipun mereka hanya berkomunikasi melalui jaringan yang mungkin tidak aman. Klien dan server menggunakan kunci DH untuk menghasilkan "shared secret" yang hanya mereka ketahui.
- **AES dalam Mode CBC**: AES adalah algoritma enkripsi, dan mode CBC menambahkan keamanan ekstra dengan menggunakan IV untuk memulai enkripsi. Karena IV berbeda-beda untuk setiap pesan, pesan yang sama akan terenkripsi menjadi *cipher text* yang berbeda setiap kali.

Tujuan dan Keamanan

Kode ini memungkinkan klien dan server untuk bertukar pesan dengan aman tanpa harus berbagi kunci sebelumnya. Bahkan jika ada pihak yang menguping komunikasi, mereka tidak akan bisa mengerti pesan yang dikirim karena mereka tidak tahu kunci bersama yang digunakan untuk enkripsi.
