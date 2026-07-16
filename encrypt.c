#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <libgen.h>
#include <limits.h>

#define KEY_SIZE 32
#define IV_SIZE 12
#define SALT_SIZE 16
#define TAG_SIZE 16
#define BUFFER_SIZE 65536
#define MAGIC "ENC1"

// ================= GLOBAL =================
char SELF_PATH[PATH_MAX] = {0};
char SELF_NAME[256] = {0};

// ================= UTIL =================

int is_dot_or_system(const char *name) {
    return (!strcmp(name, ".") || !strcmp(name, ".."));
}

int is_enc_file(const char *name) {
    return strstr(name, ".enc") != NULL;
}

int is_self(const char *path) {
    char real[PATH_MAX];
    if (!realpath(path, real)) return 0;
    return strcmp(real, SELF_PATH) == 0;
}

// ================= KEY =================

int derive_key(const char *password, unsigned char *salt, unsigned char *key) {
    int result = PKCS5_PBKDF2_HMAC(
        password,
        strlen(password),
        salt,
        SALT_SIZE,
        100000,
        EVP_sha256(),
        KEY_SIZE,
        key
    );
    
    if (result != 1) {
        fprintf(stderr, "PBKDF2 failed\n");
        return 0;
    }
    return 1;
}

// ================= ENCRYPT =================

int encrypt_file(const char *filename, const char *password) {
    if (is_enc_file(filename)) return 0;
    if (is_self(filename)) return 0;

    FILE *in = fopen(filename, "rb");
    if (!in) {
        perror("Cannot open input file");
        return 0;
    }

    char outname[512];
    snprintf(outname, sizeof(outname), "%s.enc", filename);

    FILE *out = fopen(outname, "wb");
    if (!out) {
        perror("Cannot create output file");
        fclose(in);
        return 0;
    }

    unsigned char salt[SALT_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char key[KEY_SIZE];

    // Generate random salt and IV
    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        fprintf(stderr, "RAND_bytes failed for salt\n");
        fclose(in);
        fclose(out);
        return 0;
    }
    
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        fprintf(stderr, "RAND_bytes failed for IV\n");
        fclose(in);
        fclose(out);
        return 0;
    }

    // Derive key from password and salt
    if (!derive_key(password, salt, key)) {
        fclose(in);
        fclose(out);
        return 0;
    }

    // Write header: Magic(4) + Salt(16) + IV(12)
    fwrite(MAGIC, 1, 4, out);
    fwrite(salt, 1, SALT_SIZE, out);
    fwrite(iv, 1, IV_SIZE, out);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        fclose(in);
        fclose(out);
        return 0;
    }
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 0;
    }
    
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex (key/iv) failed\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 0;
    }

    unsigned char inbuf[BUFFER_SIZE];
    unsigned char outbuf[BUFFER_SIZE + 32];
    int len, outlen;

    // Encrypt data
    while ((len = fread(inbuf, 1, BUFFER_SIZE, in)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, len) != 1) {
            fprintf(stderr, "EVP_EncryptUpdate failed\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 0;
        }
        fwrite(outbuf, 1, outlen, out);
    }

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 0;
    }
    fwrite(outbuf, 1, outlen, out);

    // Get authentication tag
    unsigned char tag[TAG_SIZE];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl (get tag) failed\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 0;
    }
    fwrite(tag, 1, TAG_SIZE, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    // Remove original file
    if (remove(filename) != 0) {
        perror("Warning: Could not remove original file");
    }

    printf("[+] Encrypted: %s\n", filename);
    return 1;
}

// ================= DECRYPT =================

int decrypt_file(const char *filename, const char *password) {
    if (!is_enc_file(filename)) return 0;

    FILE *in = fopen(filename, "rb");
    if (!in) {
        perror("Cannot open encrypted file");
        return 0;
    }

    // Create output filename (remove .enc extension)
    char outname[512];
    size_t len = strlen(filename);
    if (len < 4) {
        fclose(in);
        return 0;
    }
    strncpy(outname, filename, len - 4);
    outname[len - 4] = '\0';

    FILE *out = fopen(outname, "wb");
    if (!out) {
        perror("Cannot create output file");
        fclose(in);
        return 0;
    }

    // Read and verify magic
    char magic[5] = {0};
    if (fread(magic, 1, 4, in) != 4) {
        fprintf(stderr, "Cannot read magic bytes from %s\n", filename);
        fclose(in);
        fclose(out);
        return 0;
    }

    if (strncmp(magic, MAGIC, 4) != 0) {
        fprintf(stderr, "Invalid magic bytes in %s\n", filename);
        fclose(in);
        fclose(out);
        remove(outname);
        return 0;
    }

    // Read salt and IV
    unsigned char salt[SALT_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char key[KEY_SIZE];

    if (fread(salt, 1, SALT_SIZE, in) != SALT_SIZE) {
        fprintf(stderr, "Cannot read salt from %s\n", filename);
        fclose(in);
        fclose(out);
        remove(outname);
        return 0;
    }

    if (fread(iv, 1, IV_SIZE, in) != IV_SIZE) {
        fprintf(stderr, "Cannot read IV from %s\n", filename);
        fclose(in);
        fclose(out);
        remove(outname);
        return 0;
    }

    // Derive key from password and salt
    if (!derive_key(password, salt, key)) {
        fclose(in);
        fclose(out);
        remove(outname);
        return 0;
    }

    // Get file size
    fseek(in, 0, SEEK_END);
    long file_size = ftell(in);
    fseek(in, 4 + SALT_SIZE + IV_SIZE, SEEK_SET);

    long encrypted_data_size = file_size - (4 + SALT_SIZE + IV_SIZE + TAG_SIZE);
    
    if (encrypted_data_size < 0) {
        fprintf(stderr, "Corrupted file: %s\n", filename);
        fclose(in);
        fclose(out);
        remove(outname);
        return 0;
    }

    // Read authentication tag
    unsigned char tag[TAG_SIZE];
    fseek(in, file_size - TAG_SIZE, SEEK_SET);
    if (fread(tag, 1, TAG_SIZE, in) != TAG_SIZE) {
        fprintf(stderr, "Cannot read tag from %s\n", filename);
        fclose(in);
        fclose(out);
        remove(outname);
        return 0;
    }

    // Go back to start of encrypted data
    fseek(in, 4 + SALT_SIZE + IV_SIZE, SEEK_SET);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        fclose(in);
        fclose(out);
        remove(outname);
        return 0;
    }

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "EVP_DecryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        remove(outname);
        return 0;
    }
    
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        fprintf(stderr, "EVP_DecryptInit_ex (key/iv) failed\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        remove(outname);
        return 0;
    }

    unsigned char inbuf[BUFFER_SIZE];
    unsigned char outbuf[BUFFER_SIZE + 32];
    int outlen;
    long processed = 0;
    int ret;

    // Decrypt data
    while (processed < encrypted_data_size) {
        size_t to_read = BUFFER_SIZE;
        if (encrypted_data_size - processed < BUFFER_SIZE) {
            to_read = encrypted_data_size - processed;
        }
        
        int len = fread(inbuf, 1, to_read, in);
        if (len <= 0) break;
        
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, len) != 1) {
            fprintf(stderr, "EVP_DecryptUpdate failed\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            remove(outname);
            return 0;
        }
        
        fwrite(outbuf, 1, outlen, out);
        processed += len;
    }

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag) != 1) {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl (set tag) failed\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        remove(outname);
        return 0;
    }

    // Finalize decryption - THIS IS WHERE PASSWORD IS VERIFIED
    ret = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
    
    if (ret <= 0) {
        // Wrong password or corrupted data
        printf("[-] WRONG PASSWORD OR CORRUPTED FILE: %s\n", filename);
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        remove(outname);  // Delete the incomplete decrypted file
        return 0;
    }
    
    // Write final decrypted data
    if (outlen > 0) {
        fwrite(outbuf, 1, outlen, out);
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    // Remove encrypted file
    if (remove(filename) != 0) {
        perror("Warning: Could not remove encrypted file");
    }

    printf("[+] Decrypted: %s\n", filename);
    return 1;
}

// ================= PROCESS =================

void process(const char *path, const char *password, int encrypt, int *count) {
    struct stat st;
    if (stat(path, &st) != 0) {
        perror("stat failed");
        return;
    }

    if (!S_ISDIR(st.st_mode)) {
        if (is_self(path)) return;
        
        int res = 0;
        if (encrypt) {
            if (!is_enc_file(path)) {
                res = encrypt_file(path, password);
            }
        } else {
            if (is_enc_file(path)) {
                res = decrypt_file(path, password);
            }
        }
        
        if (res) (*count)++;
        return;
    }

    // It's a directory - process recursively
    DIR *d = opendir(path);
    if (!d) {
        perror("Cannot open directory");
        return;
    }

    struct dirent *e;
    while ((e = readdir(d))) {
        if (is_dot_or_system(e->d_name)) continue;

        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", path, e->d_name);
        process(full, password, encrypt, count);
    }

    closedir(d);
}

// ================= MAIN =================

int main(int argc, char *argv[]) {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    if (argc < 4) {
        printf("Usage:\n");
        printf("  ./enc -e password file1 file2 folder1\n");
        printf("  ./enc -d password file1.enc folder1\n");
        printf("  ./enc -e password *\n");
        printf("  ./enc -d password *\n");
        return 1;
    }

    // Get self path
    if (realpath(argv[0], SELF_PATH) == NULL) {
        perror("realpath failed");
        return 1;
    }

    char tmp[PATH_MAX];
    strncpy(tmp, SELF_PATH, sizeof(tmp));
    strcpy(SELF_NAME, basename(tmp));

    int encrypt = (strcmp(argv[1], "-e") == 0);
    const char *password = argv[2];

    if (!encrypt && strcmp(argv[1], "-d") != 0) {
        fprintf(stderr, "Invalid option. Use -e or -d\n");
        return 1;
    }

    if (strlen(password) == 0) {
        fprintf(stderr, "Password cannot be empty\n");
        return 1;
    }

    int total = 0;
    printf("%s started...\n", encrypt ? "Encryption" : "Decryption");

    // Process each argument
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "*") == 0) {
            // Process current directory
            process(".", password, encrypt, &total);
        } else {
            // Process specific file/directory
            process(argv[i], password, encrypt, &total);
        }
    }

    printf("[+] Total files processed: %d\n", total);
    printf("Done.\n");
    
    // Cleanup OpenSSL
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}
