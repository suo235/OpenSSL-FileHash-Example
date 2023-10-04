#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/evp.h>

// https://wiki.openssl.org/index.php/EVP_Message_Digests
int main(int argc, char* argv[])
{
    FILE *target = NULL;
    char *buffer = NULL;

    FILE *hash_file = NULL;
    char *hash_file_name = NULL;

    size_t target_size = 0;

    EVP_MD_CTX *mdctx = NULL;

    unsigned char *digest = NULL;
    size_t digest_size = 0;

    int evp_error_code = 0;

    int main_error_code = 0;

    mdctx = EVP_MD_CTX_new();
    if(mdctx == NULL)
    {
        main_error_code = 1;
        goto EVP_MD_CTX_new_failed;
    }

    evp_error_code = EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    if(evp_error_code == 0)
    {
        main_error_code = 2;
        goto EVP_DigestInit_ex_failed;
    }

    target = fopen(argv[1], "rb");
    if(target == NULL)
    {
        main_error_code = 3;
        goto target_fopen_failed;
    }

    buffer = (char*)malloc(512);
    if(buffer == NULL)
    {
        main_error_code = 4;
        goto buffer_malloc_failed;
    }

    clearerr(target);

    while(feof(target) == 0)
    {
        target_size = fread(buffer, 1, 512, target);
        if(ferror(target) != 0)
        {
            main_error_code = 5;
            goto buffer_fread_failed;
        }

        evp_error_code = EVP_DigestUpdate(mdctx, buffer, target_size);
        if(evp_error_code == 0)
        {
            main_error_code = 6;
            goto EVP_DigestUpdate_failed;
        }
    }

    digest = (unsigned char *)malloc(EVP_MD_size(EVP_sha256()));
    if(digest == NULL)
    {
        main_error_code = 7;
        goto digest_malloc_failed;
    }

    evp_error_code = EVP_DigestFinal_ex(mdctx, digest, &digest_size);
    if(evp_error_code == 0)
    {
        main_error_code = 8;
        goto EVP_DigestFinal_ex_failed;
    }
    
    printf("digest_size = %d\n", digest_size);

    

    hash_file = fopen(argv[2], "wb");
    if(hash_file == NULL)
    {
        main_error_code = 9;
        goto hash_file_fopen_failed;
    }

    if(fwrite(digest, 1, digest_size, hash_file) < EVP_MD_size(EVP_sha256()))
    {
        main_error_code = 10;
        goto digest_fwrite_failed;
    }



digest_fwrite_failed:
    fclose(hash_file);

hash_file_fopen_failed:

EVP_DigestFinal_ex_failed:
    free(digest);
    
digest_malloc_failed:

EVP_DigestUpdate_failed:
buffer_fread_failed:
    free(buffer);

buffer_malloc_failed:
    fclose(target);

target_fopen_failed:

EVP_DigestInit_ex_failed:
    EVP_MD_CTX_free(mdctx);

EVP_MD_CTX_new_failed:

    return main_error_code;
}
