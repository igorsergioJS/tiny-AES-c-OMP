#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <omp.h>
#include "aes.h"

void print_hex(const uint8_t* str, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", str[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <tamanho_em_MB>\n", argv[0]);
        return 1;
    }

    // Obtém o tamanho do buffer em MB a partir do argumento
    size_t size_in_mb = atoi(argv[1]);
    if (size_in_mb <= 0) {
        fprintf(stderr, "Erro: o tamanho deve ser maior que 0.\n");
        return 1;
    }

    // Calcula o tamanho do buffer em bytes
    size_t data_size = size_in_mb * 1024 * 1024;

    // Define uma chave de 128 bits (16 bytes)
    uint8_t key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

    uint8_t* plaintext = malloc(data_size);
    uint8_t* encrypted = malloc(data_size);
    uint8_t* decrypted = malloc(data_size);

    // Verifica a alocação de memória
    if (!plaintext || !encrypted || !decrypted) {
        fprintf(stderr, "Erro ao alocar memória\n");
        free(plaintext);
        free(encrypted);
        free(decrypted);
        return 1;
    }

    // Inicializa o buffer de dados com algum padrão (ex.: todos os 'A's)
    memset(plaintext, 'A', data_size);

    // Copia o buffer de dados para o buffer criptografado
    memcpy(encrypted, plaintext, data_size);
    double start_time = omp_get_wtime();

    #pragma omp parallel
    {
        // Criptografa o buffer de dados
        struct AES_ctx ctx;
        AES_init_ctx(&ctx, key);

        #pragma omp for
        for (size_t i = 0; i < data_size; i += 16) {
            AES_ECB_encrypt(&ctx, encrypted + i);
        }
    }
    double end_time = omp_get_wtime();
    printf("Tempo de criptografia (tamanho de entrada %zu bytes): %.6f segundos\n", data_size, end_time - start_time);

    // Copia o buffer criptografado para o buffer descriptografado
    memcpy(decrypted, encrypted, data_size);

    start_time = omp_get_wtime();
    #pragma omp parallel
    {
        struct AES_ctx ctx;
        AES_init_ctx(&ctx, key);

        #pragma omp for
        for (size_t i = 0; i < data_size; i += 16) {
            AES_ECB_decrypt(&ctx, decrypted + i);
        }
    }

    end_time = omp_get_wtime();
    printf("Tempo de descriptografia (tamanho de entrada %zu bytes): %.6f segundos\n", data_size, end_time - start_time);

    // Verifica a precisão da descriptografia
    if (memcmp(plaintext, decrypted, data_size) == 0) {
        printf("Descriptografia bem-sucedida.\n");
    } else {
        printf("Erro na descriptografia.\n");
    }

    // Libera a memória alocada
    free(plaintext);
    free(encrypted);
    free(decrypted);

    return 0;
}

