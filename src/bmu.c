/*! # BMU FileParser 

    При magic =0xABABABAB вызывается merge_bmu_extract().
    Если это single BMU выполняется разбор

Что делает утилита (аналог FileParser, см Update.sh)

+ Проверяет magic и согласованность content mask / file_count / размера.
+ Извлекает `miner.pem` / `miner.pem.sig`.
+ Проверяет подпись `miner.pem` корневым ключом (`bitmain.pub`).
+ Извлекает все файлы и их подписи `.sig`.
+ Проверяет подпись каждого файла ключом из `miner.pem`.
+ Проверяет финальную подпись пакета.
+ Если встречается datafile (code 9) — пытается распаковать, как Android bootimg.

Сборка:
$ gcc -O2 -Wall -Wno-deprecated-declarations -o bmu_parser bmu.c crc5.c r3_args.c farmhash64.c -lcrypto -I.
Разбор BMU, пример:
$ ./bmu_parser Antminer\ S19\ XP/AMLCtrl_BHB56XXX/update.bmu bitmain.pub out -s 'AMLCtrl_BHB56XXX'

Порядок работы
1. Разбор Merge BMU - формирует структуру директории {model}/{hardware}/{image.bmu}
2. Разбор файлов в структуре single BMU : BOOT.bin, kernel, minerfs, update...
3. Проверка подписей каждого файла
4. Если в архиве найден файл тип(9) `datafile` он может быть в формате Android boot image с шифрованием. 
    Такие файлы встречаются в прошивках плат `AMLCtrl`. Архив раскрывается в три файла:
    `kernel`, `ramdisk.img`, `second.img` - Amlogic Multi-DTB
5. Разбор полученных файлов: 
```sh
  $ mkdir ramdisk
  $ cd ramdisk
  $ gzip -dc ../ramdisk.img | cpio -idmv
```

Для распаковки AMLSECU использован код (https://github.com/Alex20129/aml_decrypt.git)

**Amlogic Multi-DTB образ (мульти-DTB).**
Магическое значение AML_ (в little-endian 0x5F4C4D41) — это стандартный заголовок для упаковки 
нескольких Device Tree Blob’ов в один файл. Такой формат встречается в `second.img`, `dtb.img` 
разделах на Amlogic-устройствах.

 */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#if defined(_WIN32) && !defined(__CYGWIN__) && !defined(__MSYS__)
#  include <direct.h>
#  define mkdir(path, mode) _mkdir(path)
#endif

#define CRC32_INIT  0xffffffff
#define CRC32_CHECK 0xcbf43926
extern uint32_t crc32(uint32_t crc, const uint8_t *buffer, size_t size);
extern uint64_t farmhash64(const char *s, size_t len);

#define BMU_HEADER_SIZE     2048 
#define RSA_SIG_SIZE        256
#define BMU_MAX_FILES       16
#define BLOCK_SZ            0x1000 // копирование выполняется блоками

/* single BMU Header field offsets (big-endian multi-byte fields) */
#define OFF_MAGIC           0       /* uint8  must be 0x26 ('&') */
#define OFF_TYPE_HASH       2       /* uint64 farmhash64 of miner type */
#define OFF_CONTENT_MASK    11      /* uint16 BE — bit i set => file type i present */
#define OFF_FW_VERSION      13      /* char[8]   */
#define OFF_PEM_LEN         22      /* uint16 BE */
#define OFF_PEM_DATA        24      /* miner.pem */
#define OFF_PEM_SIG         1048    /* miner.pem RSA Signature */
#define OFF_FILE_COUNT      1304    /* uint8  — must equal popcount(content) */
#define OFF_DECLARED_SIZE   1305    /* uint32 BE */
#define OFF_FILE_TABLE      1309    /* file_count × 5 bytes: type + size BE */
#define OFF_COMMENT         1360    /* 256 bytes */

//! Таблица имен файлов в архиве BMU
static const char* filenames[BMU_MAX_FILES] = {
[0] = "BOOT.bin",
[1] = "devicetree.dtb",
[2] = "uImage",
[3] = "minerfs.image.gz",
[4] = "update.image.gz",
[5] = "crl.tar.gz",
[6] = "miner.btm.tar.gz",
[7] = "reserve",
[9] = "datafile"
};
struct merge_bmu_header {
    uint32_t magic;         // 0xABABABAB
    uint32_t version;       // обычно 0
    uint32_t header_size;   // 36
    uint32_t item_count;    // количество записей (в примере 10)
    uint32_t item_size;     // размер одной записи (172 Б)
    uint32_t data_offset;   // смещение начала данных (обычно 16384 = 16 КБ)
    uint32_t crc32;         // CRC32 всего файла (с обнулённым полем crc32)
    uint32_t reserve[2];    // 0
} __attribute__((packed));

struct merge_bmu_item {
    uint8_t  filename_len;      // длина имени файла
    uint8_t  chip_len;          // длина поля chip
    uint8_t  hardware_len;      // длина поля hardware
    uint8_t  model_len;         // длина поля model
    char     filename[64];      // имя файла (update.bmu / Antminer-....bmu)
    char     chip[32];          // обычно пусто
    char     hardware[32];      // CVCtrl_BHB42XXX / AMLCtrl_BHB42XXX / zynq7007_...
    char     model[32];         // например, Antminer S19j Pro
    uint32_t offset;            // абсолютное смещение данных в файле
    uint32_t size;              // размер данных
} __attribute__((packed));

struct _Android_boot_hdr {
    uint8_t  magic[8];       /* "ANDROID!" */
    uint32_t kernel_size;
    uint32_t kernel_addr;
    uint32_t ramdisk_size;
    uint32_t ramdisk_addr;
    uint32_t second_size;
    uint32_t second_addr;
    uint32_t tags_addr;
    uint32_t page_size;
    uint32_t dt_size;        /* unused in v0, header_version in newer */
    uint32_t unused;
    uint8_t  name[16];
    uint8_t  cmdline[512];
    uint32_t id[8];
    /* further fields exist in bootimg v1/v2/v3 — not needed for basic split */
} __attribute__((packed));
#define AMLSEC_BOOTIMG_MAGIC      "AMLSECU!"
#define AMLSEC_BOOTIMG_VESRION    0x0905   // типичное значение версии
struct _aml_enc_block {// шапка зашифрованного блока
    uint32_t  data_offset;   // Смещение блока данных относительно начала образа
    uint32_t  RawLength;     // Размер исходных (незашифрованных) данных
    uint32_t  SigLength;     // Размер подписи
    uint32_t  Alignment;     // Выравнивание
    uint32_t  TotalLength;   // Общий размер блока (данные + подпись + паддинг)
    uint8_t   padding[12];    // Выравнивание/резерв (обычно нули)
    uint8_t   hash_image[32]; // SHA-256 хеш образа (или зашифрованных данных)
    uint8_t   hash_keyId[32]; // SHA-256 хеш идентификатора ключа
} __attribute__((packed));
struct _aml_enc_hdr {
    uint8_t     magic[8]; // "AMLSECU!"
    uint32_t    version;              // HW версия (0x905)
    uint32_t    blk_count;            // количество блоков (обычно 3)
    unsigned char timestamp[16];      // строка времени сборки (например "2025020719312667")
    struct _aml_enc_block block[0];   // описание зашифрованного ядра
} __attribute__((packed));
#define AML_DTB_MAGIC  0x5F4C4D41   // "AML_"
struct _aml_dtb {// структура файла Amlogic Multi-DTB
    uint32_t magic;      // 0x5F4C4D41 ("AML_")
    uint32_t version;    // версия формата (1 или 2)
    uint32_t DTB_count;  // количество DTB в образе
};

struct _rsa_key {
	uint32_t modulus[64];			// 256
	uint32_t reserved1[64];			// 256
	uint32_t exponent;		        // 4
	uint32_t montgomeryParams[64];	// 256
	uint32_t reserved2[64];			// 256
	uint32_t montgomeryCoefficient;	// 4
	uint32_t modulusSize;			// 4
} __attribute__((packed));
typedef struct _rsa_key rsa_key_t;

typedef struct _Android_boot_hdr boot_img_hdr_t;

static void dump_file(const uint8_t *data, size_t dlen, const char* path, const char* basename, const char* suffix);

static inline uint32_t align_up(uint32_t v, uint32_t page) {
    return (v + page - 1u) / page * page;
}
static inline uint16_t be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}
static inline uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) | ((uint32_t)p[3]);
}

static int write_blob(const char *path, const uint8_t *data, uint32_t size) {
    FILE* fp = fopen(path, "wb");
    if (!fp) {
        perror(path);
        return -1;
    }
    if (fwrite(data, 1, size, fp) != size) {
        perror("fwrite");
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}
#if 0
/* ---------- RSA ---------- */
static RSA *load_rsa_from_pem_mem(const uint8_t *pem, size_t len)
{
    BIO *bio = BIO_new_mem_buf(pem, (int)len);
    if (!bio) return NULL;
    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return rsa;
}

static RSA *load_rsa_from_file(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    RSA *rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return rsa;
}

static int rsa_verify_sha256(const uint8_t *data, size_t dlen,
                             const uint8_t *sig,  size_t slen,
                             RSA *rsa)
{
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(data, dlen, hash);
    return RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, sig, slen, rsa) == 1;
}
#endif

struct _aml_crypto_hdr {
	uint16_t magic;				// 0 v
	uint16_t block_size;		// 2 v
	uint16_t encrypted;			// 4 v
	uint16_t unknown1;			// 6
	uint32_t unknown2;			// 8
	uint32_t sig1;				// 12 v
	uint32_t first_offset;		// 16
	uint32_t data_offset;		// 20 v
	uint32_t encrypted_size;	// 24
	uint32_t payload_size;		// 28
	uint8_t  hash[32];			// 32
	uint8_t  key[32];			// 64
	uint8_t  iv[16];			// 96
	uint8_t  padding1[24];		// 112
	char     cipher[7];		    // 136
	char     date[20];			// 143
	uint8_t  padding2[69];		// 163
	uint8_t  padding3[16];		// 232
	uint16_t unknown3;			// 248
	uint16_t unknown4;			// 250 v
	uint32_t sig2;				// 252 v
};
typedef struct _aml_crypto_hdr aml_crypto_hdr_t;
static void hex_print(const uint8_t *data, uint32_t len) {
	for(uint32_t b = 0; b < len; ++b)
		fprintf(stdout, "%02X ", data[b]);
	fprintf(stdout, "\n");
}
static int validate_header(aml_crypto_hdr_t *header) {
	if (header == NULL)
		return 1199;
	if (header->sig1 != 0x434c4d41 || header->sig2 != 0x434c4d41)
		return 1204;
	if (header->encrypted >= 2 || header->block_size != 512)
		return 1214;
	if (header->unknown4 != 512)
		return 1214;
	if (header->data_offset != 512)
		return 1225;
	return 0;
}
/*! \brief загрузить ключ в формате amlsec из файла */
int  amlsec_key(const char *filename, rsa_key_t * key) {
   	FILE *key_fp = fopen(filename, "rb");
    if (key_fp==NULL) return -1;
    size_t n = fread(key, 1, sizeof(rsa_key_t), key_fp);
    fclose(key_fp);
    return n;
}
/*! \brief преобразовать ключ в формат RSA */
RSA *amlsec_rsa_key(rsa_key_t *key)
{
	RSA *rsa = RSA_new();
	if (!rsa) {
		fprintf(stderr, "Ошибка: не удалось создать RSA объект.\n");
		return NULL;
	}
	BIGNUM *n = BN_new();
	BIGNUM *e = BN_new();
	if (!n || !e) {
		fprintf(stderr, "Ошибка: не удалось создать BIGNUM.\n");
		RSA_free(rsa);
		BN_free(n);
		BN_free(e);
		return NULL;
	}
	unsigned char modulus_bytes[256]; // 64 * 4 байта = 256 байт
	for (int i = 0; i < 64; ++i) {
		modulus_bytes[252 - i * 4] = (key->modulus[i] >> 24) & 0xFF;
		modulus_bytes[253 - i * 4] = (key->modulus[i] >> 16) & 0xFF;
		modulus_bytes[254 - i * 4] = (key->modulus[i] >>  8) & 0xFF;
		modulus_bytes[255 - i * 4] = (key->modulus[i]      ) & 0xFF;
	}
	BN_bin2bn(modulus_bytes, 256, n);
	BN_set_word(e, key->exponent);
	if (RSA_set0_key(rsa, n, e, NULL) != 1)	{
		fprintf(stderr, "Ошибка: не удалось установить ключ в RSA объект.\n");
		RSA_free(rsa);
		BN_free(n);
		BN_free(e);
		return NULL;
	}
	return rsa;
}
int  amlsec_aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, 
    const unsigned char *key, const unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0;
	int plaintext_len = 0;
	int ret = -1;

	if(!(ctx = EVP_CIPHER_CTX_new())) {
		fprintf(stderr, "Error: EVP_CIPHER_CTX_new failed\n");
		return ret;
	}
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	EVP_CIPHER_CTX_set_key_length(ctx, 32);
	if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
		fprintf(stderr, "Error: EVP_DecryptInit_ex (key/iv) failed\n");
		goto cleanup;
	}
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
		fprintf(stderr, "Error: EVP_DecryptUpdate failed\n");
		goto cleanup;
	}
	plaintext_len = len;
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
		fprintf(stderr, "Error: EVP_DecryptFinal_ex failed\n");
		unsigned long err = ERR_get_error();
		char err_msg[256];
		ERR_error_string_n(err, err_msg, sizeof(err_msg));
		fprintf(stderr, "OpenSSL error: %s\n", err_msg);
		goto cleanup;
	}
	plaintext_len += len;
	ret = plaintext_len;
cleanup:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}
int  amlsec_decrypt_encrypt(uint8_t *input_buffer, uint8_t *output_buffer, 
    rsa_key_t *key_51C6778, rsa_key_t *key_51C6340, const uint8_t *reference_hash)
{
	int error_code = 0;
	unsigned int i;
	aml_crypto_hdr_t header[2];
	aml_crypto_hdr_t decrypted_header[1];
	uint8_t temp_storage[256];
	uint8_t computed_hash[32];
	uint8_t key_hash[32];
	rsa_key_t *selected_key = NULL;
	//const char *selected_key_name = NULL;

	rsa_key_t *keys[] = {key_51C6778, key_51C6340};
	// const char *key_names[] = {"key_51C6778", "key_51C6340"};
	size_t key_lengths[] = {516, 1036};
	size_t num_keys = sizeof(keys) / sizeof(keys[0]);
	size_t num_lengths = sizeof(key_lengths) / sizeof(key_lengths[0]);
	uint32_t decrypted_size;

	for (size_t i = 0; i < num_keys; ++i) {
		for (size_t j = 0; j < num_lengths; ++j) {
            SHA256((uint8_t*)keys[i], key_lengths[j], key_hash);
            if (0) hex_print(key_hash, 32);
			if (memcmp(reference_hash, key_hash, 32) == 0) {
				selected_key = keys[i];
				break;
			}
		}
		if (selected_key != NULL) {
			break;
		}
	}
	if (selected_key == NULL) {
		printf("Error: No matching key found\n");
		return 666;
	}
	memcpy(header, input_buffer, sizeof(aml_crypto_hdr_t)*2);
	if (validate_header(header))
	{
		for (i = 0; i < 512; i += 4 * selected_key->modulusSize) {
			RSA *rsa = amlsec_rsa_key(selected_key);
			if (!rsa) {
				fprintf(stderr, "RSA error\n");
				return 1;
			}
			RSA_public_decrypt(4 * selected_key->modulusSize, &input_buffer[i], temp_storage, rsa, RSA_NO_PADDING);
			RSA_free(rsa);
			memcpy(&input_buffer[i], temp_storage, 4 * selected_key->modulusSize);
		}
		memcpy(&decrypted_header[0], input_buffer, sizeof(aml_crypto_hdr_t));
		error_code = validate_header(&decrypted_header[0]);
		if (error_code)		{
			fprintf(stdout, "check fail with ERR = %d\n", error_code);
		} else {
			fprintf(stdout, "header valid\n");
			memcpy(input_buffer, (input_buffer+decrypted_header[0].first_offset), decrypted_header[0].block_size);
			SHA256(input_buffer, decrypted_header[0].encrypted_size, computed_hash);
			if (0) hex_print(decrypted_header[0].hash, 32);
			if (!memcmp(computed_hash, decrypted_header[0].hash, 32))
			{
				if (decrypted_header[0].encrypted) {
					decrypted_size = amlsec_aes_decrypt(
						input_buffer,
						decrypted_header[0].payload_size,
						decrypted_header[0].key,
						decrypted_header[0].iv,
						output_buffer);
					if (decrypted_size < 0) {
						fprintf(stderr, "AES decryption failed\n");
						return 1331;
					}
					if (decrypted_size != decrypted_header[0].payload_size) {
						fprintf(stderr, "Decrypted size mismatch\n");
						return 1331;
					}
				}
				return 0;
			}
			else
			{
				fprintf(stderr, "Hash mismatch\n");
				return 1332;
			}
		}
	}
	else {
		error_code = 1320;
	}

	fprintf(stdout, "fail with %d\n", error_code);
	return error_code;
}

/*! \brief распаковка `datafile` в формате Android boot image 
 */
int bmu_unpack_abootimg(const char *path, const char *outdir)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize < (long)sizeof(boot_img_hdr_t)) {
        fprintf(stderr, "file too small\n");
        fclose(f);
        return 1;
    }

    uint8_t *buf = malloc((size_t)fsize);
    if (!buf) {
        fclose(f);
        return 1;
    }
    if (fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
        perror("fread");
        free(buf);
        fclose(f);
        return 1;
    }
    fclose(f);

    boot_img_hdr_t *hdr = (boot_img_hdr_t *)buf;
    if (memcmp(hdr->magic, "ANDROID!", 8) != 0) {
        free(buf);
        return 1;
    }


    uint32_t page = hdr->page_size;
    if (page == 0 || (page & (page - 1)) != 0) {
        fprintf(stderr, "bad page_size %u\n", page);
        free(buf);
        return 1;
    }

    mkdir(outdir, 0755);

static const char* block_name[] = {"kernel", "ramdisk.img.gz", "second.img.gz"};
    printf(" - magic:       ANDROID!\n");
    printf(" - 'kernel'  size:%u\n", hdr->kernel_size);
    printf(" - 'ramdisk' size:%u\n", hdr->ramdisk_size);
    printf(" - 'second'  size:%u\n", hdr->second_size);
    printf(" - page      size:%u\n", hdr->page_size);
    printf(" - cmdline: %.*s\n", 512, hdr->cmdline);
    int aml_enc = memcmp(buf+1024, "AMLSECU!", 8) == 0;
    if (aml_enc) {
        rsa_key_t key[2];
        amlsec_key("key1", &key[0]); 
        amlsec_key("key2", &key[1]); 
        struct _aml_enc_hdr *amlsec_hdr = (struct _aml_enc_hdr *)(buf+1024);
        printf("AML encrypted header\n");
        printf(" - magic     :%-8.8s\n",    amlsec_hdr->magic);
        printf(" - version   :%X\n",        amlsec_hdr->version);
        printf(" - timestamp :%-16.16s\n",  amlsec_hdr->timestamp);
        // = validate_image_header(image_buffer, key_51C6340);
        for (int i=0; i<amlsec_hdr->blk_count; i++){
            struct _aml_enc_block* blk = &amlsec_hdr->block[i];
            printf("AML block[%d]:\n", i);
            printf(" - data  offset: 0x%X\n", blk->data_offset);
            printf(" - raw   length: 0x%X\n", blk->RawLength);
            printf(" - total length: 0x%X\n", blk->TotalLength);
            uint8_t * data = buf + blk->data_offset;
            size_t dlen = align_up(blk->RawLength, blk->Alignment);
            uint8_t *decrypt_buffer = (uint8_t *)malloc(dlen);
            if (decrypt_buffer && i<3){
                amlsec_decrypt_encrypt(data, decrypt_buffer, &key[0], &key[1], blk->hash_keyId);
                printf("Save file '%s/%s'\n", outdir, block_name[i]);
                dump_file(decrypt_buffer, blk->RawLength, outdir, block_name[i], "");
                dump_file(data+dlen, blk->SigLength, outdir, block_name[i], ".sig");
                // сохранить RSA signature
                free(decrypt_buffer);
            }
        }

    } else {
    /* layout: [header: 1 page] [kernel] [ramdisk] [second] — each padded to page */
        uint32_t off = hdr->page_size;

        const uint8_t *kernel  = buf + off;
        off += align_up(hdr->kernel_size, page);

        const uint8_t *ramdisk = buf + off;
        off += align_up(hdr->ramdisk_size, page);

        const uint8_t *second  = buf + off;
        off += align_up(hdr->second_size, page);

        if (off > (uint32_t)fsize) {
            fprintf(stderr, "truncated image (need %u, have %ld)\n", off, fsize);
            free(buf);
            return 1;
        }
        char pathbuf[512];
        snprintf(pathbuf, sizeof(pathbuf), "%s/kernel", outdir);
        if (write_blob(pathbuf, kernel, hdr->kernel_size) != 0) goto fail;

        snprintf(pathbuf, sizeof(pathbuf), "%s/ramdisk", outdir);
        if (write_blob(pathbuf, ramdisk, hdr->ramdisk_size) != 0) goto fail;

        if (hdr->second_size > 0) {
            snprintf(pathbuf, sizeof(pathbuf), "%s/second", outdir);
            if (write_blob(pathbuf, second, hdr->second_size) != 0) goto fail;
        }
    }
    printf("written to %s/\n", outdir);
    free(buf);
    return 0;

fail:
    free(buf);
    return 1;
}

static int32_t verify_pem_payload(const uint8_t *pem_data,
                           int32_t        pem_len,
                           const uint8_t *pem_sig,
                           const uint8_t *root_key);

int get_file_size(const char *path, off_t *out) {
    struct stat st;
    if (stat(path, &st) != 0)
        return -1;
    *out = st.st_size;
    return 0;
}

static int32_t process_firmware_chunk(FILE *src, uint32_t size, uint8_t *hash, const char* filename)
{
    uint8_t buf[BLOCK_SZ];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    FILE *fp = fopen(filename, "wb");
    if (fp==NULL)
        printf("Create File '%s' Failed!\r\n", filename);

    // читаем блоками по 1024, сохраняем копию, считаем хэш
    uint32_t remaining = size;
    while (remaining > BLOCK_SZ) {
        size_t n = fread(buf, 1, BLOCK_SZ, src);
        SHA256_Update(&ctx, buf, n);
        if (fp)
            fwrite(buf, 1, n, fp);
        remaining -= n;
    }
    if (remaining > 0) {
        size_t n = fread(buf, 1, remaining, src);
        SHA256_Update(&ctx, buf, n);
        if (fp)
            fwrite(buf, 1, n, fp);
    }
    SHA256_Final(hash, &ctx);
    if (fp)
        fclose(fp);
    return 0;
}
static void dump_file(const uint8_t *data, size_t dlen, const char* path, const char* basename, const char* suffix) {
    char buf[512];
    int offs = 0;
    offs += sprintf(buf+offs, "%s/%s", path, basename);
    if (suffix && suffix[0]!='\0')
        offs += sprintf(buf+offs, "%s", suffix);
    FILE* fp = fopen(buf, "wb");
    if (fp) {
        fwrite(data, 1, dlen, fp);
        fclose(fp);
    }
}
static uint32_t merge_bmu_extract_file(FILE* bmu, const char* filename, off_t offs, size_t size) {
    uint8_t buf[BLOCK_SZ];
    FILE* fp = fopen(filename, "wb");
    if (fp==NULL) return ~0;
    fseeko(bmu, offs, SEEK_SET);
    offs = 0;
    do {
        size_t n = fread(buf, 1, BLOCK_SZ, bmu);
        if (n==0) break;
        fwrite(buf, 1, n, fp);
        offs += n;
    }while (offs < size);
    fclose(fp);
    return 0;
}
/*! \brief расчет контрольной суммы от остатка файла */
static uint32_t merge_bmu_crc32(FILE* bmu, size_t size, uint32_t crc) {
    size_t offs = 0;
    uint8_t buf[BLOCK_SZ];
    do {
        size_t n = fread(buf, 1, BLOCK_SZ, bmu);
        if (n==0) break;
        crc = crc32(crc, buf, n);
        offs += n;
    } while(offs<size);
    return crc;
}
static  int32_t merge_bmu_extract(FILE* bmu) {
    struct merge_bmu_header hdr;
    fseek(bmu, 0, SEEK_SET);
    size_t n = fread(&hdr, 1, sizeof(struct merge_bmu_header), bmu);
    if (n!= sizeof(struct merge_bmu_header)) return -1;
    printf("=== Merge BMU Header ===\n");
    printf("magic       : %08X %s\n", hdr.magic, hdr.magic == 0xABABABAB ? "OK" : "FAIL");
    printf("version     : %u\n", hdr.version);
    printf("header_size : %u\n", hdr.header_size);
    printf("item_count  : %u\n", hdr.item_count);
    printf("item_size   : %u\n", hdr.item_size);
    printf("data_offset : %u (0x%X)\n", hdr.data_offset, hdr.data_offset);
    uint32_t crc_ = hdr.crc32;
    hdr.crc32 = 0;
    uint32_t crc = crc32(~0u, (uint8_t*)&hdr, hdr.header_size);

    uint8_t *items = calloc(hdr.item_count, hdr.item_size);
    n = fread(items, hdr.item_size, hdr.item_count, bmu);
    if (n!=hdr.item_count) return -1;
    crc = crc32(crc, items, hdr.item_count*hdr.item_size); 
    crc = merge_bmu_crc32(bmu, ~0, crc);
    printf("crc32       : 0x%08X %s\n", crc_, ~crc==crc_?"OK": "FAIL");
// Печатаем таблицу
    printf("%-3s %-20s %-20s %-12s %-50s %10s %10s\n",
           "#", "Model", "Hardware", "Chip", "Name", "Offset", "Size");
    char filename[512];
    for (int i=0; i<hdr.item_count; i++) {
        struct merge_bmu_item *item = (struct merge_bmu_item *)(items + hdr.item_size*i);
        printf("%-3u %-20s %-20s %-12s %-50s %10u %10u\n",
               i, item->model, item->hardware, item->chip, item->filename, item->offset, item->size);
        int offs = 0;
        offs+= snprintf(filename+offs, 512-offs, "%s",  item->model);
        mkdir(filename, 0755);
        offs+= snprintf(filename+offs, 512-offs, "/%s", item->hardware);
        mkdir(filename, 0755);
        offs+= snprintf(filename+offs, 512-offs, "/%s", item->filename);
        merge_bmu_extract_file(bmu, filename,  item->offset, item->size);
    }
    free(items);
    return 0;
}
/**
 * Разбирает и проверяет BMU-файл прошивки Antminer.
 *
 * @param bmu_path      путь к .bmu файлу
 * @param root_pubkey   путь к корневому публичному ключу (обычно /etc/bitmain.pub)
 * @param header_buf    буфер ≥ 2048 байт заголовок BMU
 * @param dump_files    1 = выписать miner.pem + .sig и все файлы в /tmp
 * @param print_comment 1 = напечатать комментарий из пакета
 * @param verbose  1 = требовать "полный" отчет
 * @return 0 = OK, иначе - код ошибки
 */
int32_t bmu_extract_verify(const char *bmu_path,
                               const char *root_pubkey,
                               const char *path, 
                               uint32_t print_comment,
                               uint32_t verbose)
{
    struct stat st;
    if (stat(bmu_path, &st) != 0) {
        perror(bmu_path);
        return 7;
    }
    off_t file_size = st.st_size;

    uint8_t header_buf[2048];

    FILE *bmu = fopen(bmu_path, "rb");
    if (bmu==NULL) {
        printf("Read File '%s' Failed!\n", bmu_path);
        return 7;
    }

    // Читаем заголовок 2048 байт
    size_t n = fread(header_buf, 1, BMU_HEADER_SIZE, bmu);
    if (n!=BMU_HEADER_SIZE) {
        printf("'%s' Btmu File Size = %zd!\n", bmu_path, n);
        fclose(bmu);
        return 6;
    }
    // Magic: первый байт должен быть 0x26 ('&') 
    if (header_buf[0] != 0x26) {
        if (*(uint32_t*)header_buf==0xABABABAB){
            merge_bmu_extract(bmu);
        } else
            printf("'%s' Not A Btmu File!\n", bmu_path);
        fclose(bmu);
        return 8;
    }
    // FarmHash :: Fingerprint64() от строки типа машины  `-s 'S19'`
    uint64_t type_hash = *(uint64_t*) (header_buf+2);// 2-10
    printf("BMU file '%s'\n"
           "BMU image type: '%016"PRIx64"'\n", bmu_path, type_hash);
    printf("BMU fw version: '%-.8s'\n", &header_buf[OFF_FW_VERSION]);
/* optional: write firmware version string (8 bytes at offset 13) */
    if (0) {
        FILE *ver = fopen("/usr/bin/fw_version", "w");
        if (ver) {
            fwrite(&header_buf[OFF_FW_VERSION], 1, 8, ver);
            fclose(ver);
        }
    }
    uint16_t content = be16(header_buf + OFF_CONTENT_MASK);
    int file_count = header_buf[OFF_FILE_COUNT];
    int file_count_ex = __builtin_popcount(content);
    if (file_count_ex != file_count) {
        printf("Content Doesn't Match![%d][%d]\n", file_count, file_count_ex);
        fclose(bmu);
        return 9;
    }

    // Суммарный размер всех файлов из таблицы (каждый entry = 5 байт)
    // Таблица начинается с offset 1309
    uint32_t declared_size = be32(header_buf + OFF_DECLARED_SIZE);
    uint32_t calculated_total = 256 * file_count + 2304; // заголовок + подписи
    if (file_count > 0) {
        for (int i = 0; i < file_count; i++) {
            const uint8_t *entry = &header_buf[1309 + 5 * i];// 
            uint8_t  ftype =  entry[0];
            uint32_t fsize = be32(&entry[1]);
            calculated_total += fsize;
            printf("file[%d] type:[%d] size:[%u]\n", i, ftype, fsize);
        }
    }

    // Проверка размера файла
    if (calculated_total > (uint32_t)file_size) {
        printf("Check FileSize Failed, FileSize Should Be [%u]Bytes, "
               "But It Was [%u] Bytes, And Total Says[%u]\n",
               declared_size, (uint32_t)file_size, calculated_total);
        fclose(bmu);
        return 10;
    }

    // --- Проверка miner.pem подписи корневым ключом ---
    FILE *fp_root = fopen(root_pubkey, "r");
    uint8_t root_key_buf[1024] = {0};
    if (fp_root) {
        n = fread(root_key_buf, 1024, 1, fp_root);
        fclose(fp_root);
    }

    const uint16_t pem_len  = be16(header_buf + OFF_PEM_LEN);
    const uint8_t *pem_data = header_buf + OFF_PEM_DATA;  // miner.pem
    const uint8_t *pem_sig  = header_buf + OFF_PEM_SIG;   // 256 байт подпись miner.pem ключом bitmain.pub

    int ret = verify_pem_payload(pem_data, pem_len, pem_sig, root_key_buf);
    if (ret != 0) {
        printf("Check pem payload failed! ret:[%d]\n", ret);
        // fclose(bmu);
        // return ret;
    }

    // Опционально выписать miner.pem и его подпись
    if (path) {
        dump_file(pem_data, pem_len, path, "miner.pem", "");
        dump_file(pem_sig, 256, path, "miner.pem", ".sig");
    }

    // --- Считаем SHA-256 заголовка + всех файлов + всех .sig ---
    uint8_t hashes[64 * 16 + 32];   // хеш заголовка + хеши файлов + хеши .sig
    memset(hashes, 0, sizeof(hashes));

    SHA256(header_buf, BMU_HEADER_SIZE, hashes);

    // Сначала сами файлы (add_sig = 0)
    for (int i = 0; i < file_count; i++) {
        const uint8_t *entry = &header_buf[1309 + 5 * i];
        uint8_t  ftype = entry[0];
        uint32_t fsize = (entry[1] << 24) | (entry[2] << 16) |
                         (entry[3] << 8)  | (entry[4]);

        char file[256];
        sprintf(file, "%s/%s", path, filenames[ftype]);

        process_firmware_chunk(bmu, fsize, &hashes[32 + 32 * i], file);
        if (ftype==9)
            bmu_unpack_abootimg(file, path);
    }
    BIO *bio = BIO_new_mem_buf((void *)pem_data, pem_len);
    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    // Потом их .sig (add_sig = 1, размер всегда 256)
    for (int i = 0; i < file_count; i++) {
        const uint8_t *entry = &header_buf[1309 + 5 * i];
        uint8_t ftype = entry[0];
        uint8_t sig[256];
        n = fread(sig, 1, 256, bmu);
        SHA256(sig, 256, &hashes[32 + 32*(file_count + i)]);
        if (path) {
            dump_file(sig, 256, path, filenames[ftype], ".sig");
        }
        int ok = RSA_verify(NID_sha256, &hashes[32 + 32 * i], 32, sig, 256, rsa);
        printf("File '%s' Signature %s!\n", filenames[ftype], ok?"OK": "FAIL");
    }

    /* ---------- финальная подпись пакета ----------
     * FileParser считает:
     *   H0 = SHA256(header)
     *   Hi = SHA256(file_i)          for i = 1 .. n
     *   Si = SHA256(sig_i)           for i = 1 .. n
     *   final = SHA256( H0 || H1..Hn || S1..Sn )
     * и проверяет RSA(final, package_sig) ключом miner.pem
     */

    uint8_t package_sig[256] = {0};
//    fseek(bmu, -256, SEEK_END);
    fseek(bmu, calculated_total-256, SEEK_SET);
    n = fread(package_sig, 1, 256, bmu);
    if (path)
        dump_file(package_sig, 256, path, "bmu.sig", "");

    // SHA-256( хеш_заголовка + хеши_файлов + хеши_подписей )
    uint8_t final_hash[32];
    SHA256(hashes, 32 + 64 * file_count, final_hash);

    // Проверяем RSA-подпись пакета ключом из miner.pem
    if (!rsa) {
        printf("OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        puts("Load Pem Failed!");
        fclose(bmu);
        return 17;
    }

    int ok = RSA_verify(NID_sha256, final_hash, 32, package_sig, 256, rsa);
    RSA_free(rsa);
    if (bio)
        BIO_free(bio);

    if (ok != 1) {
        puts("Check File Sig failed!\r");
        printf("OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        fclose(bmu);
        return 18;
    }

    fclose(bmu);
    puts("All Done!\r");

    if (print_comment) {// комментарий из пакета (offset 1360, 256 байт)
        puts("This Comment Of This Package:");
        char comment[256];
        memcpy(comment, &header_buf[OFF_COMMENT], 256);
        puts(comment);
    }

    return 0;
}

/**
 * Проверяет подпись miner.pem корневым публичным ключом.
 *
 * @param pem_data   указатель на содержимое miner.pem
 * @param pem_len    длина miner.pem в байтах
 * @param pem_sig    256-байтовая RSA-подпись miner.pem
 * @param root_key   буфер с корневым публичным ключом (PEM, до 1024 байт)
 * @return 0 = OK, 12 = не удалось загрузить корневой ключ,
 *         13 = подпись неверна
 */
static int32_t verify_pem_payload(const uint8_t *pem_data, int32_t pem_len, const uint8_t *pem_sig, const uint8_t *root_key)
{
    BIO *bio = BIO_new_mem_buf((void *)root_key, 1024);
    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);

    if (rsa == NULL) {
        printf("OpenSSL error: %s\n",
               ERR_error_string(ERR_get_error(), NULL));
        puts("Read Root PubK Failed!");
        return 12;
    }

    uint8_t hash[32];
    SHA256(pem_data, pem_len, hash);
    int ok = RSA_verify(NID_sha256, hash, 32, pem_sig, 256, rsa);
    RSA_free(rsa);
    if (bio != NULL)
        BIO_free(bio);

    if (ok != 1) {
        printf("OpenSSL error: %s\n",
               ERR_error_string(ERR_get_error(), NULL));
        puts("Check miner.pem Failed!");
        return 13;
    }

    return 0;
}

#include "r3_args.h"
#include <signal.h>
#include <locale.h>
typedef struct _options {
    char* machine_type; // строка идентификатор типа машины, например 'CVCtrl_BHB42XXX', 'AMLCtrl', 'BBCtrl'
    char* key1; // ключ шифрования
    char* key2;
    int selftest;
    int overwrite;
    int verbose;
    int version;
} MainOptions;
MainOptions options = {
    .machine_type = "",
};
static GOptionEntry entries[] = {
  { "type",     's', 0, G_OPTION_ARG_STRING,   &options.machine_type,   "machine type", "S19|S21"},
  { "selftest", 't', 0, G_OPTION_ARG_NONE,     &options.selftest,       "Self Test"},
  { "verbose",  'v', 0, G_OPTION_ARG_NONE,     &options.verbose,        "be verbose"},
  {NULL}
};
/*
Сборка
 $ gcc -O2 -Wall -o bmu_parser bmu.c -lcrypto
 $ gcc -O2 -Wall -Wno-deprecated-declarations -o bmu_parser bmu.c -lcrypto
 $ ./bmu_parser {firmware.bmu} {bitmain.pub}
*/
int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "");
	setlocale(LC_NUMERIC, "C");
	GOptionContext *opt_context;
    opt_context = g_option_context_new ("# command line interface\n"
        "(c) 2026 Anatoly Georgievski (https://github.com/AnatolyGeorgievski)"
    );
    g_option_context_add_main_entries (opt_context, entries, NULL/*GETTEXT_PACKAGE*/);
    if (!g_option_context_parse (opt_context, &argc, &argv, NULL))
    {
        //printf ("option parsing failed: %s\n", error->message);
        _Exit(1);
    }
    g_option_context_free (opt_context);
	if (options.version) {
	}

    if (argc < 3) {
        fprintf(stderr, "Usage: %s [options] <file.bmu> <root.pub> <out_path>\n", argv[0]);
        return 1;
    }

    if (options.machine_type) {
        uint64_t fhash = farmhash64(options.machine_type, strlen(options.machine_type));
        printf("machine type hash: '%016"PRIx64"'\n", fhash);
    }
    if (options.selftest) {
        uint8_t test[] = "123456789";
        uint32_t crc = crc32(~0u, (uint8_t*)test, 9);
        printf("crc32 test: 0x%08X %s\n", ~crc, ~crc == CRC32_CHECK?"ok":"fail");// cbf43926
        char machine[] = "CVCtrl_BHB42XXX";
        // MATCH 883b7c5d69fe738b 'CVCtrl_BHB42XXX'  (from S19j Pro README)
        // MATCH 7d5cc307eda5eda1 'CVCtrl_L9'
        uint64_t h64 = farmhash64(machine, strlen(machine));
        printf("farmhash64: 0x%016"PRIX64" %s\n", h64, h64 == 0x883b7c5d69fe738b?"ok":"fail");
    }

    int ret = bmu_extract_verify(argv[1], argv[2], argc>3?argv[3]: NULL, 
                                 0, /* print_comment */ options.verbose);
    return ret;
}
