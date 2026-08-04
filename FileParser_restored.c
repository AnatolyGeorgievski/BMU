/*
 * FileParser — restored from Hex-Rays decompilation of the Antminer
 * "FileParser" ELF (ARM, libcrypto.so.1.1).
 *
 * Naming / structure layout aligned with the reference implementation
 * in bmu.c (same BMU header layout, same RSA/SHA-256 verification
 * scheme, same on-disk paths).
 *
 * Build (on a 32-bit ARM host or with the right cross toolchain):
 *   gcc -O2 -Wall -Wno-deprecated-declarations -o FileParser \
 *       FileParser_restored.c -lcrypto
 *
 * Usage (matches the binary):
 *   FileParser -f|-s|-p|-x <minerType> <file.bmu> <root.pub>
 *   FileParser -n <nand.bin>
 *   FileParser -q
 *
 * Options:
 *   -f  verify only
 *   -s  verify + extract payloads into /tmp/tmpfw/
 *   -p  verify + print package comment
 *   -x  require "full" content mask (0xFE00 bits set)
 *   -n  split fixed-layout NAND image into /tmp/tmpNand/
 *   -q  write 256 bytes of 0xFF to /tmp/256BFF
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>   /* NID_sha256 */

/* ------------------------------------------------------------------ */
/* Constants                                                          */
/* ------------------------------------------------------------------ */

#define BMU_HEADER_SIZE     2048
#define RSA_SIG_SIZE        256
#define MAX_FILES           16
#define ROOT_KEY_BUF_SIZE   1024
#define CHUNK_SIZE          0x400   /* 1024 — matches original fread size */

/* Header field offsets (big-endian multi-byte fields) */
#define OFF_MAGIC           0       /* uint8  must be 0x26 ('&') */
#define OFF_TYPE_HASH       2       /* uint64 farmhash of miner type (unused here) */
#define OFF_CONTENT_MASK    11      /* uint16 BE — bit i set => file type i present */
#define OFF_PEM_LEN         22      /* uint16 BE */
#define OFF_PEM_DATA        24
#define OFF_PEM_SIG         1048    /* RSA_SIG_SIZE */
#define OFF_FILE_COUNT      1304    /* uint8  — must equal popcount(content) */
#define OFF_DECLARED_SIZE   1305    /* uint32 BE */
#define OFF_FILE_TABLE      1309    /* file_count × 5 bytes: type + size BE */
#define OFF_COMMENT         1360    /* 256 bytes */

/* Error codes returned by the original binary */
enum {
    ERR_OK              = 0,
    ERR_USAGE           = 1,
    ERR_PARAM           = 2,
    ERR_NAME_TOO_LONG   = 3,
    ERR_PEM_NAME_LONG   = 4,
    ERR_BAD_CMD         = 5,
    ERR_TOO_SMALL       = 6,
    ERR_READ_FAIL       = 7,
    ERR_NOT_BTMU        = 8,
    ERR_CONTENT_MISMATCH= 9,
    ERR_SIZE_MISMATCH   = 10,
    ERR_ROOT_OPEN       = 11,
    ERR_ROOT_PEM        = 12,
    ERR_PEM_VERIFY      = 13,
    ERR_DUMP_PEM        = 15,
    ERR_DUMP_PEM_SIG    = 16,
    ERR_LOAD_MINER_PEM  = 17,
    ERR_PKG_SIG         = 18,
    ERR_NOT_FULL        = 20,
};

/* ------------------------------------------------------------------ */
/* File-type → name table (indices used in the BMU header)            */
/* ------------------------------------------------------------------ */

static const char *const bmu_filenames[MAX_FILES] = {
    [0] = "BOOT.bin",
    [1] = "devicetree.dtb",
    [2] = "uImage",
    [3] = "minerfs.image.gz",
    [4] = "update.image.gz",
    [5] = "crl.tar.gz",
    [6] = "miner.btm.tar.gz",
    [7] = "reserve",
    /* 8 unused */
    [9] = "datafile",
};

/* ------------------------------------------------------------------ */
/* NAND-image split table (option -n)                                 */
/*                                                                    */
/* Layout in the original .data section (unk_2307C):                  */
/*   struct { uint32_t size; char path[128]; } entries[15];           */
/*   stride = 132 bytes.                                              */
/* ------------------------------------------------------------------ */

struct nand_part {
    uint32_t    size;
    const char *path;
};

static const struct nand_part nand_parts[] = {
    {  256, "/tmp/tmpNand/devicetree.dtb.sig" },
    {  256, "/tmp/unused" },
    {  256, "/tmp/tmpNand/uImage.sig" },
    {  256, "/tmp/unused" },
    {  256, "/tmp/tmpNand/minerfs.image.gz.sig" },
    {  256, "/tmp/unused" },
    {  256, "/tmp/tmpNand/update.image.gz.sig" },
    {  256, "/tmp/unused" },
    {  256, "/tmp/tmpNand/miner.btm.sig" },
    {  256, "/tmp/unused" },
    {  256, "/tmp/tmpNand/crl.sig" },
    {  256, "/tmp/unused" },
    { 7168, "/tmp/tmpNand/7kreserve" },
    { 2048, "/tmp/tmpNand/miner.btm" },
    {10240, "/tmp/tmpNand/crl" },
};
#define NAND_PART_COUNT  (sizeof(nand_parts) / sizeof(nand_parts[0]))

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static void usage(const char *prog)
{
    puts("Useage:\r");
    printf("\t%s [option] [paramaters]\n\n", prog);
    puts("\tOption:{-f} {-s} {-p} {-n} {-x} {-q}\n");
    puts("\t\t-f [minerType] [fileName] [rootPublicKeyFile]: \n"
         "\t\t\tOnly Check If Filename was Valided.\n");
    puts("\t\t-s [minerType] [fileName] [rootPublicKeyFile]: \n"
         "\t\t\tCheck If Filename Was Valided, and Splite Bmu To \"/tmp/tmpfw/\"\n");
    puts("\t\t-p [minerType] [fileName] [rootPublicKeyFile]: \n"
         "\t\t\tCheck If Filename Was Valided, and Dump BmuComments\n");
    puts("\t\t-x [minerType] [fileName] [rootPublicKeyFile]: \n"
         "\t\t\tCheck If Filename Was FullSize BMU\n");
    puts("\t\t-n [nandBinFile]: \n"
         "\t\t\tSplite SigImg To Single File To \"/tmp/tmpNand/\"\n");
    puts("\t\t-q: \n"
         "\t\t\tGenerate A 256Bytes 0xff File To \"/tmp/256BFF\"\n");
    puts("\tReturns:");
    puts("\t\t0: \n\t\t\tWell Done!\n");
    puts("\t\tOthers: \n\t\t\tSomething Wrong!\n");
}

/* ------------------------------------------------------------------ */
/* Option -n : sequential split of a fixed-layout NAND image          */
/* ------------------------------------------------------------------ */

static int split_nand_image(const char *path)
{
    uint8_t buf[32768];
    FILE *in = fopen(path, "rb");
    if (!in) {
        puts("Load Nand Image File Failed!");
        return 1;
    }

    for (unsigned i = 0; i < NAND_PART_COUNT; i++) {
        size_t n = nand_parts[i].size;
        if (n > sizeof(buf))
            n = sizeof(buf);          /* original only ever needed ≤ 10 KiB */
        if (fread(buf, n, 1, in) != 1) {
            /* original still continues / returns 0 after the last successful
             * write; keep the same control flow */
        }
        FILE *out = fopen(nand_parts[i].path, "wb");
        if (!out) {
            printf("Try To Write To File '%s' Failed!\n", nand_parts[i].path);
            fclose(in);
            return 2;
        }
        fwrite(buf, n, 1, out);
        fclose(out);
    }
    fclose(in);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Option -q : 256-byte 0xFF pad file                                 */
/* ------------------------------------------------------------------ */

static int gen_256bff(void)
{
    FILE *f = fopen("/tmp/256BFF", "wb");
    if (!f) {
        puts("GenFile Failed!");
        return 1;
    }
    uint8_t buf[256];
    memset(buf, 0xFF, sizeof(buf));
    fwrite(buf, 256, 1, f);
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Verify miner.pem against the root public key                       */
/* (original sub_10C70)                                               */
/* ------------------------------------------------------------------ */

static int verify_pem_payload(const uint8_t *pem_data, size_t pem_len,
                              const uint8_t *pem_sig,
                              const uint8_t *root_key)
{
    BIO *bio = BIO_new_mem_buf(root_key, ROOT_KEY_BUF_SIZE);
    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (!rsa) {
        printf("OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        puts("Read Root PubK Failed!");
        if (bio) BIO_free(bio);
        return ERR_ROOT_PEM;
    }

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, pem_data, pem_len);
    SHA256_Final(hash, &ctx);

    int ok = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH,
                        pem_sig, RSA_SIG_SIZE, rsa);
    RSA_free(rsa);
    if (bio) BIO_free(bio);

    if (ok != 1) {
        printf("OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        puts("Check miner.pem Failed!");
        return ERR_PEM_VERIFY;
    }
    return ERR_OK;
}

/* ------------------------------------------------------------------ */
/* Stream one payload (or its .sig), optionally dump it, always hash  */
/* (original sub_10DE8)                                               */
/*                                                                    */
/*   ftype   – file-type code from the BMU table                      */
/*   is_sig  – 0 = payload, 1 = append ".sig"                         */
/*   do_dump – write to /tmp/tmpfw/<name>[.sig]                       */
/*   out_hash– 32-byte SHA-256 of the streamed data                   */
/* ------------------------------------------------------------------ */

static void process_chunk(FILE *src, uint32_t size, uint8_t *out_hash,
                          uint8_t ftype, int is_sig, int do_dump)
{
    char path[128];
    FILE *out = NULL;

    if (do_dump) {
        strcpy(path, "/tmp/tmpfw/");
        if (ftype < MAX_FILES && bmu_filenames[ftype])
            strcat(path, bmu_filenames[ftype]);
        if (is_sig)
            strcat(path, ".sig");
        printf("fileName:'%s', size:[%u]\r\n", path, size);
        out = fopen(path, "wb");
        if (!out)
            printf("Create File '%s' Failed!\r\n", path);
    }

    uint8_t buf[CHUNK_SIZE];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    uint32_t done = 0;
    while (size - done > CHUNK_SIZE) {
        size_t n = fread(buf, 1, CHUNK_SIZE, src);
        done += (uint32_t)n;
        SHA256_Update(&ctx, buf, n);
        if (out)
            fwrite(buf, 1, n, out);
    }
    size_t n = fread(buf, 1, size - done, src);
    SHA256_Update(&ctx, buf, n);
    if (out)
        fwrite(buf, 1, n, out);

    SHA256_Final(out_hash, &ctx);
    if (out)
        fclose(out);
}

/* ------------------------------------------------------------------ */
/* Core BMU verify / extract                                          */
/* (original sub_11460)                                               */
/*                                                                    */
/*   dump_files     – extract miner.pem + payloads + .sig             */
/*   print_comment  – print the 256-byte comment field                */
/*   require_full   – content mask must have the high bits 0xFE00 set */
/* ------------------------------------------------------------------ */

static int bmu_extract_verify(const char *bmu_path,
                              const char *root_pubkey,
                              int dump_files,
                              int print_comment,
                              int require_full)
{
    struct stat st;
    if (stat(bmu_path, &st) != 0 || st.st_size < BMU_HEADER_SIZE) {
        printf("File '%s' Not Enough %d, Something Wrong!\n",
               bmu_path, BMU_HEADER_SIZE);
        return ERR_TOO_SMALL;
    }
    off_t file_size = st.st_size;

    FILE *fp = fopen(bmu_path, "rb");
    if (!fp) {
        printf("Read File '%s' Failed!\n", bmu_path);
        return ERR_READ_FAIL;
    }

    uint8_t header[BMU_HEADER_SIZE];
    if (fread(header, BMU_HEADER_SIZE, 1, fp) != 1) {
        printf("Read File '%s' Failed!\n", bmu_path);
        fclose(fp);
        return ERR_READ_FAIL;
    }

    /* Magic byte */
    if (header[OFF_MAGIC] != 0x26) {
        printf("'%s' Not A Btmu File!\n", bmu_path);
        fclose(fp);
        return ERR_NOT_BTMU;
    }

    uint16_t content = be16(&header[OFF_CONTENT_MASK]);
    if (require_full) {
        printf("content:%x\n", content);
        if ((content & 0xFE00) != 0xFE00) {
            puts("This Package Was Not Full Package!");
            fclose(fp);
            return ERR_NOT_FULL;
        }
    }

    /* popcount(content) must equal file_count */
    int file_count = 0;
    for (int i = 0; i < 16; i++)
        if ((content >> i) & 1)
            file_count++;

    if (file_count != (int)header[OFF_FILE_COUNT]) {
        printf("Content Doesn't Match![%d][%d]\n",
               header[OFF_FILE_COUNT], file_count);
        fclose(fp);
        return ERR_CONTENT_MISMATCH;
    }

    /* Expected total size:
     *   header (2048) + sum(file sizes) + file_count * 256 (sigs)
     *   + final 256-byte package signature
     * The original computes:
     *   (file_count + 9) << 8   ==  256*file_count + 2304
     * then adds every declared payload size.
     */
    uint32_t calculated = (uint32_t)(file_count + 9) << 8;
    uint32_t declared   = be32(&header[OFF_DECLARED_SIZE]);

    for (int i = 0; i < file_count; i++) {
        const uint8_t *entry = &header[OFF_FILE_TABLE + 5 * i];
        uint32_t fsize = be32(&entry[1]);
        calculated += fsize;
        printf("file[%d] size:[%u]\n", i, fsize);
    }

    if ((uint32_t)file_size != calculated) {
        printf("Check FileSize Failed, FileSize Should Be [%u]Bytes, "
               "But It Was [%u] Bytes, And Total Says[%u]\n",
               declared, (uint32_t)file_size, calculated);
        fclose(fp);
        return ERR_SIZE_MISMATCH;
    }

    /* ---- load root public key ---- */
    FILE *fp_root = fopen(root_pubkey, "r");
    if (!fp_root) {
        printf("Cannot Open Root PublicKey '%s'!\n", root_pubkey);
        fclose(fp);
        return ERR_ROOT_OPEN;
    }
    uint8_t root_key[ROOT_KEY_BUF_SIZE];
    memset(root_key, 0, sizeof(root_key));
    fread(root_key, 1, ROOT_KEY_BUF_SIZE, fp_root);
    fclose(fp_root);

    /* ---- verify miner.pem ---- */
    uint16_t pem_len = be16(&header[OFF_PEM_LEN]);
    const uint8_t *pem_data = &header[OFF_PEM_DATA];
    const uint8_t *pem_sig  = &header[OFF_PEM_SIG];

    int ret = verify_pem_payload(pem_data, pem_len, pem_sig, root_key);
    if (ret != ERR_OK) {
        printf("Check pem payload failed! ret:[%d]\n", ret);
        fclose(fp);
        return ret;
    }

    /* optional: write firmware version string (8 bytes at offset 13) */
    {
        FILE *ver = fopen("/usr/bin/fw_version", "w");
        if (ver) {
            fwrite(&header[13], 1, 8, ver);
            fclose(ver);
        }
    }

    /* optional: dump miner.pem + .sig */
    if (dump_files) {
        FILE *o = fopen("/tmp/tmpfw/miner.pem", "w");
        if (!o) {
            puts("Dump Miner.pem Failed!\r");
            fclose(fp);
            return ERR_DUMP_PEM;
        }
        fwrite(pem_data, 1, pem_len, o);
        fclose(o);

        o = fopen("/tmp/tmpfw/miner.pem.sig", "w");
        if (!o) {
            puts("Dump Miner.pem.sig Failed!\r");
            fclose(fp);
            return ERR_DUMP_PEM_SIG;
        }
        fwrite(pem_sig, 1, RSA_SIG_SIZE, o);
        fclose(o);
    }

    /* ---- collect hashes for the final package signature ---- */
    /*
     * Layout of the hash buffer (original v22[]):
     *   [0 .. 31]               SHA256(header)
     *   [32 + 32*i ..]          SHA256(file_i)          i = 0 .. n-1
     *   [32 + 32*n + 32*i ..]   SHA256(sig_i)           i = 0 .. n-1
     * Final digest = SHA256( whole buffer of length 32 + 64*n )
     */
    uint8_t hashes[32 + 64 * MAX_FILES];
    memset(hashes, 0, sizeof(hashes));

    SHA256(header, BMU_HEADER_SIZE, hashes);

    /* stream payloads */
    for (int i = 0; i < file_count; i++) {
        const uint8_t *entry = &header[OFF_FILE_TABLE + 5 * i];
        uint8_t  ftype = entry[0];
        uint32_t fsize = be32(&entry[1]);
        process_chunk(fp, fsize, &hashes[32 + 32 * i],
                      ftype, /*is_sig=*/0, dump_files);
    }

    /* stream per-file signatures */
    for (int i = 0; i < file_count; i++) {
        const uint8_t *entry = &header[OFF_FILE_TABLE + 5 * i];
        uint8_t ftype = entry[0];
        process_chunk(fp, RSA_SIG_SIZE, &hashes[32 + 32 * (file_count + i)],
                      ftype, /*is_sig=*/1, dump_files);
    }

    /* package signature is the last 256 bytes of the file */
    uint8_t package_sig[RSA_SIG_SIZE];
    fseek(fp, -RSA_SIG_SIZE, SEEK_END);
    fread(package_sig, RSA_SIG_SIZE, 1, fp);

    uint8_t final_hash[SHA256_DIGEST_LENGTH];
    SHA256(hashes, 32 + 64 * (size_t)file_count, final_hash);

    /* verify package sig with miner.pem */
    BIO *bio = BIO_new_mem_buf(pem_data, pem_len);
    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (!rsa) {
        printf("OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        puts("Load Pem Failed!");
        if (bio) BIO_free(bio);
        fclose(fp);
        return ERR_LOAD_MINER_PEM;
    }

    int ok = RSA_verify(NID_sha256, final_hash, SHA256_DIGEST_LENGTH,
                        package_sig, RSA_SIG_SIZE, rsa);
    RSA_free(rsa);
    if (bio) BIO_free(bio);

    if (ok != 1) {
        puts("Check File Sig failed!\r");
        printf("OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        fclose(fp);
        return ERR_PKG_SIG;
    }

    fclose(fp);
    puts("All Done!\r");

    if (print_comment) {
        puts("This Comment Of This Package:");
        char comment[257];
        memset(comment, 0, sizeof(comment));
        memcpy(comment, &header[OFF_COMMENT], 256);
        puts(comment);
    }
    return ERR_OK;
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    if (argc <= 1) {
        usage(argv[0]);
        return ERR_USAGE;
    }
    if (argv[1][0] != '-') {
        usage(argv[0]);
        return ERR_PARAM;
    }

    char file_name[128];
    char pem_name[128];
    memset(file_name, 0, sizeof(file_name));
    memset(pem_name,  0, sizeof(pem_name));

    /* Argument layout mirrors the original:
     *   argc==5 : -{f|s|p|x}  minerType  fileName  rootPublicKey
     *   argc==3 : -n nandBinFile
     *   argc==2 : -q
     */
    switch (argc) {
    case 5:
        if (strlen(argv[3]) > 0x7F) {
            puts("fileName Too Long!");
            return ERR_NAME_TOO_LONG;
        }
        strcpy(file_name, argv[3]);
        if (strlen(argv[4]) > 0x7F) {
            puts("pemName Too Long!");
            return ERR_PEM_NAME_LONG;
        }
        strcpy(pem_name, argv[4]);
        break;
    case 3:
        if (strlen(argv[2]) > 0x7F) {
            puts("fileName Too Long!");
            return ERR_NAME_TOO_LONG;
        }
        strcpy(file_name, argv[2]);
        break;
    case 2:
        break;
    default:
        puts("Param Err!");
        usage(argv[0]);
        return ERR_NAME_TOO_LONG;
    }

    /* Note: argv[2] (minerType) is accepted by the CLI but never used
     * by the original binary for verification.  The type hash that sits
     * at header[2..9] is likewise ignored. */

    /*
     * Flag fall-through exactly as in the original binary:
     *   v14 / require_full   set by -x
     *   v15 / print_comment  set by -p  (only when require_full is clear)
     *   v16 / dump_files     set by -s or -x (when print_comment is clear)
     *
     * Effective combinations:
     *   -f  → verify only
     *   -s  → verify + extract to /tmp/tmpfw/
     *   -p  → verify + print comment
     *   -x  → verify as "full" package + extract
     */
    int dump_files    = 0;  /* a4 / v16 */
    int print_comment = 0;  /* a5 / v15 */
    int require_full  = 0;  /* a6 / v14 */
    int ret           = 0;

    switch (argv[1][1]) {
    case 'n':
        return split_nand_image(file_name);
    case 'q':
        return gen_256bff();
    case 'x':
        require_full = 1;
        /* fall through */
    case 'p':
        if (!require_full)
            print_comment = 1;
        /* fall through */
    case 's':
        if (!print_comment)
            dump_files = 1;
        /* fall through */
    case 'f':
        ret = bmu_extract_verify(file_name, pem_name,
                                 dump_files, print_comment, require_full);
        break;
    default:
        puts("Command Not Support!");
        usage(argv[0]);
        ret = ERR_BAD_CMD;
        break;
    }
    return ret;
}
