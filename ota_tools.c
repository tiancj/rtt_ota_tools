#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "quicklz.h"
#include "tiny_aes.h"


#define BIT(i)                   (1UL << (i))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

//none, gzip, quicklz, fastlz
#define RT_OTA_CMPRS_ALGO_NONE     			0
#define RT_OTA_CMPRS_ALGO_GZIP     			BIT(8)
#define RT_OTA_CMPRS_ALGO_QUICKLZ  			BIT(9)
#define RT_OTA_CMPRS_ALGO_FASTLZ   			BIT(10)
#define RT_OTA_CMPRS_STAT_MASK     			0x0F00

#define RT_OTA_CRYPT_ALGO_NONE     			0
#define RT_OTA_CRYPT_ALGO_XOR				BIT(0)
#define RT_OTA_CRYPT_ALGO_AES256   			BIT(1)
#define RT_OTA_CRYPT_STAT_MASK				0x0F

typedef unsigned short rt_ota_algo_t;

// sizeof rt_ota_rbl_hdr = 96
struct rt_ota_rbl_hdr {
	char 	 magic[4];		// 0x0
	uint32_t algo;		// 0x4
	uint32_t timestamp; // 0x8
	char 	 name[16];		// 0xc
	char 	 version[24];	// 0x1c
	char 	 sn[24];		// 0x34
	uint32_t crc32;		// 0x4c
	uint32_t hash;		// 0x50
	uint32_t size_raw;	// 0x54
	uint32_t size_package; // 0x58
	uint32_t info_crc32; // 0x5c
};

#define RT_OTA_HDR_SIZE		sizeof(struct rt_ota_rbl_hdr)

char iv[33];
char key[65];
char cmprs[10] = {"none"};
char file[255];
char out_file[260];
char part[16];
char crypt_arg[10] = {"none"};
char version[24];

static const char *crypt_table[] = {"none", "xor", "aes"};
static const char *cmprs_table[] = {"none", "gzip", "quicklz", "fastlz"};

static const uint32_t crc32_table[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

struct option long_options[] = {
	{"key", 	required_argument, 	0, 'k'},
	{"iv", 		required_argument, 	0, 'i'},
	{"crypt", 	required_argument, 	0, 's'},
	{"cmprs", 	required_argument, 	0, 'c'},
	{"version", required_argument, 	0, 'v'},
	{"part", 	required_argument, 	0, 'p'},
	{"help", 	no_argument, 		0, 'h'},
	{"out", 	no_argument, 		0, 'o'},
	{"file", 	no_argument, 		0, 'f'},
};

#define FNV1_PRIME_32 0x01000193
#define FNV1_BASE_32 2166136261U

/* FNV-1a core implementation returning a 32 bit checksum over the first
 * LEN bytes in INPUT.  HASH is the checksum over preceding data (if any).
 */
uint32_t rt_ota_calc_hash(uint32_t hash, const void *input, size_t len)
{
	const unsigned char *data = input;
	const unsigned char *end = data + len;

	for (; data != end; ++data) {
		hash ^= *data;
		hash *= FNV1_PRIME_32;
	}

	return hash;
}

/**
 * Calculate the CRC32 value of a memory buffer.
 *
 * @param crc accumulated CRC32 value, must be 0 on first call
 * @param buf buffer to calculate CRC32 value for
 * @param size bytes in buffer
 *
 * @return calculated CRC32 value
 */
uint32_t rt_ota_calc_crc32(uint32_t crc, const void *buf, size_t size)
{
	const uint8_t *p;

	p = (const uint8_t *)buf;
	crc = crc ^ ~0U;

	while (size--)
		crc = crc32_table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);

	return crc ^ ~0U;
}

char *package_rbl(rt_ota_algo_t algo, const char *part, const char *version,
				  const char *buffer, const char *iv, const char *key, size_t size, size_t *package_size)
{
	size_t pack_size;
	qlz_state_compress *state;
	tiny_aes_context ctx;
	char *result;
	unsigned char *output;
	char *crypt_buffer;
	struct stat statbuf;
	struct rt_ota_rbl_hdr hdr;
	int padding = 0x10;
#define EXTRA_SIZE		0x10

	memset(&hdr, 0, sizeof(hdr));

	pack_size = size;
	hdr.hash = rt_ota_calc_hash(0x811C9DC5, buffer, size);
	strcpy(hdr.magic, "RBL");
	hdr.size_raw = size;
	hdr.algo = algo;
	strcpy(hdr.name, part);
	strcpy(hdr.version, version);
	hdr.timestamp = time(NULL);
	if (!stat(file, &statbuf))
		hdr.timestamp = statbuf.st_mtime;

	if (!(algo & RT_OTA_CMPRS_STAT_MASK)) {  // no compress
		if (!(crypt_buffer = (char *)malloc(size + EXTRA_SIZE)))
			return 0;
		memcpy(crypt_buffer, buffer, size + EXTRA_SIZE);

	} else {
		// compress firmware
		if ((algo & RT_OTA_CMPRS_STAT_MASK) != RT_OTA_CMPRS_ALGO_QUICKLZ)		// only support quicklz
			return NULL;
		state = (qlz_state_compress *)malloc(qlz_get_setting(1));
		crypt_buffer = (char *)malloc(size + EXTRA_SIZE);
		if (!crypt_buffer || !state) {
			free(state);
			free(crypt_buffer);
			return NULL;
		}

		if (size) {
			char compressed_data[4096];
			int block_size;
			char *p = crypt_buffer;
			const char *q = buffer;
			const char *end = buffer + pack_size;
			size_t compressed_len; // compress size after compress 4096b

			/*
			 * format: 
			 * +----------------+-----------------+----------+
			 * | compressed_len | compressed_data |  ......  |
			 * +----------------+-----------------+----------+
			 */
			for (; q < end; q += block_size, p += compressed_len) {
				block_size = 4096;
				if (q + block_size > end)
					block_size = end - q;

				compressed_len = qlz_compress(q, compressed_data, block_size, state);
				*p++ = (compressed_len >> 24) & 0xff;
				*p++ = (compressed_len >> 16) & 0xff;
				*p++ = (compressed_len >> 8) & 0xff;
				*p++ = compressed_len & 0xff;

				memcpy(p, compressed_data, compressed_len);
			}
			pack_size = p - crypt_buffer;
		}
		free(state);
	}

#ifdef WINDOWS
	if (pack_size & 0xF) {
		padding = 0x10 - (pack_size & 0xF);
		memset(crypt_buffer + pack_size, 0xFF, padding);
		pack_size += padding;
	}
#else
	// always padding: if pack_size is aligned with 16bytes, padding with 0x10
	padding = 0x10 - (pack_size & 0xF);
	memset(crypt_buffer + pack_size, padding, padding);
	pack_size += padding;
#endif

	if (algo & RT_OTA_CRYPT_STAT_MASK) {	// encryption
		if ((algo & RT_OTA_CRYPT_STAT_MASK) != RT_OTA_CRYPT_ALGO_AES256) {
			free(crypt_buffer);
			printf("crypt_buffer null");
			return NULL;
		}

		output = (unsigned char *)malloc(pack_size);
		if (!output) {
			printf("crypt_data null");
			free(crypt_buffer);
			return NULL;
		}

		tiny_aes_setkey_enc(&ctx, (unsigned char *)key, 256);
		tiny_aes_crypt_cbc(&ctx, 1, pack_size, (unsigned char *)iv, (unsigned char *)crypt_buffer, output);
		free(crypt_buffer);
		crypt_buffer = (char *)output;
	}

	// package header
	hdr.size_package = pack_size;		// aligned size
	strcpy(hdr.sn, "00000000000000000000000");
	hdr.crc32 = rt_ota_calc_crc32(0, crypt_buffer, pack_size);

	// caculate crc with hdr(exclude info_crc32)
	hdr.info_crc32 = rt_ota_calc_crc32(0, &hdr, RT_OTA_HDR_SIZE - sizeof(uint32_t));
	result = (char *)malloc(pack_size + RT_OTA_HDR_SIZE);
	if (result) {
		memcpy(result, &hdr, RT_OTA_HDR_SIZE);
		memcpy(result + RT_OTA_HDR_SIZE, crypt_buffer, pack_size);
		*package_size = pack_size + RT_OTA_HDR_SIZE;
	}

	free(crypt_buffer);

	return result;
}

void print_help()
{
	printf(
		"%s",
		"Usage: ota_tools -f BIN -v VERSION -p PARTNAME [-o OUTFILE] [-c CMPRS_TYPE] [-s CRYPT_TYPE] [-i IV] [-k KEY] [-h]\n"
		"	  -f bin file.\n"
		"	  -v firmware's version.\n"
		"	  -p firmware's target part name.\n"
		"	  -o output rbl file path.(optional)\n"
		"	  -c compress type allow [none, gzip, quicklz, fastlz](optional)\n"
		"	  -s crypt type allow [none|xor|aes](optional)\n"
		"	  -i iv for aes-256-cbc\n"
		"	  -k key for aes-256-cbc\n"
		"	  -h show this help information\n");
}

int main(int argc, char **argv)
{
	int c;
	int ret;
	unsigned char crypto_algo;
	unsigned char compress_method;
	rt_ota_algo_t algo;
	size_t package_size = 0;

	FILE *finput; // input file, -f
	FILE *foutput; // input file, -f
	char *input_file_buf;
	char *pack_buf;

	while (1) {
		c = getopt_long(argc, argv, "f:o:p:v:s:c:i:k:h", long_options, 0);
		ret = c;
		if (c == -1)
			break;
		switch (c) {
		case 'c':
			strncpy(cmprs, optarg, sizeof(cmprs) - 1);
			break;
		case 'f':
			strncpy(file, optarg, sizeof(file) - 1);
			break;
		case 'h':
			ret = 0;
			print_help();
			return 0;
		case 'i':
			strncpy(iv, optarg, sizeof(iv) - 1);
			break;
		case 'k':
			strncpy(key, optarg, sizeof(key) - 1);
			break;
		case 'o':
			strncpy(out_file, optarg, sizeof(out_file) - 1);
			break;
		case 'p':
			strncpy(part, optarg, sizeof(part) - 1);
			break;
		case 's':
			strncpy(crypt_arg, optarg, sizeof(crypt_arg) - 1);
			break;
		case 'v':
			strncpy(version, optarg, sizeof(version) - 1);
			break;
		default:
			printf("\n%s Argument error!\n", optarg);
			print_help();
			return -1;
		}
	}
	if (!file[0]) {
		printf("no input file\n");
		print_help();
		return -1;
	}

	/* if not specify -o, generate out_file based on file */
	if (!out_file[0]) {
		strncpy(out_file, file, sizeof(out_file) - 4);
		strcat(out_file, ".rbl");
	}

	/* specify fimware version */
	if (!version[0]) {
		printf("request option -- v\n");
		return -1;
	}

	/* specify crypto algo */
	crypto_algo = RT_OTA_CRYPT_ALGO_NONE;
	if (!part[0]) {
		printf("request option -- p\n");
		return -1;
	}

	while (strcmp(crypt_arg, crypt_table[crypto_algo])) {
		if (++crypto_algo == ARRAY_SIZE(crypt_table)) {
			printf("Error crypt's argument %s\n", crypt_arg);
			return -1;
		}
	}

	/* specify compress method */
	compress_method = RT_OTA_CMPRS_ALGO_NONE;
	while (1) {
		ret = strcmp(cmprs, cmprs_table[compress_method]);
		if (!ret)
			break;
		if (++compress_method == ARRAY_SIZE(cmprs_table)) {
			printf("Error cmprs's argument %s\n", cmprs);
			return -1;
		}
	}

	algo = crypto_algo | (compress_method << 8);

	/* sanity check aes key & iv*/
	if ((crypto_algo & RT_OTA_CRYPT_STAT_MASK) == RT_OTA_CRYPT_ALGO_AES256) {  //aes
		if (strlen(iv) != 16) {
			printf("Error iv argument %s\n", iv);
			return -1;
		}

		if (strlen(key) != 32) {
			printf("Error key argument %s\n", key);
			return -1;
		}
	}

	if (!(finput = fopen(file, "rb"))) {
		printf("Open file %s failed\n", file);

		return -1;
	}

	// file size
	fseek(finput, 0, SEEK_END);
	package_size = ftell(finput);
	fseek(finput, 0, SEEK_SET);

	if (!(input_file_buf = (char *)malloc(package_size))) {
		fclose(finput);
		printf("no memory");

		return -1;
	}

	ret = fread(input_file_buf, 1, package_size, finput);
	fclose(finput);
	pack_buf = package_rbl(algo, part, version, input_file_buf, iv, key, package_size, &package_size);
	free(input_file_buf);

	if (!pack_buf) {
		printf("pack error");
		return -1;
	}

	if (!(foutput = fopen(out_file, "wb"))) {
		printf("Open file %s failed\n", out_file);
		return -1;
	}

	fwrite(pack_buf, 1, package_size, foutput);
	fclose(foutput);
	free(pack_buf);
	ret = 0;

	return ret;
}


