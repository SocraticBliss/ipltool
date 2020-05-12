#define _CRT_SECURE_NO_WARNINGS

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "ipltool.h"
#include "aes.h"
#include "sha1.h"
#include "ec.h"
#include "kirk_engine.h"
#include "ipl.h"

#define APP_VER "0.2"
#define DATA_BUF 512
#define DECRYPTED_BLOCK_SIZE ((decdataSize-dataSize))

// Default values
unsigned long int entry			= 0x040F0000;
u32 loadAddr 					= 0x040F0000;
u32 dataSize 					= 0xF50;
u32 decblkSize 					= 0xF60;

#ifdef __cplusplus
extern "C"
{
#endif

unsigned char kirk1_priv[] = {0x00, 0xF3, 0x92, 0xE2, 0x64, 0x90, 0xB8, 0x0F, 0xD8, 0x89, 0xF2, 0xD9, 0x72, 0x2C, 0x1F, 0x34, 0xD7, 0x27, 0x4F, 0x98, 0x3D};

int EncryptiplBlk(iplEncBlk *dst, const void *src)
{
    int ret = kirk_CMD0(dst, (void*)src, 0xFD0);
    if(ret == KIRK_NOT_ENABLED){ printf("KIRK not enabled!\n"); return -1;}
    else if(ret == KIRK_INVALID_MODE){ printf("Mode in header not CMD1\n"); return -1;}
    else if(ret == KIRK_HEADER_HASH_INVALID){ printf("header hash check failed\n"); return -1;}
    else if(ret == KIRK_DATA_HASH_INVALID){ printf("data hash check failed\n"); return -1;}
    else if(ret == KIRK_DATA_SIZE_ZERO){ printf("data size = 0\n"); return -1;}
    return 0;
}

u8 ipl[MAX_IPLBLK_DATA_SIZE * MAX_NUM_IPLBLKS]; // buffer for IPL
struct {
    KIRK_CMD1_HEADER_ENC hdr;
    u8 data[sizeof(iplBlk)];
} buf;
iplEncBlk encblk; // temp buffer for one 4KB encrypted IPL block
#ifdef __cplusplus
}
#endif

void decrypt_header(unsigned char* header_buf, unsigned int buf_size)
{
	unsigned char *iv = (unsigned char*) malloc(0x10);
	memset(iv, 0, 0x10);
	aescbc128_decrypt(kirk1_key, iv, header_buf, header_buf, buf_size);
}

unsigned int calculate_checksum(const void *buf, int size)
{
	int i = 0;
	unsigned int checksum = 0;

	for (i=0; i<size; i+=4)
		checksum += *(unsigned int*)((unsigned char*)buf + i);

 return(checksum);
}

bool verify_checksum(unsigned int expected_checksum, unsigned int computed_checksum)
{
	if (computed_checksum == expected_checksum)
		return true;
	
	return false;
}

bool decrypt_data(FILE *in, unsigned int offset, unsigned int size, unsigned char *key, unsigned int *data_checksum, FILE *out)
{
	unsigned char iv[0x10];
	memset(iv, 0, 0x10);
	unsigned int pad = (0x10 - (size % 0x10)) % 0x10;
	unsigned char *data_in_buf = (unsigned char*) malloc(size + pad);
	unsigned char *data_out_buf = (unsigned char*) malloc(size + pad);
	unsigned int computed_checksum;
	bool res = true;
	
	memset(data_in_buf, 0, (size + pad));
	memset(data_out_buf, 0, (size + pad));
	fseek(in, offset, SEEK_SET);
	fread(data_in_buf, (size + pad), 1, in);
	
	aescbc128_decrypt(key, iv, data_in_buf, data_in_buf, (size + pad));
	
	BLOCK_HEADER* blk_header = (BLOCK_HEADER*)data_in_buf;
	
	//Check for type
	if (size <= 0xF60)
	{
		printf("\n");													//type 2+
		printf("[*] Block Header:\n");
		printf("LOAD ADDRESS:    0x%X\n", blk_header->load_address);
		printf("DATA SIZE:       0x%X\n", blk_header->data_size);
		if (blk_header->entry_point != 0)
			printf("ENTRY POINT:     0x%X\n", blk_header->entry_point);
	
		printf("PREW BLK CHKSUM: 0x%X\n", blk_header->checksum);	
		printf("COMPUTED:        0x%X\n", data_checksum[0]);

		if (!verify_checksum(data_checksum[0], blk_header->checksum))
		{
			printf("STATUS: FAIL\n");
			res = false;
		}
		else
			printf("STATUS: OK\n");

		memcpy(data_out_buf, (data_in_buf + 0x10), size);
		size = blk_header->data_size;
		
		//calculate and store current block checksum.
		computed_checksum = calculate_checksum((data_in_buf + 0x10), blk_header->data_size);
		data_checksum[0] = computed_checksum;
	}
	else
		memcpy(data_out_buf, data_in_buf, size);  //type 1
	
	fwrite(data_out_buf, size, 1, out);
	free(data_in_buf);
	free(data_out_buf);
	return res;
}

void print_usage(char *argv[])
{
	printf("USAGE: %s -d <file_in> <file_out> [dec options]\n", argv[0]);
	printf("       %s -e <file_in> <file_out> [enc options]\n\n", argv[0]);
	printf("Decryption Options:\n       -nv\t\t\t\tDisables verbose logging\n\n");
	printf("Encryption Options:\n       -nv\t\t\t\tDisables verbose logging\n       -r\t\t\t\tUse 'retail flag'\n       -s=<size>\t\t\tSpecify block size\n       -l=<address>\t\t\tSpecify base load address\n       -p=<entrypoint>\t\t\tSpecify entrypoint\n       -ec\t\t\t\tToggle ECDSA on last block\n");

	printf("\n       Default values:\n       \tEntrypoint: \t\t\t0x%08X\n       \tLoad Address: \t\t\t0x%08X\n       \tData Size: \t\t\t0x%08X\n", entry, loadAddr, dataSize);
}

int main(int argc, char *argv[])
{
	printf("*=================*\n| IPL Tool v." APP_VER "  |\n*=================*\nCredits: draanPSP, Proxima, 173210, Sorvigolova, zecoxao, Mathieulh & LemonHaze\n\n");
	        
	if (argc <= 3)
	{
		print_usage(argv);
		return 0;
	}
	
	FILE *in = NULL;
	FILE *out = NULL;
	unsigned int in_size;
	int blocks = 0;
	bool verbose = true;
	
	if ((strcmp(argv[1], "-e") == 0))
	{
		int cur;
		u32 hash = 0;
		iplBlk *bufBlock;
		bool retail = false, ecdsa = false;
		char *tmpSize = (char*)malloc(DATA_BUF); 
		char *tmpEntrypoint = (char*)malloc(DATA_BUF); 
		char *tmpLoadAddress = (char*)malloc(DATA_BUF);
		
		// process extra args
		for(int i = 4; i < argc; i++)
		{
			if ((strcmp(argv[i], "-nv") == 0))
				verbose = !verbose;
			else if ((strcmp(argv[i], "-r") == 0))
				retail = !retail;
			else if ((strcmp(argv[i], "-ec") == 0))
				ecdsa = !ecdsa;
			else if (sscanf(argv[i], "-s=%s", tmpSize))
				dataSize = strtoul(tmpSize, NULL, 0);	
			else if (sscanf(argv[i], "-l=%s", tmpLoadAddress))
				loadAddr = strtoul(tmpLoadAddress, NULL, 0);
			else if (sscanf(argv[i], "-p=%s", tmpEntrypoint))
			{
				entry = strtoul(tmpEntrypoint, NULL, 0);
				if (entry >= 0xB0000000) {
					printf("illegal entry\n");
					return -2;
				}
			}
		}
		
		printf("==================================\nOptions:\n\tVerbose: \t%s\n\tRetail: \t%s\n\tData Size: \t0x%08X\n\tLoad Address: \t0x%08X\n\tEntrypoint: \t0x%08X\n==================================\n\n", (verbose?"true":"false"), (retail?"true":"false"), dataSize, loadAddr, entry);
				
		//return 0;
		
		//Open the file to decrypt, get it's size
		in = fopen(argv[2], "rb");
		fseek(in, 0, SEEK_END);
		int size_dec = ftell(in);
		rewind(in);
		
		fread(ipl, size_dec, 1, in);
		fclose(in);
		
		//init KIRK crypto engine
		kirk_init(); 

		out = fopen(argv[3], "wb");

		buf.hdr.mode = KIRK_MODE_CMD1;
		buf.hdr.ecdsa = 0;
		buf.hdr.data_offset = 0x10;
		
		// Add devflag
		if(!retail)
		{
			buf.hdr.unk3[4] = 0xFF;
			buf.hdr.unk3[5] = 0xFF;
			buf.hdr.unk3[6] = 0xFF;
			buf.hdr.unk3[7] = 0xFF;
		}

		bufBlock = (iplBlk *)(buf.data + 0x10);
		
		bufBlock->addr = loadAddr;
		bufBlock->size = dataSize;
		bufBlock->entry = 0;
		bufBlock->hash = 0;
		hash = iplMemcpy(bufBlock->data, ipl, bufBlock->size);

		buf.hdr.data_size = offsetof(iplBlk, data) + bufBlock->size;
		
		blocks++;
		if(verbose) printf("================================================================\n| Block %d \t | Load Address: 0x%08X | Size: 0x%08X |\n================================================================\n", blocks, bufBlock->addr, bufBlock->size);

		if (EncryptiplBlk(&encblk, &buf) != 0)
		{
			printf("IPL block encryption failed!\n");
			fclose(out);
			return -1;
		}

		fwrite(&encblk, sizeof(encblk), 1, out);

		buf.hdr.data_offset = 0x10;
		
		bufBlock = (iplBlk *)(buf.data + 0x10);
		bufBlock->size = dataSize;
		bufBlock->entry = 0;

		buf.hdr.data_size = offsetof(iplBlk, data) + bufBlock->size;

		//encrypt all decrypted IPL blocks
		for (cur = bufBlock->size; cur + bufBlock->size < size_dec; cur += bufBlock->size)
		{
			blocks++;
			
			bufBlock->addr = loadAddr + cur;
			bufBlock->hash = hash;
			// load a single decrypted IPL block
			hash = iplMemcpy(bufBlock->data, ipl + cur, bufBlock->size);

			// encrypt the ipl block
			if (EncryptiplBlk(&encblk, &buf) != 0)
			{
				printf("IPL block encryption failed!\n");
				fclose(out);
				return -1;
			}
			
			if(verbose) printf("| Block %d \t | Load Address: 0x%08X | Size: 0x%08X |\n================================================================\n", blocks, bufBlock->addr, bufBlock->size);
			
			fwrite(&encblk, sizeof(encblk), 1, out);
		}

		buf.hdr.ecdsa 		= (ecdsa?1:0);      
		bufBlock->addr 		= loadAddr + cur;
		bufBlock->size 		= size_dec - cur;
		bufBlock->entry 	= entry; 
		bufBlock->hash 		= hash;
		memcpy(bufBlock->data, ipl + cur, bufBlock->size);

		buf.hdr.data_size = offsetof(iplBlk, data) + bufBlock->size;

		if (EncryptiplBlk(&encblk, &buf) != 0)
		{
			printf("IPL block encryption failed!\n");
			fclose(out);
			return -1;
		}
		
		blocks++;
		if(verbose) printf("| Block %d \t | Load Address: 0x%08X | Size: 0x%08X |\n================================================================\n", blocks, bufBlock->addr, bufBlock->size);

		fwrite(&encblk, sizeof(encblk), 1, out);
		fclose(out);	

		printf("\nIPL encrypted successfully. \n");	

		free(tmpSize);
	}
	else if ((strcmp(argv[1], "-d") == 0))
	{
		// process extra args
		for(int i = 4; i < argc; i++)
		{
			if ((strcmp(argv[i], "-nv") == 0))
				verbose = !verbose;
		}
		
		printf("Decryption mode\n");
		in = fopen(argv[2], "rb");
		//Check input file for permission.
		if (in == NULL)
		{
			printf("Error! Could not open file %s.\n", argv[2]);
			return 0;
		}
		else
			printf("File %s loaded.\n", argv[2]);
		
		//Obtain size of the input file.
		fseek(in, 0, SEEK_END);
		in_size = ftell(in);
		fseek(in, 0, SEEK_SET);
		
		//Check input file for size.
		if (in_size < 0x100 || in_size > 0x40000000)
		{
			printf("Error! Invalid IPL file detected, exiting.\n");
			fclose(in);
			return 0;
		}
		printf("File size : 0x%X bytes\n", in_size);
		
		//Create output file.
		out = fopen(argv[3], "wb");
	
		//Check output file for permission.
		if (out == NULL)
		{
			printf("Error! Could not create file %s.\n", argv[3]);
			fclose(in);
			return 0;
		}
		fclose(out);
	
		//Open output file.
		out = fopen(argv[3], "ab");
		unsigned int header_offset = 0;
		unsigned int pad_size = 0;
		unsigned int real_data_offset = 0;
		bool IsLastBlock = false;
		unsigned int *data_checksum = (unsigned int*) malloc(sizeof(data_checksum));
		data_checksum[0] = 0;
		
		while (IsLastBlock == false)
		{
			unsigned char *header_buf = (unsigned char*) malloc(0x90);
			memset(header_buf, 0, 0x90);
			fseek(in, header_offset, SEEK_SET);
			fread(header_buf, 0x90, 1, in);

			KIRK_CMD1_HEADER* header = (KIRK_CMD1_HEADER*)header_buf;
			pad_size = (0x10 - (header->data_size % 0x10)) % 0x10;
			if(verbose) printf("\n");
			if(verbose) printf("[*] Kirk Header:\n");
		
		
			if (header->mode == CMAC_MODE)
			{
				if(verbose) printf("Kirk mode: CMAC\n");
				CMAC_KEY_HEADER* cmac_header = (CMAC_KEY_HEADER*)header->key_header;
			
				//Decrypt keys.
				decrypt_header(header_buf, 0x20);
			
				int i;
				if(verbose) printf("CIPHER KEY:  ");
				for (i = 0; i < 0x10; i++)
					if(verbose) printf("%02X", cmac_header->aes_key[i]);
				if(verbose) printf("\n");
		
				if(verbose) printf("HASHER KEY:  ");
				for (i = 0; i < 0x10; i++)
					if(verbose) printf("%02X", cmac_header->cmac_key[i]);
				if(verbose) printf("\n");
		
				//Check CMAC hashes
				if(verbose) printf("HEADER CMAC: ");
				for (i = 0; i < 0x10; i++)
					if(verbose) printf("%02X", cmac_header->cmac_header_hash[i]);
				if(verbose) printf("\n");

				unsigned char *cmac_hash = (unsigned char*) malloc(0x10);
				memset(cmac_hash, 0, 0x10);

				cmac_hash_forge((header_buf + 0x10), 0x10, (header_buf + 0x60), 0x30, cmac_hash);
				if(verbose) printf("COMPUTED:    ");
				for (i = 0; i < 0x10; i++)
					if(verbose) printf("%02X", cmac_hash[i]);
				if(verbose) printf("\n");
				
				//Check header cmac.
				if (memcmp(cmac_hash, cmac_header->cmac_header_hash, 0x10))
				{
					if(verbose) printf("STATUS: FAIL\n");
					fclose(in);
					fclose(out);
					return 0;
				}
				else
					if(verbose) printf("STATUS: OK\n");

				if(verbose) printf("BLOCK CMAC:  ");
				for (i = 0; i < 0x10; i++)
					if(verbose) printf("%02X", cmac_header->cmac_block_hash[i]);
				if(verbose) printf("\n");

				memset(cmac_hash, 0, 0x10);
		
				unsigned int block_buf_size = 0x30 + header->data_offset + header->data_size + pad_size;
				unsigned char *block_buf = (unsigned char *) malloc(block_buf_size);
				memset(block_buf, 0, block_buf_size);
				fseek(in, header_offset + 0x60, SEEK_SET);
				fread(block_buf, block_buf_size , 1, in);
		
				cmac_hash_forge((header_buf + 0x10), 0x10, block_buf, block_buf_size, cmac_hash);
				if(verbose) printf("COMPUTED:    ");
				for (i = 0x0; i < 0x10; i++)
					if(verbose) printf("%02X", cmac_hash[i]);
				if(verbose) printf("\n");
				
				//Check block cmac.
				if (memcmp(cmac_hash, cmac_header->cmac_block_hash, 0x10))
				{
					if(verbose) printf("STATUS: FAIL\n");
					fclose(in);
					fclose(out);
					return 0;
				}
				else
					if(verbose) printf("STATUS: OK\n");
			
				free(block_buf);
				blocks++;
			}
			else if (header->mode == ECDSA_MODE)
			{
				if(verbose) printf("Kirk mode: ECDSA\n");
				ECDSA_KEY_HEADER* ecdsa_header = (ECDSA_KEY_HEADER*)header->key_header;
			
				//Decrypt keys.
				decrypt_header(header_buf, 0x10);
			
				int i;
				if(verbose) printf("CIPHER KEY:  ");
				for (i = 0; i < 0x10; i++)
					if(verbose) printf("%02X", ecdsa_header->aes_key[i]);
				if(verbose) printf("\n");
				
				//Header Signature
				if(verbose) printf("HEADER SIGNATURE:\n");
				if(verbose) printf("R:   ");
				for (i = 0; i < 0x14; i++)
					if(verbose) printf("%02X", ecdsa_header->header_sig_r[i]);
				if(verbose) printf("\n");
				if(verbose) printf("S:   ");
				for (i = 0; i < 0x14; i++)
					if(verbose) printf("%02X", ecdsa_header->header_sig_s[i]);
				if(verbose) printf("\n");
			
				unsigned char header_hash[0x14];
				memset(header_hash, 0, 0x14);
				sha1((header_buf + 0x60), 0x30, header_hash);
			
				// Setup ECDSA curve and public key.
				ecdsa_set_curve(kirk1_p, kirk1_a, kirk1_b, kirk1_N, kirk1_Gx, kirk1_Gy);
				unsigned char kirk1_pub[0x28];
				memset(kirk1_pub, 0, 0x28);			
				ec_priv_to_pub(kirk1_priv, kirk1_pub);
				ecdsa_set_pub(kirk1_pub);
			
				// Setup signature
				unsigned char signature_r[0x15];
				unsigned char signature_s[0x15];
				memset(signature_r, 0, 0x15);
				memset(signature_s, 0, 0x15);
				memcpy(signature_r + 01, ecdsa_header->header_sig_r, 0x14);
				memcpy(signature_s + 01, ecdsa_header->header_sig_s, 0x14);
				
				//Check header signature
				if (!ecdsa_verify(header_hash, signature_r, signature_s))
				{
					if(verbose) printf("STATUS: FAIL\n");
					fclose(in);
					fclose(out);
					return 0;
				}
				else
					if(verbose) printf("STATUS: OK\n");
				
				//Block Signature
				if(verbose) printf("BLOCK SIGNATURE:\n");
				if(verbose) printf("R:   ");
				for (i = 0; i < 0x14; i++)
					if(verbose) printf("%02X", ecdsa_header->block_sig_r[i]);
				if(verbose) printf("\n");
				if(verbose) printf("S:   ");
				for (i = 0; i < 0x14; i++)
					if(verbose) printf("%02X", ecdsa_header->block_sig_s[i]);
				if(verbose) printf("\n");

				unsigned char block_hash[0x14];
				memset(block_hash, 0, 0x14);
			
				unsigned int block_buf_size = 0x30 + header->data_offset + header->data_size + pad_size;
				unsigned char *block_buf = (unsigned char*) malloc(block_buf_size);
				memset(block_buf, 0, block_buf_size);
				fseek(in, header_offset + 0x60, SEEK_SET);
				fread(block_buf, block_buf_size , 1, in);
				sha1(block_buf, block_buf_size, block_hash);

				// Setup signature
				memset(signature_r, 0, 0x15);
				memset(signature_s, 0, 0x15);
				memcpy(signature_r + 01, ecdsa_header->block_sig_r, 0x14);
				memcpy(signature_s + 01, ecdsa_header->block_sig_s, 0x14);

				//Check block signature
				if (!ecdsa_verify(block_hash, signature_r, signature_s))
				{
					if(verbose) printf("STATUS: FAIL\n");
					fclose(in);
					fclose(out);
					return 0;
				}
				else
					if(verbose) printf("STATUS: OK\n");
			}
			else
			{
					if(verbose) printf("Error! Unknown Kirk mode.\n");
					fclose(in);
					fclose(out);
					return 0;
			}
		
		
			//Decrypt data
			if(verbose) printf("Encrypted data size:   0x%X\n", header->data_size);
			if(verbose) printf("Encrypted data offset: 0x%X\n", header->data_offset);
			real_data_offset = (header_offset + 0x90 + header->data_offset);
			if (!decrypt_data(in, real_data_offset, header->data_size, header->key_header, data_checksum, out))
			{
				if(verbose) printf("Error! decrypt_data() failed.\n");
				fclose(in);
				fclose(out);
				return 0;
			}
			else
				if(verbose) printf("Block decrypted.\n");
			
			header_offset = header_offset + 0x1000;
			if ((header_offset >= in_size) || header_offset < header->data_size )
				IsLastBlock = true;
			free(header_buf);
			
		}	
		printf("Data successfully decrypted!\nDecrypted %d blocks.\n", blocks);
		fclose(in);
		fclose(out);
	}
	else
		printf("Unknown mode, exiting\n");
	
	return 4; 
}             

