/*

  state[0]:  r60  r59  r58  r57  ...... r2   r1   r0     (61 bits) (lsb: r0)
  state[1]:  r106 r105 r104 r103 ...... r63  r62  r61    (46 bits) (lsb: r61)
  state[2]:  r153 r152 r151 r150 ...... r109 r108 r107   (47 bits) (lsb: r107)
  state[3]:  r192 r191 r190 r189 ...... r156 r155 r154   (39 bits) (lsb: r154)
  state[4]:  r229 r228 r227 r226 ...... r195 r194 r193   (37 bits) (lsb: r193)
  state[5]:  r288 r287 r286 r285 ...... r232 r231 r230   (59 bits) (lsb: r230)
  state[6]:  r292 r291 r290 r289                         (4  bits) (lsb: r289)
 */
#include <asm/unaligned.h>
#include <crypto/algapi.h>
#include <crypto/internal/aead.h>
#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>

#define ACORN_AUTH_SIZE 16
#define ACORN_KEY_SIZE 16
#define ACORN_BLOCK_SIZE 4 /// überprüfen
#define ACORN_NONCE_SIZE 16
#define ACORN_MAX_AUTH_SIZE 16

#define ACORN_STATE_BLOCKS 7
#define ACORN_KEY 4
#define ACORN_BLOCK_ALIGN (__alignof__(__le32))
#define ACORN_ALIGNED(p) IS_ALIGNED((uintptr_t)p, ACORN_BLOCK_ALIGN)


#define maj(x,y,z)   ( ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)) )
#define ch(x,y,z)    ( ((x) & (y)) ^ ((~x) & (z)) )


struct acorn_block {
	u32 word;
};

struct acorn_state_block{
	u64 word;
};

struct acorn_state {
	struct acorn_state_block s[ACORN_STATE_BLOCKS];
};

struct acorn_ctx {
	struct acorn_block key[ACORN_KEY]; 
};

union acorn_block_in {
	__le32 words[ACORN_STATE_BLOCKS]; 
	u8 bytes[ACORN_BLOCK_SIZE];
};

struct acorn_ops {
	int (*skcipher_walk_init)(struct skcipher_walk *walk,
			struct aead_request *req, bool atomic);

	void (*crypt_chunk)(unsigned long long *state,
			u8 *dst, const u8 *src, unsigned int size,unsigned int clen);
};

static void encrypt_32bits(unsigned long long *state, unsigned int src, unsigned int *dst, unsigned int ca, unsigned int cb)  
{
	unsigned int f,ks;
	unsigned long long  word_244, word_23, word_160, word_111, word_66, word_196,word_12,word_235;

	word_235 = state[5] >> 5;
	word_196 = state[4] >> 3;
	word_160 = state[3] >> 6;
	word_111 = state[2] >> 4;
	word_66  = state[1] >> 5;
	word_23  = state[0] >> 23;
	word_244 = state[5] >> 14;
	word_12  = state[0] >> 12;

	//update using those 6 LFSRs
	state[6] ^= (state[5] ^ word_235) & 0xffffffff;
	state[5] ^= (state[4] ^ word_196) & 0xffffffff;
	state[4] ^= (state[3] ^ word_160) & 0xffffffff;
	state[3] ^= (state[2] ^ word_111) & 0xffffffff;
	state[2] ^= (state[1] ^ word_66)  & 0xffffffff;
	state[1] ^= (state[0] ^ word_23)  & 0xffffffff;



	//compute keystream
	ks = word_12 ^ state[3] ^ maj(word_235, state[1], state[4]) ^ ch(state[5], word_111, word_66);

	f = state[0] ^ (~state[2]) ^ maj(word_244, word_23, word_160) ^ (word_196 & ca) ^ (cb & ks);
	*dst = src ^ ks;
	f = f ^ src;
	//printf("f \n %d", f);
	state[6] = state[6] ^ ( (unsigned long long)f << 4 );

	//shift by 32 bits
	state[0] = (state[0] >> 32) | ((state[1] & 0xffffffff) << 29);  //32-(64-61) = 29
	state[1] = (state[1] >> 32) | ((state[2] & 0xffffffff) << 14);  //32-(64-46) = 14
	state[2] = (state[2] >> 32) | ((state[3] & 0xffffffff) << 15);  //32-(64-47) = 15
	state[3] = (state[3] >> 32) | ((state[4] & 0xffffffff) << 7);   //32-(64-39) = 7
	state[4] = (state[4] >> 32) | ((state[5] & 0xffffffff) << 5);   //32-(64-37) = 5
	state[5] = (state[5] >> 32) | ((state[6] & 0xffffffff) << 27);  //32-(64-59) = 27
	state[6] =  state[6] >> 32;

	return;
}

static void encrypt_32bits_fast(unsigned long long *state, unsigned int src, unsigned int *dst, unsigned int ca, unsigned int cb)
{
	unsigned int f, ks;
	u64 word_244, word_23, word_160, word_111, word_66, word_196,word_12,word_235;
	printk("anfang encrypt_32bits_fast");

	word_235 = state[5] >> 5;
	word_196 = state[4] >> 3;
	word_160 = state[3] >> 6;
	word_111 = state[2] >> 4;
	word_66  = state[1] >> 5;
	word_23  = state[0] >> 23;
	word_244 = state[5] >> 14;
	word_12  = state[0] >> 12;

	//update using those 6 LFSRs
	state[6] ^= (state[5] ^ word_235) & 0xffffffff;
	state[5] ^= (state[4] ^ word_196) & 0xffffffff;
	state[4] ^= (state[3] ^ word_160) & 0xffffffff;
	state[3] ^= (state[2] ^ word_111) & 0xffffffff;
	state[2] ^= (state[1] ^ word_66)  & 0xffffffff;
	state[1] ^= (state[0] ^ word_23)  & 0xffffffff;

	//compute keystream
	ks = word_12 ^ state[3] ^ maj(word_235, state[1], state[4]) ^ ch(state[5], word_111, word_66);

	//f  = state[0] ^ (state[107] ^ 1) ^ maj(state[244], state[23], state[160]) ^ ch(state[230], state[111], state[66]) ^ (ca & state[196]) ^ (cb & (*ks));
	f = state[0] ^ (~state[2]) ^ maj(word_244, word_23, word_160) ^ (word_196 & ca);  // ^ (cb & *ks);
	*dst = src ^ ks;
	f = f ^ src;
	state[6] = state[6] ^ ( (unsigned long long)f << 4 );

	//shift by 32 bits
	state[0] = (state[0] >> 32) | ((state[1] & 0xffffffff) << 29);  //32-(64-61) = 29
	state[1] = (state[1] >> 32) | ((state[2] & 0xffffffff) << 14);  //32-(64-46) = 14
	state[2] = (state[2] >> 32) | ((state[3] & 0xffffffff) << 15);  //32-(64-47) = 15
	state[3] = (state[3] >> 32) | ((state[4] & 0xffffffff) << 7);   //32-(64-39) = 7
	state[4] = (state[4] >> 32) | ((state[5] & 0xffffffff) << 5);   //32-(64-37) = 5
	state[5] = (state[5] >> 32) | ((state[6] & 0xffffffff) << 27);  //32-(64-59) = 27
	state[6] =  state[6] >> 32;

	//perform encryption

	return;
	printk("ende encrypt_32bits_fast");
	return;
}

static void decrypt_32bits_fast(unsigned long long *state, unsigned int *src, unsigned int dst, unsigned int ca, unsigned int cb)
{

	unsigned int f, ks;
	unsigned long long word_244, word_23, word_160, word_111, word_66, word_196,word_12,word_235;

	printk("anfang decrypt_32bits_fast");
	//f  = state[0] ^ (state[107] ^ 1) ^ maj(state[244], state[23], state[160]) ^ ch(state[230], state[111], state[66]) ^ (ca & state[196]) ^ (cb & (*ks));

	word_12  = state[0] >> 12;
	word_235 = state[5] >> 5;
	word_244 = state[5] >> 14;
	word_23  = state[0] >> 23;
	word_160 = state[3] >> 6;
	word_111 = state[2] >> 4;
	word_66  = state[1] >> 5;
	word_196 = state[4] >> 3;

	state[6] ^= (state[5] ^ word_235) & 0xffffffff;
	state[5] ^= (state[4] ^ word_196) & 0xffffffff;
	state[4] ^= (state[3] ^ word_160) & 0xffffffff;
	state[3] ^= (state[2] ^ word_111) & 0xffffffff;
	state[2] ^= (state[1] ^ word_66)  & 0xffffffff;
	state[1] ^= (state[0] ^ word_23)  & 0xffffffff;


	ks = word_12 ^ state[3] ^ maj(word_235, state[1], state[4]) ^ ch(state[5], word_111, word_66) ;
	f = state[0] ^ (~state[2]) ^ maj(word_244, word_23, word_160) ^ (word_196 & ca); 
	*src = dst ^ ks;
	f  = f ^ *src;
	state[6] = state[6] ^ ( (unsigned long long)f << 4 );


	state[0] = (state[0] >> 32) | ((state[1] & 0xffffffff) << 29);  //32-(64-61) = 29
	state[1] = (state[1] >> 32) | ((state[2] & 0xffffffff) << 14);  //32-(64-46) = 14
	state[2] = (state[2] >> 32) | ((state[3] & 0xffffffff) << 15);  //32-(64-47) = 15
	state[3] = (state[3] >> 32) | ((state[4] & 0xffffffff) << 7);   //32-(64-39) = 7
	state[4] = (state[4] >> 32) | ((state[5] & 0xffffffff) << 5);   //32-(64-37) = 5
	state[5] = (state[5] >> 32) | ((state[6] & 0xffffffff) << 27);  //32-(64-59) = 27
	state[6] =  state[6] >> 32;


	printk("ende decrypt_32bits_fast");
	return;
}

static void encrypt_8bits(unsigned long long *state, unsigned int src, unsigned int *dst, unsigned int ca, unsigned int cb)
{
	unsigned int f,ks;
	unsigned long long word_244, word_23, word_160, word_111, word_66, word_196,word_12,word_235;


	//f  = state[0] ^ (state[107] ^ 1) ^ maj(state[244], state[23], state[160]) ^ ch(state[230], state[111], state[66]) ^ (ca & state[196]) ^ (cb & (*ks));
	word_12  = state[0] >> 12;
	word_235 = state[5] >> 5;
	word_244 = state[5] >> 14;
	word_23  = state[0] >> 23;
	word_160 = state[3] >> 6;
	word_111 = state[2] >> 4;
	word_66  = state[1] >> 5;
	word_196 = state[4] >> 3;

	state[6] ^= (state[5] ^ word_235) & 0xff;
	state[5] ^= (state[4] ^ word_196) & 0xff;
	state[4] ^= (state[3] ^ word_160) & 0xff;
	state[3] ^= (state[2] ^ word_111) & 0xff;
	state[2] ^= (state[1] ^ word_66)  & 0xff;
	state[1] ^= (state[0] ^ word_23)  & 0xff;

	ks = word_12 ^ state[3] ^ maj(word_235, state[1], state[4]) ^ ch(state[5], word_111, word_66);
	ks &= 0xff;

	f = state[0] ^ (~state[2]) ^ maj(word_244, word_23, word_160) ^ (word_196 & ca) ^ (cb & ks);
	f  = (f ^ src) & 0xff;
	state[6] = state[6] ^ ( (unsigned long long)f << 4 );

	state[0] = (state[0] >> 8) | ((state[1] & 0xff) << (29+24));   //32-(64-61) = 29
	state[1] = (state[1] >> 8) | ((state[2] & 0xff) << (14+24));   //32-(64-46) = 14
	state[2] = (state[2] >> 8) | ((state[3] & 0xff) << (15+24));   //32-(64-47) = 15
	state[3] = (state[3] >> 8) | ((state[4] & 0xff) << (7+24));    //32-(64-39) = 7
	state[4] = (state[4] >> 8) | ((state[5] & 0xff) << (5+24));    //32-(64-37) = 5
	state[5] = (state[5] >> 8) | ((state[6] & 0xff) << (27+24));    //32-(64-59) = 27
	state[6] =  state[6] >> 8;

	*dst = src ^ ks;
	return;
}

static void decrypt_8bits(unsigned long long *state, unsigned int *src, unsigned int dst, unsigned int ca, unsigned int cb)
{
	unsigned int f, ks;
	unsigned long long word_244, word_23, word_160, word_111, word_66, word_196, word_0, word_107, word_230;
	unsigned long long word_12,word_154,word_235,word_61,word_193;

	word_12  = state[0] >> 12;
	word_235 = state[5] >> 5;
	word_244 = state[5] >> 14;
	word_23  = state[0] >> 23;
	word_160 = state[3] >> 6;
	word_111 = state[2] >> 4;
	word_66  = state[1] >> 5;
	word_196 = state[4] >> 3;

	state[6] ^= (state[5] ^ word_235) & 0xff;
	state[5] ^= (state[4] ^ word_196) & 0xff;
	state[4] ^= (state[3] ^ word_160) & 0xff;
	state[3] ^= (state[2] ^ word_111) & 0xff;
	state[2] ^= (state[1] ^ word_66)  & 0xff;
	state[1] ^= (state[0] ^ word_23)  & 0xff;

	word_0   = state[0];
	word_107 = state[2];
	word_230 = state[5];
	word_154 = state[3];
	word_61  = state[1];
	word_193 = state[4];

	ks = word_12 ^ state[3] ^ maj(word_235, state[1], state[4]) ^ ch(state[5], word_111, word_66);
	ks &= 0xff;
	f = state[0] ^ (~state[2]) ^ maj(word_244, word_23, word_160) ^ (word_196 & ca) ^ (cb & ks);
	*src = dst ^ ks;
	f  = (f ^ *src) & 0xff;
	state[6] = state[6] ^ ( (unsigned long long)f << 4 );

	state[0] = (state[0] >> 8) | ((state[1] & 0xff) << (29+24));   //32-(64-61) = 29
	state[1] = (state[1] >> 8) | ((state[2] & 0xff) << (14+24));   //32-(64-46) = 14
	state[2] = (state[2] >> 8) | ((state[3] & 0xff) << (15+24));   //32-(64-47) = 15
	state[3] = (state[3] >> 8) | ((state[4] & 0xff) << (7+24));    //32-(64-39) = 7
	state[4] = (state[4] >> 8) | ((state[5] & 0xff) << (5+24));    //32-(64-37) = 5
	state[5] = (state[5] >> 8) | ((state[6] & 0xff) << (27+24));    //32-(64-59) = 27
	state[6] =  state[6] >> 8;

	return;
}

static void acorn128_padding_256(unsigned long long *state, unsigned int cb)
{
	unsigned int i, plaintextword, ciphertextword, ca;

	plaintextword = 1;
	ca = 0xffffffff;
	encrypt_32bits(state, plaintextword, &ciphertextword, ca, cb);

	plaintextword = 0;
	for (i = 1; i <= 3; i++) encrypt_32bits(state, plaintextword, &ciphertextword, ca, cb);

	ca = 0;
	for (i = 4; i <= 7; i++) encrypt_32bits(state, plaintextword, &ciphertextword, ca, cb);

}


static void crypto_acorn_load_ak(struct acorn_ctx *dst, const u8 *src)
{
	unsigned int i;
	for (i = 0; i < 4; i++) {

		dst->key[i].word = le32_to_cpu(*(const __le32 *)src);
		printk("%d load_a",dst->key[i].word);
		src += 4;
	}
}

static void crypto_acorn_load_uk(struct acorn_ctx *dst, const u8 *src)
{
	unsigned int i;
	for (i = 0; i < 4; i++) {

		dst->key[i].word = get_unaligned_le32(src);
		printk("%d load_u",dst->key[i].word);
		src += 4;
	}
}

static void crypto_acorn_load_k(struct acorn_ctx *dst, const u8 *src)
{
	if (ACORN_ALIGNED(src))
		crypto_acorn_load_ak(dst, src);
	else
		crypto_acorn_load_uk(dst, src);
}

static void crypto_acorn_load_a(struct acorn_block *dst, const u8 *src)
{				
	dst->word = le32_to_cpu(*(const __le32 *)src);
	printk("%d load_a",dst->word);		
	src += 4;
}

static void crypto_acorn_load_u(struct acorn_block *dst, const u8 *src)
{
	dst->word = get_unaligned_le32(src);
	printk("%d load_u",dst->word);	
	src += 4;
}

static void crypto_acorn_store_a(u8 *dst, const struct acorn_block *src)
{	
	*(__le32 *)dst = cpu_to_le32(src->word);
	dst += 4;
}

static void crypto_acorn_store_u(u8 *dst, const struct acorn_block *src)
{
	put_unaligned_le32(src->word, dst);
	dst += 4;
}


static void crypto_acorn_store(u8 *dst, const struct acorn_block *src)
{
	if (ACORN_ALIGNED(dst))
		crypto_acorn_store_a(dst, src);
	else
		crypto_acorn_store_u(dst, src);
}


static void crypto_acorn_ad(unsigned long long *state, const u8 *src,
		unsigned int size,unsigned int ca ,unsigned int cb)
{
	struct acorn_block m,c;
	printk("anfang crypto_acorn_ad");
	c.word=0;
	if (ACORN_ALIGNED(src)) {
		while (size >= ACORN_BLOCK_SIZE) {
			crypto_acorn_load_a(&m,src);
			encrypt_32bits(state,m.word, &c.word, ca, cb); 

			size -= ACORN_BLOCK_SIZE;	
			src += ACORN_BLOCK_SIZE;
			printk("ende crypto_acorn_ad1");	
		}
	} else {
		while (size >= ACORN_BLOCK_SIZE) {
			crypto_acorn_load_u(&m,src);
			encrypt_32bits(state,m.word,&c.word, ca, cb);

			size -= ACORN_BLOCK_SIZE;	
			src += ACORN_BLOCK_SIZE;
			printk("ende crypto_acorn_ad2");
		}
	}
}

static void crypto_acorn_encrypt_chunk(unsigned long long *state, u8 *dst,
		const u8 *src, unsigned int size,unsigned int clen)
{
	struct acorn_block m,c;
	unsigned int ca = 0xffffffff;
	unsigned int cb = 0;
	int i;
	c.word=0;
	printk("anfang crypto_acorn_encrypt_chunk");
	if (ACORN_ALIGNED(src) && ACORN_ALIGNED(dst)) {
		while (size >= ACORN_BLOCK_SIZE) {

			crypto_acorn_load_a(&m,src);
			encrypt_32bits_fast(state,m.word,&c.word, ca, cb); 
			crypto_acorn_store_a(dst,&c);

			src += ACORN_BLOCK_SIZE;
			dst += ACORN_BLOCK_SIZE;
			size -= ACORN_BLOCK_SIZE;
			printk("ende crypto_acorn_encrypt_chunk1");
		}
	} else {
		while (size >= ACORN_BLOCK_SIZE) {

			crypto_acorn_load_u(&m,src);			
			encrypt_32bits_fast(state,m.word,&c.word, ca, cb); 
			crypto_acorn_store_u(dst,&c);

			src += ACORN_BLOCK_SIZE;
			dst += ACORN_BLOCK_SIZE;
			size -= ACORN_BLOCK_SIZE;
			printk("ende crypto_acorn_encrypt_chunk2");
		}

	}
	for (i = 0; i <= 6; i++){
		printk("State nach encryption ENDE %d %lld \n",i, state[i]);
	}
	if (size > 0) {
		union acorn_block_in tail;
		printk("ende crypto_acorn_encrypt_chunk3");
		memcpy(tail.bytes, src, size);
		memset(tail.bytes + size, 0, ACORN_BLOCK_SIZE - size);

		for(i=0;i<size;i++)
		{
			crypto_acorn_load_a(&m,tail.bytes);
			encrypt_8bits(state,m.word, &c.word, ca, cb);
			crypto_acorn_store_a(tail.bytes,&c);
			dst+=1;
			src+=1;
		}

		for (i = 0; i <= 6; i++){
			printk("State encryption 8bit ENDE %d %lld \n",i, state[i]);
		}
		memcpy(dst, tail.bytes, size);
		printk("ende crypto_acorn_encrypt_chunk3");
	}
	acorn128_padding_256(state,cb);
	for (i = 0; i <= 6; i++){
		printk("State encryption mit padding ENDE %d %lld \n",i, state[i]);
	}

}

static void crypto_acorn_decrypt_chunk(unsigned long long *state, u8 *dst,
		const u8 *src, unsigned int size,unsigned int clen)
{
	unsigned int ca = 0xffffffff;
	unsigned int cb = 0;
	int i;
	struct acorn_block m,c;
	m.word=0;
	printk("anfang crypto_acorn_decrypt_chunk");
	//size=clen-16;
	//printk("size %d",size);
	if (ACORN_ALIGNED(src) && ACORN_ALIGNED(dst)) {
		while (size >= ACORN_BLOCK_SIZE) {

			crypto_acorn_load_a(&c,src);
			decrypt_32bits_fast(state, &m.word, c.word, ca, cb); 

			for (i = 0; i <= 6; i++){
				printk("State ENDE nach decryption%d %lld \n",i, state[i]);
			}
			src += ACORN_BLOCK_SIZE;
			dst += ACORN_BLOCK_SIZE;
			size -= ACORN_BLOCK_SIZE;
			printk("ende crypto_acorn_decrypt_chunk1");
		}
	} else {
		while (size >= ACORN_BLOCK_SIZE) {

			crypto_acorn_load_u(&c,src);
			decrypt_32bits_fast(state, &m.word, c.word, ca, cb); 
			for (i = 0; i <= 6; i++){
				printk("State ENDE nach decryption %d %lld \n",i, state[i]);
			}
			src += ACORN_BLOCK_SIZE;
			dst += ACORN_BLOCK_SIZE;
			size -= ACORN_BLOCK_SIZE;
			printk("ende crypto_acorn_decrypt_chunk2");
		}
	}

	if (size > 0) {
		union acorn_block_in tail;

		memcpy(tail.bytes, src, size);
		memset(tail.bytes + size, 0, ACORN_BLOCK_SIZE - size);
		for(i=0;i<size;i++)
		{
			crypto_acorn_load_a(&c,tail.bytes);
			decrypt_8bits(state,&m.word, c.word, ca, cb);
			src+=1;
		}

		memcpy(dst, tail.bytes, size);
		printk("ende crypto_acorn_decrypt_chunk3");
	}
	acorn128_padding_256(state,cb);
}

static void crypto_acorn_init(unsigned long long *state,
		struct acorn_block *key,
		const u8 *iv)
{
	int j;
	unsigned int tmp = 0;

	printk("anfang crypto_acorn_init");
	//crypto_acorn_load(state, iv);

	for (j = 0; j <= 6; j++)state[j] = 0;


	//run the cipher for 1792 steps
	for (j = 0;  j <= 3;  j++)
	{
		/////((unsigned int*)key)[j]
		encrypt_32bits(state,((unsigned int*)key)[j], &tmp, 0xffffffff, 0xffffffff);

	}
	for (j = 4;  j <= 7;  j++)
	{	
		//iv wird geladen
		encrypt_32bits(state,((unsigned int*)iv)[j-4], &tmp, 0xffffffff, 0xffffffff); //fehler

	}

	for (j = 8;  j <= 8; j++)
	{
		encrypt_32bits(state,((unsigned int*)key)[j&3] ^ 1, &tmp, 0xffffffff, 0xffffffff);

	}

	for (j = 9;  j <= 55; j++)
	{		
		encrypt_32bits(state,((unsigned int*)key)[j&3],&tmp, 0xffffffff, 0xffffffff);

	}

	for (j = 0; j <= 6; j++){
		printk("State init ENDE %d %lld \n",j, state[j]);
	}
	printk("ende crypto_acorn_init");
}

static void crypto_acorn_process_ad(unsigned long long *state,
		struct scatterlist *sg_src,
		unsigned int assoclen,unsigned int cryptlen)
{
	struct scatter_walk walk;
	struct acorn_block m,c; 
	union acorn_block_in buf;
	unsigned int pos = 0;
	unsigned int ca = 0xffffffff;
	unsigned int cb = 0xffffffff;
	int j;

	printk("anfang crypto_acorn_process_ad");
	scatterwalk_start(&walk, sg_src);

	while (assoclen != 0) {
		unsigned int size = scatterwalk_clamp(&walk, assoclen); 
		unsigned int left = size; 
		void *mapped = scatterwalk_map(&walk);
		const u8 *src = (const u8 *)mapped;

		if (pos + size >= ACORN_BLOCK_SIZE) {
			if (pos > 0) {
				unsigned int fill = ACORN_BLOCK_SIZE - pos;
				memcpy(buf.bytes + pos, src, fill);

				for(j=0;j<pos;j++)
				{
					crypto_acorn_load_a(&m,buf.bytes);
					encrypt_8bits(state,m.word, &c.word, ca, cb); // in work
					src+=1;
				}

				pos = 0;
				left -= fill;
				src += fill;
				printk("ende crypto_acorn_process_ad1");
			}
			crypto_acorn_ad(state, src,left,ca,cb);  
			for (j = 0; j <= 6; j++){
				printk("State nach acorn_ad %d %lld \n",j, state[j]);
			}
			src += left & ~(ACORN_BLOCK_SIZE - 1);
			left &= ACORN_BLOCK_SIZE - 1;
			printk("ende crypto_acorn_process_ad2");
		}

		memcpy(buf.bytes + pos, src, left);
		pos += left;
		assoclen -= size;
		scatterwalk_unmap(mapped);
		scatterwalk_advance(&walk, size);
		scatterwalk_done(&walk, 0, assoclen);
		printk("ich war hier1");
	}

	if (pos> 0) {
		memset(buf.bytes + pos, 0, ACORN_BLOCK_SIZE - pos);
		for(j=0;j<pos;j++)
		{
			crypto_acorn_load_a(&m,buf.bytes);
			encrypt_8bits(state,m.word, &c.word, ca, cb);
		}
		printk("ende crypto_acorn_process_ad3");
	}
	for (j = 0; j <= 6; j++){
		printk("State vor padding %d %lld \n",j, state[j]);
	}
	acorn128_padding_256(state,cb);
	for (j = 0; j <= 6; j++){
		printk("State nach padding %d %lld \n",j, state[j]);
	}
	printk("ende crypto_acorn_process_ad4");
}

static void crypto_acorn_process_crypt(unsigned long long *state,
		struct aead_request *req,
		const struct acorn_ops *ops)
{
	struct skcipher_walk walk;
	u8 *dst;	
	const u8 *src;
	unsigned int clen =req->cryptlen + req->assoclen; //clen is defined as clen=msglen+adlen  msglen=crypt+adlen
	printk("assoclen %d",req->assoclen);
	printk("cryptlen %d",req->cryptlen);

	ops->skcipher_walk_init(&walk, req, false);
	printk("anfang crypto_acorn_process_crypt");
	printk("walk.nbytes %d",walk.nbytes);
	while (walk.nbytes) {

		src = walk.src.virt.addr; 
		dst = walk.dst.virt.addr;
		ops->crypt_chunk(state,dst,src,walk.nbytes,clen);
		skcipher_walk_done(&walk, 0);
	}
	printk("ende crypto_acorn_process_crypt");
}

static void crypto_acorn_final(unsigned long long *state,
		struct acorn_block *tag_xor,
		u64 assoclen, u64 cryptlen)
{
	int i;
	unsigned int ksword = 0;
	unsigned char mac[16];
	unsigned int plaintextword  = 0;
	tag_xor->word=0;


	printk("anfang crypto_acorn_final");
	for (i = 0; i <= 6; i++){
		printk("State vor final ENDE %d %lld \n",i, state[i]);
	}
	for (i = 0; i < 768/32; i++)
	{

		encrypt_32bits(state, plaintextword, &tag_xor->word, 0xffffffff, 0xffffffff);
		if ( i >= (768/(32 - 4)) ) { ((unsigned int*)mac)[i-(768/(32-4))] = tag_xor->word; }
	}
	for (i = 0; i <= 6; i++){
		printk("State final ENDE %d %lld \n",i, state[i]);
	}
	printk("ende crypto_acorn_final");
}
//adlen=assoclen msglen=cryptlen
static void crypto_acorn_crypt(struct aead_request *req,
		struct acorn_block *tag_xor,
		unsigned int cryptlen,
		const struct acorn_ops *ops)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct acorn_ctx *ctx = crypto_aead_ctx(tfm);
	//struct acorn_state state;
	unsigned long long state[7];
	unsigned int j;
	printk("anfang crypto_acorn_crypt\n");
	crypto_acorn_init(state, ctx->key, req->iv);
	crypto_acorn_process_ad(state, req->src, req->assoclen,req->cryptlen);
	crypto_acorn_process_crypt(state, req, ops);
	crypto_acorn_final(state, tag_xor, req->assoclen, cryptlen);
	for (j = 0; j <= 6; j++){
		printk("State ENDE ENDE %d %lld \n",j, state[j]);
	}
	printk("ende crypto_acorn_crypt");

}

static int crypto_acorn_encrypt(struct aead_request *req)
{
	static const struct acorn_ops ops = {
			.skcipher_walk_init = skcipher_walk_aead_encrypt,
			.crypt_chunk = crypto_acorn_encrypt_chunk,
	};

	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct acorn_block tag = {}; 
	union acorn_block_in tag_out; 
	unsigned int authsize = crypto_aead_authsize(tfm);
	unsigned int cryptlen = req->cryptlen;
	printk("anfang crypto_acorn_encrypt");
	crypto_acorn_crypt(req, &tag, cryptlen, &ops);
	crypto_acorn_store(tag_out.bytes, &tag);
	printk("assoclen %d cryptlen %d",req->assoclen,req->cryptlen);

	scatterwalk_map_and_copy(tag_out.bytes, req->dst,
			req->assoclen + cryptlen, authsize, 1);

	printk("ende crypto_acorn_encrypt\n");
	return 0;
}

static int crypto_acorn_decrypt(struct aead_request *req)
{
	static const struct acorn_ops ops = {
			.skcipher_walk_init = skcipher_walk_aead_decrypt,
			.crypt_chunk = crypto_acorn_decrypt_chunk,
	};
	static const u8 zeros[ACORN_BLOCK_SIZE] = {};

	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	union acorn_block_in tag_in;
	struct acorn_block tag;
	unsigned int authsize = crypto_aead_authsize(tfm);
	unsigned int cryptlen = req->cryptlen - authsize;
	printk("anfang crypto_acorn_decrypt");
	scatterwalk_map_and_copy(tag_in.bytes, req->src,
			req->assoclen + cryptlen, authsize, 0);

	printk("decryption beginnt");
	crypto_acorn_crypt(req, &tag, cryptlen, &ops);
	printk("ende crypto_acorn_decrypt");
	return crypto_memneq(tag_in.bytes, zeros, authsize) ? -EBADMSG : 0;
}

static int crypto_acorn_setkey(struct crypto_aead *aead, const u8 *key,
		unsigned int keylen)
{
	struct acorn_ctx *ctx = crypto_aead_ctx(aead);
	if (keylen != ACORN_KEY_SIZE) {
		crypto_aead_set_flags(aead, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}


	crypto_acorn_load_k(ctx, key);
	printk("ende crypto_acorn_setkey");
	return 0;
}

static int crypto_acorn_setauthsize(struct crypto_aead *tfm,
		unsigned int authsize)
{	
	printk("anfang crypto_acorn_setauthsize");
	return (authsize <= ACORN_AUTH_SIZE) ? 0 : -EINVAL;
}

static int crypto_acorn_init_tfm(struct crypto_aead *tfm)
{	
	printk("anfang crypto_acorn_init_tfm");
	return 0;
}

static void crypto_acorn_exit_tfm(struct crypto_aead *tfm)
{
}

static struct aead_alg crypto_acorn_alg = {
		.setkey = crypto_acorn_setkey,
		.setauthsize = crypto_acorn_setauthsize,
		.encrypt = crypto_acorn_encrypt,
		.decrypt = crypto_acorn_decrypt,
		.init = crypto_acorn_init_tfm,
		.exit = crypto_acorn_exit_tfm,

		.ivsize = ACORN_NONCE_SIZE,
		.maxauthsize = ACORN_MAX_AUTH_SIZE,
		.chunksize = ACORN_BLOCK_SIZE,

		.base = {
				.cra_flags = CRYPTO_ALG_TYPE_AEAD,
				.cra_blocksize = 1,
				.cra_ctxsize = sizeof(struct acorn_ctx),
				.cra_alignmask = 0,

				.cra_priority = 100,

				.cra_name = "acorn",
				.cra_driver_name = "acorn-generic",

				.cra_module = THIS_MODULE,
		}
};


static int __init crypto_acorn_module_init(void)
{
	printk("ACORN wurde registriert");
	return crypto_register_aead(&crypto_acorn_alg);
}

static void __exit crypto_acorn_module_exit(void)
{	
	printk("ACORN wurde unregistriert");
	crypto_unregister_aead(&crypto_acorn_alg);
}

module_init(crypto_acorn_module_init);
module_exit(crypto_acorn_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gregor Garten");
MODULE_DESCRIPTION("ACORN AEAD algorithm");
MODULE_ALIAS_CRYPTO("acorn");
MODULE_ALIAS_CRYPTO("acorn");
