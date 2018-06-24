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

/* Notizen: Es wird nur die Msglen-adlen encrypted
im testvektor sind irgendwie ad[i] und msg[i] vertauscht

warum ist cipherword auf 28 und mac auf 29 initialisiert??

*/

struct acorn_block {
	u32 word; ///////////// keine ahnung was mit dem schlüssel passiert
};

struct acorn_state_block{
	u64 word;
};

struct acorn_state {
	struct acorn_state_block s[ACORN_STATE_BLOCKS]; ////////////////293
};

struct acorn_ctx {
	struct acorn_block key[ACORN_KEY]; /////128
};

union acorn_block_in {
	__le32 words[ACORN_STATE_BLOCKS]; //??????
	u8 bytes[ACORN_BLOCK_SIZE];
};

struct acorn_ops {
	int (*skcipher_walk_init)(struct skcipher_walk *walk,
				  struct aead_request *req, bool atomic);

	void (*crypt_chunk)(unsigned long long *state,
			    u8 *dst, const u8 *src, unsigned int size);
};

//src sender plaintextword ||| dst empfänger ciphertextword
////src und dst müssten eigentlich u16 haben?!?!?
/*static void encrypt_32bits(struct acorn_state *state, unsigned int src, unsigned int *dst, unsigned int ca, unsigned int cb)  
{
    unsigned int f,ks;
    u64 word_244, word_23, word_160, word_111, word_66, word_196,word_12,word_235;
	printk("%d cb \n",cb);
		word_235 = state->s[5].word >> 5;
	word_196 = state->s[4].word >> 3;
	word_160 = state->s[3].word >> 6;
	word_111 = state->s[2].word >> 4;
	word_66  = state->s[1].word >> 5;
	word_23  = state->s[0].word >> 23;
    word_244 = state->s[5].word >> 14;
	word_12  = state->s[0].word >> 12;

    //update using those 6 LFSRs
	state->s[6].word ^= (state->s[5].word ^ word_235) & 0xffffffff;
	state->s[5].word ^= (state->s[4].word ^ word_196) & 0xffffffff;
	state->s[4].word ^= (state->s[3].word ^ word_160) & 0xffffffff;
	state->s[3].word ^= (state->s[2].word ^ word_111) & 0xffffffff;
	state->s[2].word ^= (state->s[1].word ^ word_66)  & 0xffffffff;
	state->s[1].word ^= (state->s[0].word ^ word_23)  & 0xffffffff;



	//compute keystream
	ks = word_12 ^ state->s[3].word ^ maj(word_235, state->s[1].word, state->s[4].word) ^ ch(state->s[5].word, word_111, word_66);

	f = state->s[0].word ^ (~state->s[2].word) ^ maj(word_244, word_23, word_160) ^ (word_196 & ca) ^ (cb & ks);
    *dst = src ^ ks;
	f = f ^ src;
	//printf("f \n %d", f);
	state->s[6].word = state->s[6].word ^ ( (unsigned long long)f << 4 );

    //shift by 32 bits
    state->s[0].word = (state->s[0].word >> 32) | ((state->s[1].word & 0xffffffff) << 29);  //32-(64-61) = 29
    state->s[1].word = (state->s[1].word >> 32) | ((state->s[2].word & 0xffffffff) << 14);  //32-(64-46) = 14
    state->s[2].word = (state->s[2].word >> 32) | ((state->s[3].word & 0xffffffff) << 15);  //32-(64-47) = 15
    state->s[3].word = (state->s[3].word >> 32) | ((state->s[4].word & 0xffffffff) << 7);   //32-(64-39) = 7
    state->s[4].word = (state->s[4].word >> 32) | ((state->s[5].word & 0xffffffff) << 5);   //32-(64-37) = 5
    state->s[5].word = (state->s[5].word >> 32) | ((state->s[6].word & 0xffffffff) << 27);  //32-(64-59) = 27
    state->s[6].word =  state->s[6].word >> 32;
	
    return;
}*/


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
// welche größe ?? u32 ooder u8?????
/*static void encrypt_32bits_fast(struct acorn_state *state, unsigned int src, unsigned int *dst, unsigned int ca, unsigned int cb)
{
    unsigned int f, ks;
    u64 word_244, word_23, word_160, word_111, word_66, word_196,word_12,word_235;
	printk("anfang encrypt_32bits_fast");
	word_235 = state->s[5].word >> 5;
	word_196 = state->s[4].word >> 3;
	word_160 = state->s[3].word >> 6;
	word_111 = state->s[2].word >> 4;
	word_66  = state->s[1].word >> 5;
	word_23  = state->s[0].word >> 23;
   	word_244 = state->s[5].word >> 14;
	word_12  = state->s[0].word >> 12;

    //update using those 6 LFSRs
	state->s[6].word ^= (state->s[5].word ^ word_235) & 0xffffffff;
	state->s[5].word ^= (state->s[4].word ^ word_196) & 0xffffffff;
	state->s[4].word ^= (state->s[3].word ^ word_160) & 0xffffffff;
	state->s[3].word ^= (state->s[2].word ^ word_111) & 0xffffffff;
	state->s[2].word ^= (state->s[1].word ^ word_66)  & 0xffffffff;
	state->s[1].word ^= (state->s[0].word ^ word_23)  & 0xffffffff;

	//compute keystream
	ks = word_12 ^ state->s[3].word ^ maj(word_235, state->s[1].word, state->s[4].word) ^ ch(state->s[5].word, word_111, word_66);

    //f  = state[0] ^ (state[107] ^ 1) ^ maj(state[244], state[23], state[160]) ^ ch(state[230], state[111], state[66]) ^ (ca & state[196]) ^ (cb & (*ks));
	f = state->s[0].word ^ (~state->s[2].word) ^ maj(word_244, word_23, word_160) ^ (word_196 & ca);  // ^ (cb & *ks);
    	*dst = src ^ ks;
	f = f ^ src;
	state->s[6].word = state->s[6].word ^ ( (unsigned long long)f << 4 );

    //shift by 32 bits
    state->s[0].word = (state->s[0].word >> 32) | ((state->s[1].word & 0xffffffff) << 29);  //32-(64-61) = 29
    state->s[1].word = (state->s[1].word >> 32) | ((state->s[2].word & 0xffffffff) << 14);  //32-(64-46) = 14
    state->s[2].word = (state->s[2].word >> 32) | ((state->s[3].word & 0xffffffff) << 15);  //32-(64-47) = 15
    state->s[3].word = (state->s[3].word >> 32) | ((state->s[4].word & 0xffffffff) << 7);   //32-(64-39) = 7
    state->s[4].word = (state->s[4].word >> 32) | ((state->s[5].word & 0xffffffff) << 5);   //32-(64-37) = 5
    state->s[5].word = (state->s[5].word >> 32) | ((state->s[6].word & 0xffffffff) << 27);  //32-(64-59) = 27
    state->s[6].word =  state->s[6].word >> 32;

    //perform encryption
	printk("ende encrypt_32bits_fast");
    return;
}*/

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

	/*
    word_0   = state[0];
    word_107 = state[2];
    word_230 = state[5];
    word_154 = state[3];
    word_61  = state[1];
    word_193 = state[4];
    */

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
static void decrypt_32bits_fast(struct acorn_state *state, struct acorn_block *src, struct acorn_block *dst, unsigned int ca, unsigned int cb)
{

    unsigned int f, ks;
    unsigned long long word_244, word_23, word_160, word_111, word_66, word_196,word_12,word_235;

	printk("anfang decrypt_32bits_fast");
    //f  = state[0] ^ (state[107] ^ 1) ^ maj(state[244], state[23], state[160]) ^ ch(state[230], state[111], state[66]) ^ (ca & state[196]) ^ (cb & (*ks));

    word_12  = state->s[0].word >> 12;
    word_235 = state->s[5].word >> 5;
    word_244 = state->s[5].word >> 14;
    word_23  = state->s[0].word >> 23;
    word_160 = state->s[3].word >> 6;
    word_111 = state->s[2].word >> 4;
    word_66  = state->s[1].word >> 5;
    word_196 = state->s[4].word >> 3;

	state->s[6].word ^= (state->s[5].word ^ word_235) & 0xffffffff;
	state->s[5].word ^= (state->s[4].word ^ word_196) & 0xffffffff;
	state->s[4].word ^= (state->s[3].word ^ word_160) & 0xffffffff;
	state->s[3].word ^= (state->s[2].word ^ word_111) & 0xffffffff;
	state->s[2].word ^= (state->s[1].word ^ word_66)  & 0xffffffff;
	state->s[1].word ^= (state->s[0].word ^ word_23)  & 0xffffffff;

	/*
    word_0   = state[0];
    word_107 = state[2];
    word_230 = state[5];
    word_154 = state[3];
    word_61  = state[1];
    word_193 = state[4];
    */

	ks = word_12 ^ state->s[3].word ^ maj(word_235, state->s[1].word, state->s[4].word) ^ ch(state->s[5].word, word_111, word_66) ;
	f = state->s[0].word ^ (~state->s[2].word) ^ maj(word_244, word_23, word_160) ^ (word_196 & ca); // ^ (cb & *ks);
    src->word = dst->word ^ ks;
    f  = f ^ src->word;
	state->s[6].word = state->s[6].word ^ ( (unsigned long long)f << 4 );


    state->s[0].word = (state->s[0].word >> 32) | ((state->s[1].word & 0xffffffff) << 29);  //32-(64-61) = 29
    state->s[1].word = (state->s[1].word >> 32) | ((state->s[2].word & 0xffffffff) << 14);  //32-(64-46) = 14
    state->s[2].word = (state->s[2].word >> 32) | ((state->s[3].word & 0xffffffff) << 15);  //32-(64-47) = 15
    state->s[3].word = (state->s[3].word >> 32) | ((state->s[4].word & 0xffffffff) << 7);   //32-(64-39) = 7
    state->s[4].word = (state->s[4].word >> 32) | ((state->s[5].word & 0xffffffff) << 5);   //32-(64-37) = 5
    state->s[5].word = (state->s[5].word >> 32) | ((state->s[6].word & 0xffffffff) << 27);  //32-(64-59) = 27
    state->s[6].word =  state->s[6].word >> 32;
	printk("ende decrypt_32bits_fast");
    return;
}

static void encrypt_8bits(unsigned long long *state, unsigned int plaintextword, unsigned int *ciphertextword, unsigned int ca, unsigned int cb)
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
    f  = (f ^ plaintextword) & 0xff;
	state[6] = state[6] ^ ( (unsigned long long)f << 4 );

    state[0] = (state[0] >> 8) | ((state[1] & 0xff) << (29+24));   //32-(64-61) = 29
    state[1] = (state[1] >> 8) | ((state[2] & 0xff) << (14+24));   //32-(64-46) = 14
    state[2] = (state[2] >> 8) | ((state[3] & 0xff) << (15+24));   //32-(64-47) = 15
    state[3] = (state[3] >> 8) | ((state[4] & 0xff) << (7+24));    //32-(64-39) = 7
    state[4] = (state[4] >> 8) | ((state[5] & 0xff) << (5+24));    //32-(64-37) = 5
    state[5] = (state[5] >> 8) | ((state[6] & 0xff) << (27+24));    //32-(64-59) = 27
    state[6] =  state[6] >> 8;

    *ciphertextword = plaintextword ^ ks;
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
		
		dst->key[i].word = le32_to_cpu(*(const __le32 *)src);//optimierungsbedarf!!!
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
	unsigned int i;
	for (i = 0; i < 1; i++) {
				///////////////optiermieren! gerade funktionierts!
		dst->word = le32_to_cpu(*(const __le32 *)src);//ergibt keinen sinn man muss irgendwie über den state gehen|||||||||||ergibt sinn um den schlüssel zu laden
		printk("%d load_a",dst->word);		
		src += 4;
	}
}

static void crypto_acorn_load_u(struct acorn_block *dst, const u8 *src)
{
	unsigned int i;
	for (i = 0; i < 1; i++) {
		dst->word = get_unaligned_le32(src);
		printk("%d load_u",dst->word);	
		src += 4;
	}
}

static void crypto_acorn_load(struct acorn_block *dst, const u8 *src)
{
	if (ACORN_ALIGNED(src))
		crypto_acorn_load_a(dst, src);
	else
		crypto_acorn_load_u(dst, src);
}

static void crypto_acorn_ad(unsigned long long *state, const u8 *src,
			       unsigned int size,unsigned int ca ,unsigned int cb,struct acorn_block *c)
{
	struct acorn_block m;
	printk("anfang crypto_acorn_ad");
	c->word=28;
	if (ACORN_ALIGNED(src)) {
		while (size >= ACORN_BLOCK_SIZE) {
			//müssen noch geladen werden
			crypto_acorn_load_a(&m,src);
			printk("m.word in acorn_ad %d\n",m.word);
			printk("c.word in acorn_ad %d\n",c->word);
			encrypt_32bits(state,m.word, &c->word, ca, cb); /// m.word c.word????? irgendwie muss man an das richtige kommen!

			size -= ACORN_BLOCK_SIZE;	//////welche größe?!?!?!?
			src += ACORN_BLOCK_SIZE;
		printk("ende crypto_acorn_ad1");	// eigentlich müsste die größe 32 sein!! gerade ist sie 128
		}
	} else {
		while (size >= ACORN_BLOCK_SIZE) {
			//müssen  noch geladen werden
			crypto_acorn_load_u(&m,src);
			encrypt_32bits(state,m.word,&c->word, ca, cb);

			size -= ACORN_BLOCK_SIZE;	//////welche größe?!?!?!?
			src += ACORN_BLOCK_SIZE;
			printk("ende crypto_acorn_ad2");
		}
	}
}

static void crypto_acorn_encrypt_chunk(unsigned long long *state, u8 *dst,
					  const u8 *src, unsigned int size)
{
	struct acorn_block m,c;
	unsigned int ca = 0xffffffff;
    	unsigned int cb = 0;
	int i;
	c.word=0;
	printk("anfang crypto_acorn_encrypt_chunk");
	if (ACORN_ALIGNED(src) && ACORN_ALIGNED(dst)) {
		while (size >= ACORN_BLOCK_SIZE) {
			/*crypto_morus640_load_a(&m, src);
			c = m;
			crypto_morus640_core(state, &c);
			crypto_morus640_store_a(dst, &c);
			crypto_morus640_update(state, &m);
			*/
			
			crypto_acorn_load_a(&m,src);
			//crypto_acorn_load_a(&c,dst);
			printk("m.word %d",m.word);
			printk("c.word %d",c.word);
			encrypt_32bits_fast(state,m.word,&c.word, ca, cb); 
			
			printk("src %d",*src);
			printk("dst %d",*dst);
			printk("size %d",size);
			src += ACORN_BLOCK_SIZE;
			dst += ACORN_BLOCK_SIZE;
			size -= ACORN_BLOCK_SIZE;
printk("ende crypto_acorn_encrypt_chunk1");
		}
	} else {
		while (size >= ACORN_BLOCK_SIZE) {
			

			/*crypto_morus640_load_u(&m, src);
			c = m;
			crypto_morus640_core(state, &c);
			crypto_morus640_store_u(dst, &c);
			crypto_morus640_update(state, &m);
			*/
			
			
			crypto_acorn_load_u(&m,src);
			//crypto_acorn_load_u(&c,dst);
printk("m.word %d",m.word);
printk("c.word %d",c.word);
			encrypt_32bits_fast(state,m.word,&c.word, ca, cb); 

			src += ACORN_BLOCK_SIZE;
			dst += ACORN_BLOCK_SIZE;
			size -= ACORN_BLOCK_SIZE;
printk("ende crypto_acorn_encrypt_chunk2");
		}
	for (i = 0; i <= 6; i++){
                   	printk("State nach encryption ENDE %d %lld \n",i, state[i]);
                   	}
		
	}

	if (size > 0) {
		union acorn_block_in tail;
		printk("ende crypto_acorn_encrypt_chunk3");
		memcpy(tail.bytes, src, size);
		memset(tail.bytes + size, 0, ACORN_BLOCK_SIZE - size);
								////////////wenn ein rest übrig bleibt
		/*crypto_morus640_load_a(&m, tail.bytes);
		c = m;
		crypto_morus640_core(state, &c);
		crypto_morus640_store_a(tail.bytes, &c);
		crypto_morus640_update(state, &m);
		*/

		crypto_acorn_load_a(&m,tail.bytes);
		encrypt_8bits(state,m.word, &c.word, ca, cb);
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

static void crypto_acorn_decrypt_chunk(struct acorn_state *state, u8 *dst,
					  const u8 *src, unsigned int size)
{
	unsigned int ca = 0xffffffff;
        unsigned int cb = 0;

	struct acorn_block m,c;
	printk("anfang crypto_acorn_decrypt_chunk");
	if (ACORN_ALIGNED(src) && ACORN_ALIGNED(dst)) {
		while (size >= ACORN_BLOCK_SIZE) {
			decrypt_32bits_fast(state, &m, &c, ca, cb); 


			src += ACORN_BLOCK_SIZE;
			dst += ACORN_BLOCK_SIZE;
			size -= ACORN_BLOCK_SIZE;
	printk("ende crypto_acorn_decrypt_chunk1");
		}
	} else {
		while (size >= ACORN_BLOCK_SIZE) {
			
			decrypt_32bits_fast(state, &m, &c, ca, cb); 

			src += ACORN_BLOCK_SIZE;
			dst += ACORN_BLOCK_SIZE;
			size -= ACORN_BLOCK_SIZE;
		printk("ende crypto_acorn_decrypt_chunk2");
		}
	}

	if (size > 0) {
		union acorn_block_in tail;

		memcpy(tail.bytes, src, size);

		//crypto_morus640_load_a(&m, src);
		//crypto_morus640_core(state, &m);
		//crypto_morus640_store_a(tail.bytes, &m);
		memset(tail.bytes + size, 0, ACORN_BLOCK_SIZE - size);
		//crypto_morus640_load_a(&m, tail.bytes);
		//crypto_morus640_update(state, &m);
		
		//crypto_acorn_load_a(&m,tail.bytes);
		//encrypt_8bits(state,m.word, &c.word, ca, cb);
		
		memcpy(dst, tail.bytes, size);
	printk("ende crypto_acorn_decrypt_chunk3");
	}
}

static void crypto_acorn_init(unsigned long long *state,
				 struct acorn_block *key,
				 const u8 *iv)
{
  	int j;
	//struct acorn_block tmp;
	unsigned int tmp = 0;
	
	printk("anfang crypto_acorn_init");
	//encrypt_32bits(struct acorn_state *state, struct acorn_block *src, struct acorn_block *dst, unsigned int ca, unsigned int cb)
        //initialize the state to 0
	//crypto_acorn_load(state, iv);

        for (j = 0; j <= 6; j++)state[j] = 0;
	
	/*printk("key[0] %d",key[0].word);
	printk("key[1] %d",key[1].word);
	printk("wert von iv %d,%d,%d,%d %d %d %d %d\n", iv[0],iv[1],iv[2],iv[3],iv[4],iv[5],iv[6],iv[7]);
	*/
	tmp=0;
	
        //run the cipher for 1792 steps
        for (j = 0;  j <= 3;  j++)
        {
		/////((unsigned int*)key)[j]
            encrypt_32bits(state,((unsigned int*)key)[j], &tmp, 0xffffffff, 0xffffffff);
		//printk("state 1 %lld",state->s[j].word);
        }
	/* for (j = 0; j <= 6; j++){
               printk("State11111111111111 %d %lld \n",j, state[j]);
               }
	*/
        for (j = 4;  j <= 7;  j++)
        {	//iv wird geladen
		//tem.s[1].word=((unsigned int*)tem.s[1].word)[j-4];
            encrypt_32bits(state,((unsigned int*)iv)[j-4], &tmp, 0xffffffff, 0xffffffff); //fehler
			
        }
	/* for (j = 0; j <= 6; j++){
               printk("State22222222222222222 %d %lld \n",j, state[j]);
               }
	*/
      
        for (j = 8;  j <= 8; j++)
        {
		  
		//((unsigned int*)key)[j&3] ^ 1
		//tem.s[2].word= ((unsigned int*)tem.s[2].word)[j&3] ^ 1; //key wird geladen
            encrypt_32bits(state,((unsigned int*)key)[j&3] ^ 1, &tmp, 0xffffffff, 0xffffffff);
		
        }
	/* for (j = 0; j <= 6; j++){
               printk("State333333333333 %d %lld \n",j, state[j]);
               }
	*/
        for (j = 9;  j <= 55; j++)
        {		
		//((unsigned int*)key)[j&3]
		//tem.s[3].word =((unsigned int*)tem.s[3].word)[j&3];
            encrypt_32bits(state,((unsigned int*)key)[j&3],&tmp, 0xffffffff, 0xffffffff);
		
        }
	
	 for (j = 0; j <= 6; j++){
               printk("State init ENDE %d %lld \n",j, state[j]);
               }
	printk("%d tmp",tmp);
	printk("ende crypto_acorn_init");
}

static void crypto_acorn_process_ad(unsigned long long *state,
				       struct scatterlist *sg_src,
				       unsigned int assoclen)
{
	struct scatter_walk walk;
	struct acorn_block m,c; //m plaintext c ciphertext
	union acorn_block_in buf;
	unsigned int pos = 0;
	unsigned int ca = 0xffffffff;
    	unsigned int cb = 0xffffffff;
	unsigned int j;
	printk("anfang crypto_acorn_process_ad");
	scatterwalk_start(&walk, sg_src);
	printk("assoclen %d",assoclen);
	while (assoclen != 0) {
		unsigned int size = scatterwalk_clamp(&walk, assoclen); // size=adlen
		unsigned int left = size; 
		void *mapped = scatterwalk_map(&walk);
		const u8 *src = (const u8 *)mapped;

		if (pos + size >= ACORN_BLOCK_SIZE) {
			if (pos > 0) {
				unsigned int fill = ACORN_BLOCK_SIZE - pos;
				memcpy(buf.bytes + pos, src, fill);

        			crypto_acorn_load_a(&m,buf.bytes);
				for (j = 0; j <= 6; j++){
              			printk("State %d %lld \n",j, state[j]);
             			}
				printk("m.word: %d",m.word);
				printk("c.word: %d",c.word);
				encrypt_32bits(state,m.word, &c.word, ca, cb);
				//crypto_morus640_load_a(&m, buf.bytes); //// funktionalität
				//crypto_morus640_update(state, &m);  /// funktionalität
 
				pos = 0;
				left -= fill;
				src += fill;
				printk("ende crypto_acorn_process_ad1");
			}
			printk("source %d",*src);	
			printk("left %d", left);
			crypto_acorn_ad(state, src, left,ca,cb,&c);  // funktionalität
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

	if (pos > 0) {
		printk("pos %d", pos);
		memset(buf.bytes + pos, 0, ACORN_BLOCK_SIZE - pos);
		printk("ich war hier");
		printk("buf.bytes %hhn",buf.bytes);////klappt nicht
		//crypto_acorn_load_a(&m,buf.bytes);
		for (j = 0; j <= 6; j++){
              			printk("State nach acorn_ad %d %lld \n",j, state[j]);
             			}
				printk("m.word: %d",m.word);
				printk("c.word: %d",c.word);
		//encrypt_8bits(state,m.word, &c.word, ca, cb);
		printk("ende crypto_acorn_process_ad3");
		//crypto_morus640_load_a(&m, buf.bytes); /// funktionalität
		//crypto_morus640_update(state, &m);   // funktionalität
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
	u8 *dst;	//normalerweise u8
	const u8 *src;

	ops->skcipher_walk_init(&walk, req, false);
	printk("anfang crypto_acorn_process_crypt");
	while (walk.nbytes) {
	
		src = walk.src.virt.addr; ///von 8 auf 32 vergrößern
		dst = walk.dst.virt.addr;

		ops->crypt_chunk(state, dst, src, walk.nbytes);

		skcipher_walk_done(&walk, 0);
	}
	printk("ende crypto_acorn_process_crypt");
}

static void crypto_acorn_final(unsigned long long *state,
				  struct acorn_block *tag_xor,
				  u64 assoclen, u64 cryptlen)
{
	int i;
    	//unsigned int ksword = 0;
	unsigned char mac[16];
	unsigned int plaintextword  = 0;
    	unsigned int ciphertextword = 0;
	//u64 assocbits = assoclen * 8;
	//u64 cryptbits = cryptlen * 8;
	unsigned int ksword=0;


	/*struct acorn_block tmp;
	unsigned int i;

	tmp.words[0] = cpu_to_le32(assocbits_lo);
	tmp.words[1] = cpu_to_le32(assocbits_hi);
	tmp.words[2] = cpu_to_le32(cryptbits_lo);
	tmp.words[3] = cpu_to_le32(cryptbits_hi);
	*/
	//tag.....

	printk("anfang crypto_acorn_final");
	 for (i = 0; i <= 6; i++){
                   printk("State ENDE %d %lld \n",i, state[i]);
                   }
    for (i = 0; i < 768/32; i++)
    {
        encrypt_32bits(state,plaintextword,&ciphertextword, 0xffffffff, 0xffffffff);
        if ( i >= (768/32 - 4) ) { ((unsigned int*)mac)[i-(768/32-4)] = tag_xor->word; }
    }
	   for (i = 0; i <= 6; i++){
                   printk("State ENDE %d %lld \n",i, state[i]);
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
	unsigned int i;
	printk("anfang crypto_acorn_crypt\n");
	crypto_acorn_init(state, ctx->key, req->iv);
	crypto_acorn_process_ad(state, req->src, req->assoclen);


	crypto_acorn_process_crypt(state, req, ops);
	crypto_acorn_final(state, tag_xor, req->assoclen, cryptlen);
	printk("ende crypto_acorn_crypt");
	
}

static int crypto_acorn_encrypt(struct aead_request *req)
{
	static const struct acorn_ops ops = {
		.skcipher_walk_init = skcipher_walk_aead_encrypt,
		.crypt_chunk = crypto_acorn_encrypt_chunk,
	};

	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct acorn_block tag = {}; ////???????????????
	union acorn_block_in tag_out; 
	unsigned int authsize = crypto_aead_authsize(tfm);
	unsigned int cryptlen = req->cryptlen;
	printk("anfang crypto_acorn_encrypt");
	crypto_acorn_crypt(req, &tag, cryptlen, &ops);

	scatterwalk_map_and_copy(tag_out.bytes, req->dst,
				 req->assoclen + cryptlen, authsize, 1);
	printk("ende crypto_acorn_encrypt");
	return 0;
}

static int crypto_acorn_decrypt(struct aead_request *req)
{
	static const struct acorn_ops ops = {
		.skcipher_walk_init = skcipher_walk_aead_decrypt,
		//.crypt_chunk = crypto_acorn_decrypt_chunk,
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

	//crypto_morus640_load(&tag, tag_in.bytes);
	//crypto_morus640_crypt(req, &tag, cryptlen, &ops);
	//crypto_morus640_store(tag_in.bytes, &tag);

	crypto_acorn_crypt(req, &tag, cryptlen, &ops);
	printk("ende crypto_acorn_decrypt");
	return crypto_memneq(tag_in.bytes, zeros, authsize) ? -EBADMSG : 0;
}

static int crypto_acorn_setkey(struct crypto_aead *aead, const u8 *key,
				  unsigned int keylen)
{
	struct acorn_ctx *ctx = crypto_aead_ctx(aead);
	printk("anfang crypto_acorn_setkey");
	printk("%d",keylen);
	printk("%d",ACORN_KEY_SIZE);
	if (keylen != ACORN_KEY_SIZE) {
		crypto_aead_set_flags(aead, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}
	// hier wird der key geladen

	crypto_acorn_load_k(ctx, key);// da ist ein fehler drinne
	printk("%d %d %d %d",ctx->key[0].word,ctx->key[1].word , ctx->key[2].word ,ctx->key[3].word); //key manchmal negativ
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
