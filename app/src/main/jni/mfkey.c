
#include <jni.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#define llx PRIx64
#define lli PRIi64

// Test-file: test2.c
#include "crapto1.h"
#include <stdlib.h>
#include <stdio.h>

/* Adaptation of mfkey32 for JNI interfacing */


uint64_t mfkey(uint32_t uid, uint32_t nt, uint32_t nt1, uint32_t nr0_enc, uint32_t ar0_enc, uint32_t nr1_enc, uint32_t ar1_enc) {
  struct Crypto1State *s,*t;
  uint64_t key;     // recovered key
  /*
  uint32_t uid;     // serial number
  uint32_t nt;      // tag challenge #0
  uint32_t nt1;     // tag challenge #1
  uint32_t nr0_enc; // first encrypted reader challenge
  uint32_t ar0_enc; // first encrypted reader response
  uint32_t nr1_enc; // second encrypted reader challenge
  uint32_t ar1_enc; // second encrypted reader response
  */
  uint32_t ks2;     // keystream used to encrypt reader response

	// Generate lfsr succesors of the tag challenge
    // REMOVE?
  prng_successor(nt, 64);
  prng_successor(nt, 96);

  ks2 = ar0_enc ^ prng_successor(nt, 64);

  s = lfsr_recovery32(ar0_enc ^ prng_successor(nt, 64), 0);
	for(t = s; t->odd | t->even; ++t) {
		lfsr_rollback_word(t, 0, 0);
		lfsr_rollback_word(t, nr0_enc, 1);
		lfsr_rollback_word(t, uid ^ nt, 0);
		crypto1_get_lfsr(t, &key);
		crypto1_word(t, uid ^ nt1, 0);
		crypto1_word(t, nr1_enc, 1);
		if (ar1_enc == (crypto1_word(t, 0, 0) ^ prng_successor(nt1, 64))) {
      // printf("\nFound Key: [%012"llx"]\n\n",key);
            return key;
			// break;
		}
	}
  free(s);

  return 0;
}

void main() {

    uint64_t key = mfkey(0x12345678L, /* uid */
                         0x1AD8DF2BL, /* nt0 */
                         0x30D6CB07L, /* nt1 */
                         0x1D316024L, /* nr0 */
                         0x620EF048L, /* ar0 */
                         0xC52077E2L,  /* nr1 */
                         0x837AC61AL); /* ar1 */

    printf("key should be a0a1a2a3a4a5\n");
    printf("key is %llx\n", key);
    if (key == 0xa0a1a2a3a4a5) printf("KEY OK!\n");
    else printf("Bug in calculation, key does not match\n");

}

/*
 *  * Class:     com_example_mfc_keyextractor_MainActivity
 *  * Method:    mfkey
 *  * Signature: (IIIIIII)J
 */
JNIEXPORT jlong JNICALL Java_com_example_mfc_keyextractor_MainActivity_mfkey
  (JNIEnv * env, jobject jobj, jint a, jint b, jint c, jint d, jint e, jint f, jint g) {

  return mfkey(a,b,c,d,e,f,g);
}


