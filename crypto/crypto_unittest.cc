#include "base/macros.h"
#include "third_party/sm2/native_sm2.h"
#include "third_party/sm2/srand.h"
#include "third_party/sm2/sm3.h"

#include <gtest/gtest.h>

namespace crypto {

namespace {

#if 0
void DumpHexString(unsigned char* buf, unsigned int len)
{
    static char str[1024] = {0};
    memset(str, 0, 1024);

    unsigned char * pin = buf;
    const char * hex = "0123456789ABCDEF";
    char * pout = str;
    unsigned int i = 0;
    for(; i < len-1; ++i){
        *pout++ = hex[(*pin>>4)&0xF];
        *pout++ = hex[(*pin++)&0xF];
        *pout++ = ':';
    }
    *pout++ = hex[(*pin>>4)&0xF];
    *pout++ = hex[(*pin)&0xF];
    *pout = 0;

    printf("%s\n", str);
}

void HexStringToASCII(unsigned char* buf, unsigned int len)
{
    static unsigned char str[1024] = {0};
    memset(str, 0, 1024);

    unsigned char* pin = buf;
    unsigned char* pout= str;

    unsigned int i=0;
    for (; i < len-1; ++i) {
        *pout++ = (char)*pin++;
    }
    printf("%s\n", str);
}
#endif

int SDF_GenerateRandom(uint32 uiLength, uint8* pucRandom) {
  return oly::random_string(pucRandom, uiLength);
}

bool LoadPublicKey(const unsigned char* pBuffer,
                   int len,
                   oly::ECCrefPublicKey* pubKey) {
  if( len != 48 && len != 64 )
    return false;
  memset(pubKey, 0, sizeof(oly::ECCrefPublicKey));
  pubKey->bits = (len*8)/2;
  memcpy(pubKey->x, pBuffer, len/2);
  memcpy(pubKey->y, pBuffer+len/2, len/2);

  return true;
}

bool LoadPrivateKey(const unsigned char *pBuffer, 
                    int len, 
                    oly::ECCrefPrivateKey *prvKey)
{
  if( len != 24 && len != 32 )
    return false;
  memset(prvKey, 0, sizeof(oly::ECCrefPrivateKey));
  prvKey->bits = len*8;
  memcpy(prvKey->D, pBuffer, len);

  return true;
}

int SizeOfPackedCipher(const oly::ECCCipherEx cipher) {
  return ((cipher.bits / 8) * 2)
    + sizeof(cipher.C)
    + (cipher.mbits / 8);
}

int PackCipher(const oly::ECCCipherEx cipher, unsigned char* p_buf, int* buf_len) {
  int ofst = 0;
  if (*buf_len < SizeOfPackedCipher(cipher)) {
    return -1;
  }


  memcpy(p_buf + ofst, cipher.x, cipher.bits / 8);
  ofst += cipher.bits / 8;

  memcpy(p_buf + ofst, cipher.y, cipher.bits / 8);
  ofst += cipher.bits / 8;

  memcpy(p_buf + ofst, cipher.C, sizeof(cipher.C));
  ofst += sizeof(cipher.C);

  memcpy(p_buf + ofst, cipher.M, cipher.mbits / 8);
  ofst += cipher.mbits / 8;

  *buf_len = ofst;

  return 0;
}

int UnpackCipher(const unsigned char* p_buf, int buf_len, int bits, 
                 oly::ECCCipherEx *cipher) {
  int ofst = 0;

  cipher->bits = bits;
  cipher->mbits = (buf_len - cipher->bits / 4 - sizeof(cipher->C)) * 8;
  memcpy(cipher->x, p_buf + ofst, cipher->bits / 8);
  ofst += cipher->bits / 8;

  memcpy(cipher->y, p_buf + ofst, cipher->bits / 8);
  ofst += cipher->bits / 8;

  memcpy(cipher->C, p_buf + ofst, sizeof(cipher->C));
  ofst += sizeof(cipher->C);

  memcpy(cipher->M, p_buf + ofst, cipher->mbits / 8);
  ofst += cipher->mbits / 8;

  return 0;
}

} // namespace

enum AsymmReturnCode {
  OK = 0,
  ERROR = 1,
  BAD_PARAM = 2,
  BAD_CALL = 3
};

enum AsymmAlgorithm {
  SM2,
  RSA
};

int MPRAsymmCryptGenerateKeyPair(AsymmAlgorithm alg,
                                 const unsigned int key_bits,
                                 unsigned char* p_pubkey,
                                 unsigned int * pubkey_len,
                                 unsigned char* p_prvkey,
                                 unsigned int * prvkey_len) {
  int rt = 0;
    
  if(p_pubkey == NULL   || 
     pubkey_len == NULL || 
     p_prvkey == NULL   || 
     prvkey_len == NULL || 
     key_bits == 0){
        return BAD_PARAM;
    }

  switch (alg) {
    case SM2:
      rt = oly::SDF_GenerateKeyPair_ECC(key_bits, 
                                        (char *)p_pubkey, 
                                        (int *)pubkey_len, 
                                        (char *)p_prvkey, 
                                        (int *)prvkey_len);
      if (SDR_OK != rt){
        return rt;
      }
      return 0;
    case RSA:
      return BAD_CALL;
    default:
      return BAD_PARAM;
    }
    return BAD_PARAM;
}

int MPRAsymmCryptPubEncrypt(AsymmAlgorithm alg,
                            const unsigned char* p_pubkey,
                            const unsigned int pubkey_len,
                            const unsigned char* p_in_data,
                            const unsigned int in_len,
                            unsigned char* p_out_data,
                            unsigned int *out_len) {

  oly::ECCrefPublicKey pucPublicKey;
  oly::ECCCipherEx cipher; // = {0};

  memset(&cipher, 0, sizeof(cipher));
  
  int rt = 0;
  if(p_pubkey == NULL  || 
     pubkey_len == 0   || 
     p_in_data == NULL || 
     in_len == 0       || 
     p_out_data == NULL|| 
     out_len == NULL) {
    return BAD_PARAM;
  }
  switch (alg) {
    case SM2:
      if (LoadPublicKey(p_pubkey, pubkey_len, &pucPublicKey) != true) {
        return BAD_PARAM;
      }
      rt = oly::SNF_ExternalEncrypt_ECC(nullptr,
                                        SGD_SM2_3,
                                        &pucPublicKey,
                                        (uint8*)p_in_data,
                                        in_len,
                                        &cipher);
      if (rt != SDR_OK) {
        return rt;
      }
      if (PackCipher(cipher, p_out_data, (int*)out_len)) {
        return BAD_PARAM;
      }
      return 0;
    default:
      return BAD_PARAM;
  }
  return BAD_CALL;
}

int MPRAsymmCryptPrvDecrypt(AsymmAlgorithm alg,
                            const unsigned char* p_prvkey,
                            const unsigned int prvkey_len,
                            const unsigned char* p_in_data,
                            const unsigned int in_len,
                            unsigned char* p_out_data,
                            unsigned int *out_len) {

  oly::ECCrefPrivateKey pucPrivateKey;
  oly::ECCCipherEx decipher; // = {0};
 
  memset(&decipher, 0, sizeof(decipher));

  int ret = 0;

  if(p_prvkey == NULL  || 
     prvkey_len == 0   || 
     p_in_data == NULL || 
     in_len == 0       || 
     p_out_data == NULL|| 
     out_len == NULL) {
    return BAD_PARAM;
  }
  switch (alg) {
    case SM2:
      if (LoadPrivateKey(p_prvkey, prvkey_len, &pucPrivateKey) != 0) {
        return BAD_PARAM;
      }
      UnpackCipher(p_in_data, in_len, pucPrivateKey.bits, &decipher);
      //unsigned char* p = (unsigned char*)&pucPrivateKey;
      ret = oly::SNF_ExternalDecrypt_ECC(nullptr,
                                      SGD_SM2_3,
                                      &pucPrivateKey,
                                      &decipher,
                                      (uint8*)p_out_data,
                                      out_len);
      if (ret != SDR_OK) {
        return ret;
      }
      return 0;

    default:
      return BAD_PARAM;
  }
  return BAD_CALL;
}

bool TestSM2GenerateKeyPair() {
  int ret;
  const int KEY_BITS = 256;
  unsigned char pubkey[128] = {0};
  unsigned int  pubkey_len = 128;
  unsigned char prvkey[128] = {0};
  unsigned int  prvkey_len = 128;

  const char* text = "Hello World";
  std::string text_str(text);

  unsigned char cipherLicense[256] = {0};
  unsigned int  cipher_len = 256;
  unsigned char decipherLicense[256] = {0};
  unsigned int  decipher_len = 256;


  // GenerateKeyPair
  ret = MPRAsymmCryptGenerateKeyPair(SM2, KEY_BITS,
                                     pubkey, &pubkey_len,
                                     prvkey, &prvkey_len); 
  EXPECT_TRUE(ret == 0);
  
  // PubEncrypt
  ret = MPRAsymmCryptPubEncrypt(SM2, pubkey, pubkey_len,
                                (const unsigned char*)text,
                                strlen((char*)text),
                                cipherLicense,
                                &cipher_len);
  EXPECT_TRUE(ret == 0);

  unsigned char sbuf[1024] = {0};

  // PrvDecrypt
  ret = MPRAsymmCryptPrvDecrypt(SM2,
                                prvkey,
                                prvkey_len,
                                sbuf,
                                cipher_len,
                                decipherLicense,
                                &decipher_len);
  std::string decipher_str(decipherLicense[0], decipher_len);

  EXPECT_TRUE(ret == 0);

  EXPECT_TRUE(text_str == decipher_str);


  // Sing and Verify
  const char* content = "Hello, world";
  int content_len = strlen(content);

  uint8 hash[SM3_HASH_LEN];
  uint32 hlen = sizeof(hash);
  oly::ECCSignatureEx signaure;
  uint8 msg[16];
  int msglen = sizeof(msg);
  oly::ECCrefPublicKey pucPublicKey; 
  oly::ECCrefPrivateKey pucPrivateKey;

  ret = SDF_GenerateRandom(sizeof(msg), msg);
  oly::sm3_context sm3_context;
  oly::sm3_starts(&sm3_context);
  oly::sm3_update(&sm3_context, msg, msglen); // input <- msg
  oly::sm3_finish(&sm3_context, hash); // output -> hash

  ret = LoadPrivateKey(prvkey, prvkey_len, &pucPrivateKey);
  EXPECT_EQ(0, ret);
  ret = LoadPublicKey(pubkey, pubkey_len, &pucPublicKey);
  EXPECT_EQ(0, ret);

  ret = oly::SNF_ExternalSign_ECC(nullptr, 
                                  SGD_SM2_1, 
                                  &pucPrivateKey,
                                  hash,
                                  hlen,
                                  (unsigned char*)content,
                                  content_len,
                                  &signaure);
  EXPECT_EQ(0, ret);
  ret = oly::SNF_ExternalVerify_ECC(nullptr,
                                    SGD_SM2_1,
                                    &pucPublicKey,
                                    hash,
                                    hlen,
                                    (unsigned char*)content,
                                    content_len,
                                    &signaure);  
  EXPECT_EQ(0, ret);
  return ret == 0;
}

////////////////////////////////////////////// OLY

TEST(Sm2Crypto, GenerateKeyPair) {
  EXPECT_TRUE(TestSM2GenerateKeyPair);
}


} // namespace alpha
