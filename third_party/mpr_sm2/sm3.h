/* ============================================================================
 * Copyright (c) 2010-2015.  All rights reserved.
 * SM3 Hash Cipher Algorithm: Digest length is 256-bit
 * ============================================================================
 */

#ifndef __SM3_HEADER__
#define __SM3_HEADER__

unsigned char *sm3(const unsigned char *data, int datalen, unsigned char *digest);
/*
���ܣ�    ��SM3�㷨��ժҪ

����˵����
		data     [����] ������ժҪ������
		datalen  [����] data���ֽ���
		digest   [���] 32�ֽڵ�ժҪֵ

����ֵ��ָ��digest��ָ��

*/


unsigned char *sm3_hmac(unsigned char *key, int keylen, unsigned char *text, int textlen, unsigned char *hmac);
/*
���ܣ�    ��SM3�㷨��HMAC

����˵����
		key      [����] ������HMAC����Կ
		keylen   [����] key���ֽ���
		text     [����] ������HMAC������
		textlen  [����] text���ֽ���
		hmac     [���] 32�ֽڵ�HMACֵ

����ֵ��ָ��hmac��ָ��

*/


#define  SM3_LBLOCK         16
#define  SM3_CBLOCK         64
#define  SM3_DIGEST_LENGTH  32
#define  SM3_LAST_BLOCK     56

typedef struct SM3state_st
{
	unsigned int h[8];
	unsigned int Nl,Nh;
	unsigned int data[SM3_LBLOCK];
	unsigned int  num;
} SM3_CTX;

void SM3_Init (SM3_CTX *ctx);

void SM3_Update(SM3_CTX *ctx, const void *data, int len);
/*
ע�⣺�������һ���⣬len������64�ֽڵ���������
*/

void SM3_Final(unsigned char *md, SM3_CTX *ctx);


#endif
