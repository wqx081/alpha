/* ============================================================================
 * Copyright (c) 2010-2015.  All rights reserved.
 * SM4 Block Cipher Algorithm: Block length and key length are both 128-bit
 * ============================================================================
 */

#ifndef _SM4_HEADER_H_
#define _SM4_HEADER_H_   1

#ifndef U8
#define U8 unsigned char
#endif

#ifndef U32
#define U32 unsigned int
#endif

#define SM4_ENCRYPT    1
#define SM4_DECRYPT    0

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE   16


void sm4_set_key(const U8 *userkey, U32 *round_key);
/*
userkey:   16 �ֽڵ��û���Կ
round_key: 32 ���ֵĲ���Կ��������
*/


void sm4_encrypt(const U8 *in, U8 *out, const U32 *round_key);
/*
in:        16 �ֽڵ�����
out:       16 �ֽڵ�����
round_key: 32 ���ֵĲ���Կ��������
*/


void sm4_decrypt(const U8 *in, U8 *out, const U32 *round_key);
/*
in:        16 �ֽڵ�����
out:       16 �ֽڵ�����
round_key: 32 ���ֵĲ���Կ��������
*/


void sm4_ecb_encrypt(const U8 *in, U8 *out,
                     const U32 length, const U8 *key,
                     const U32 enc);
/*
in:        Ҫ���ܻ���ܵ����ݣ��������SM4_BLOCK_SIZE���������������Զ���0x00���롣
out:       ����Ľ������SM4_BLOCK_SIZE��������
length:    in���ֽ���
key:       16 �ֽڵ��û���Կ
enc:       ���ܻ���ܣ�SM4_ENCRYPT/SM4_DECRYPT
*/


void sm4_cbc_encrypt(const U8 *in, U8 *out,
                     const U32 length, const U8 *key,
                     const U8 *ivec, const U32 enc);
/*
in:        Ҫ���ܻ���ܵ����ݣ��������SM4_BLOCK_SIZE���������������Զ���0x00���롣
out:       ����Ľ������SM4_BLOCK_SIZE��������
length:    in���ֽ���
key:       16 �ֽڵ��û���Կ
ivec:      16 �ֽڵĳ�ʼ������
enc:       ���ܻ���ܣ�SM4_ENCRYPT/SM4_DECRYPT
*/

void sm4_cbc_mac(const U8 *in, U8 *out,
                 const U32 length, const U8 *key,
                 const U8 *ivec);
/*
in:        ��������MAC�����ݣ��������SM4_BLOCK_SIZE���������������Զ���0x00���롣
out:       �����MAC��16�ֽ�
length:    in���ֽ���
key:       16 �ֽڵ��û���Կ
ivec:      16 �ֽڵĳ�ʼ������
*/


void sm4_cfb_encrypt(const U8 *in, U8 *out,
                     const U32 length, const U8 *key,
                     const U8 *ivec, const U32 enc) ;

/*
in:        Ҫ���ܻ���ܵ����ݡ�
out:       ����Ľ��
length:    in���ֽ���
key:       16 �ֽڵ��û���Կ
ivec:      16 �ֽڵĳ�ʼ������
enc:       ���ܻ���ܣ�SM4_ENCRYPT/SM4_DECRYPT
*/

void sm4_ofb_encrypt(const U8 *in, U8 *out,
                     const U32 length, const U8 *key,
                     const U8 *ivec) ;
/*
in:        Ҫ���ܻ���ܵ����ݡ�
out:       ����Ľ��
length:    in���ֽ���
key:       16 �ֽڵ��û���Կ
ivec:      16 �ֽڵĳ�ʼ������
*/


#endif /* _SM4_HEADER_H_ */
