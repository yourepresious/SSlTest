#include <jni.h>
#include <string>
#include "openssl/md5.h"
#include <vector>
#include "base_64.h"

static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789+/";

static inline bool is_base64(const char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_decode(std::string const & encoded_string)
{
    int in_len = (int) encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i ==4) {
            for (i = 0; i <4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }
    if (i) {
        for (j = i; j <4; j++)
            char_array_4[j] = 0;

        for (j = 0; j <4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
    }

    return ret;
}

/**
 * Base64解码
 * @param str
 * @param length
 * @return
 */
std::string Base64::Decode(const char *str,int length) {
    //解码表
    const char DecodeTable[] =
            {
                    -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -2, -1, -2, -2,
                    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
                    -1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, -2, -2, 63,
                    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -2, -2, -2,
                    -2,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
                    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, -2,
                    -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
                    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
                    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
                    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
                    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
                    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
                    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
                    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
                    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2
            };
    int bin = 0,i=0,pos=0;
    std::string _decode_result;
    const char *current = str;
    char ch;
    while( (ch = *current++) != '\0' && length-- > 0 )
    {
        if (ch == base64_pad) { // 当前一个字符是“=”号
            /*
            先说明一个概念：在解码时，4个字符为一组进行一轮字符匹配。
            两个条件：
                1、如果某一轮匹配的第二个是“=”且第三个字符不是“=”，说明这个带解析字符串不合法，直接返回空
                2、如果当前“=”不是第二个字符，且后面的字符只包含空白符，则说明这个这个条件合法，可以继续。
            */
            if (*current != '=' && (i % 4) == 1) {
                return NULL;
            }
            continue;
        }
        ch = DecodeTable[ch];
        //这个很重要，用来过滤所有不合法的字符
        if (ch < 0 ) { /* a space or some other separator character, we simply skip over */
            continue;
        }
        switch(i % 4)
        {
            case 0:
                bin = ch << 2;
                break;
            case 1:
                bin |= ch >> 4;
                _decode_result += bin;
                bin = ( ch & 0x0f ) << 4;
                break;
            case 2:
                bin |= ch >> 2;
                _decode_result += bin;
                bin = ( ch & 0x03 ) << 6;
                break;
            case 3:
                bin |= ch;
                _decode_result += bin;
                break;
        }
        i++;
    }
    return _decode_result;
}

/**
 * Base64编码
 * @param str
 * @param bytes
 * @return
 */
std::string Base64::Encode(const unsigned char * str,int bytes) {
    int num = 0,bin = 0,i;
    std::string _encode_result;
    const unsigned char * current;
    current = str;
    while(bytes > 2) {
        _encode_result += _base64_table[current[0] >> 2];
        _encode_result += _base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
        _encode_result += _base64_table[((current[1] & 0x0f) << 2) + (current[2] >> 6)];
        _encode_result += _base64_table[current[2] & 0x3f];

        current += 3;
        bytes -= 3;
    }
    if(bytes > 0)
    {
        _encode_result += _base64_table[current[0] >> 2];
        if(bytes%3 == 1) {
            _encode_result += _base64_table[(current[0] & 0x03) << 4];
            _encode_result += "==";
        } else if(bytes%3 == 2) {
            _encode_result += _base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
            _encode_result += _base64_table[(current[1] & 0x0f) << 2];
            _encode_result += "=";
        }
    }
    return _encode_result;
}

void get_md5_16(std::string encrypt, std::vector<unsigned char>& decrypt)
{
    unsigned char szbuf[16];
    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, (unsigned char*)encrypt.data(), (unsigned int)encrypt.size());
    MD5_Final(szbuf, &md5);//32位

    int buf_len = sizeof(szbuf) / sizeof(szbuf[0]);
    for (int i = 0; i < buf_len; ++i) {
        decrypt.push_back(szbuf[i]);
    }
    return;
}

std::string get_signature()
{
    std::string params = "nblext881308662018-10-31 18:11:21";// : ss.str();
    std::vector<unsigned char> decrypt;
    get_md5_16(params, decrypt);
    Base64 base64;
    auto secret = base64.Encode((const unsigned char*)decrypt.data(), (int)decrypt.size());

    auto secret1 = base64.Encode((const unsigned char*)params.data(), (int)params.size());
    auto unsecret = base64.Decode(secret1.data(), (int) secret1.size());
//    auto secret = faceutility::CBase64::encode(decrypt.data(), (int)decrypt.size());
//    LOG(ERROR) << "secret:" << secret << std::endl;
    return unsecret;
}

extern "C"
JNIEXPORT jstring

JNICALL
Java_com_nazhi_ssltest_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = get_signature();
    std::string a;
    return env->NewStringUTF(hello.c_str());
}
