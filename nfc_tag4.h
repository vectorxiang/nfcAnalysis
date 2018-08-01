#include <stdio.h>

const unsigned char NDEF_Tag_Application[7] = {0xD2,0x76,0x00,0x00,0x85,0x01,0x01};
const unsigned char NDEF_Tag_Application_[7] = {0xD2,0x76,0x00,0x00,0x85,0x01,0x00};
const unsigned char CC_FILE[2] = {0xE1,0x03};

#define T4T_RSP_STATUS_WORDS_SIZE 0x02

#define T4T_RSP_CMD_CMPLTED 0x9000
#define T4T_RSP_NOT_FOUND 0x6A82
#define T4T_RSP_WRONG_PARAMS 0x6B00
#define T4T_RSP_CLASS_NOT_SUPPORTED 0x6E00
#define T4T_RSP_WRONG_LENGTH 0x6700
#define T4T_RSP_INSTR_NOT_SUPPORTED 0x6D00
#define T4T_RSP_CMD_NOT_ALLOWED 0x6986

#define SW_INCORRECT_P1P2  0x6A86
#define SW_FILE_OR_APP_NOT_FOUND  0x6A82


