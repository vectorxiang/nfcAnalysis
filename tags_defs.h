#include <stdio.h>

const unsigned char T4T_V10_NDEF_TAG_AID[7] = {0xD2,0x76,0x00,0x00,0x85,0x01,0x00};
const unsigned char T4T_V20_NDEF_TAG_AID[7] = {0xD2,0x76,0x00,0x00,0x85,0x01,0x01};
const unsigned char T4T_CC_FILE_ID[2] = {0xE1,0x03};

#define T4T_CMD_CLASS 0x00
#define T4T_CMD_INS_SELECT 0xA4
#define T4T_CMD_INS_READ_BINARY 0xB0
#define T4T_CMD_INS_READ_RECORD 0xB2
#define T4T_CMD_INS_UPDATE_BINARY 0xD6
#define T4T_CMD_DES_CLASS 0x90
#define T4T_CMD_INS_GET_HW_VERSION 0x60
#define T4T_CMD_CREATE_AID 0xCA
#define T4T_CMD_SELECT_APP 0x5A
#define T4T_CMD_CREATE_DATAFILE 0xCD
#define T4T_CMD_DES_WRITE 0x3D
#define T4T_CMD_P1_SELECT_BY_NAME 0x04
#define T4T_CMD_P1_SELECT_BY_FILE_ID 0x00
#define T4T_CMD_P2_FIRST_OR_ONLY_00H 0x00
#define T4T_CMD_P2_FIRST_OR_ONLY_0CH 0x0C

#define T4T_RSP_STATUS_WORDS_SIZE 0x02

#define T4T_RSP_CMD_CMPLTED 0x9000
#define T4T_RSP_NOT_FOUND 0x6A82
#define T4T_RSP_WRONG_PARAMS 0x6B00
#define T4T_RSP_CLASS_NOT_SUPPORTED 0x6E00
#define T4T_RSP_WRONG_LENGTH 0x6700
#define T4T_RSP_INSTR_NOT_SUPPORTED 0x6D00
#define T4T_RSP_CMD_NOT_ALLOWED 0x6986

/* Type 4 Tag Applicaiton ID length */
#define T4T_NDEF_TAG_AID_LEN 0x07

#define T4T_FILE_ID_SIZE 0x02

#define SW_INCORRECT_P1P2  0x6A86
#define SW_FILE_OR_APP_NOT_FOUND  0x6A82

#define MF_RAW_DATA_XCHG  0x10                 /* MF Raw Data Request from DH */
#define MF_WRITE_N  0x31                       /* MF N bytes write request from DH */
#define MF_READ_N  0x32                       /* MF N bytes read request from DH */
#define MFC_AUTH  0x40                       /* MFC Authentication request for NFCC from DH */


