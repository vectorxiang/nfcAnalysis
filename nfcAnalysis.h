#include <stdio.h>

typedef unsigned char uint8_t;
typedef unsigned short uint16_t; 

#define ENABLE_NFC "Enabling NFC"
#define DISABLE_NFC "Disabling NFC"
#define NFC_ENABLED "NFC Enabled"
#define NFC_DISABLED "NFC Disabled"
#define DATA_SEND "NxpNciX"
#define DATA_RECEIVE "NxpNciR"

#define BE_STREAM_TO_UINT16(u16, p)                                     \
  {                                                                     \
    u16 = (uint16_t)(((uint16_t)(*(p)) << 8) + (uint16_t)(*((p) + 1))); \
  }

/*  packet type */
#define NCI_MT_DATA 0x00
#define NCI_MT_CMD  0x01	
#define NCI_MT_RSP  0x02	
#define NCI_MT_NTF  0x03

/* CMD RSP NTF packet GID */
#define NCI_GID_CORE 0x00      /* 0000b NCI Core group */
#define NCI_GID_RF_MANAGE 0x01 /* 0001b RF Management group */
#define NCI_GID_EE_MANAGE 0x02 /* 0010b NFCEE Management group */
#define NCI_GID_PROP 0x0F      /* 1111b Proprietary */

/**********************************************
 * Supported Protocols
 **********************************************/
#define NCI_PROTOCOL_UNKNOWN 0x00
#define NCI_PROTOCOL_T1T 0x01
#define NCI_PROTOCOL_T2T 0x02
#define NCI_PROTOCOL_T3T 0x03
#define NCI_PROTOCOL_ISO_DEP 0x04
#define NCI_PROTOCOL_NFC_DEP 0x05
#define NCI_PROTOCOL_15693 0x06
#define NCI_PROTOCOL_MIFARE_CLASSIC 0x80
#define NCI_PROTOCOL_KOVIO 0x81
#define NCI_PROTOCOL_ISO7816 0xA0

/**********************************************
 * NCI Core Group Opcode        - 0
 **********************************************/
#define NCI_MSG_CORE_RESET 0
#define NCI_MSG_CORE_INIT 1
#define NCI_MSG_CORE_SET_CONFIG 2
#define NCI_MSG_CORE_GET_CONFIG 3
#define NCI_MSG_CORE_CONN_CREATE 4
#define NCI_MSG_CORE_CONN_CLOSE 5
#define NCI_MSG_CORE_CONN_CREDITS 6
#define NCI_MSG_CORE_GEN_ERR_STATUS 7
#define NCI_MSG_CORE_INTF_ERR_STATUS 8
#define NCI_MSG_CORE_SET_POWER_SUB_STATE 9

/**********************************************
 * RF MANAGEMENT Group Opcode    - 1
 **********************************************/
#define NCI_MSG_RF_DISCOVER_MAP 0
#define NCI_MSG_RF_SET_ROUTING 1
#define NCI_MSG_RF_GET_ROUTING 2
#define NCI_MSG_RF_DISCOVER 3
#define NCI_MSG_RF_DISCOVER_SELECT 4
#define NCI_MSG_RF_INTF_ACTIVATED 5
#define NCI_MSG_RF_DEACTIVATE 6
#define NCI_MSG_RF_FIELD 7
#define NCI_MSG_RF_T3T_POLLING 8
#define NCI_MSG_RF_EE_ACTION 9
#define NCI_MSG_RF_EE_DISCOVERY_REQ 10
#define NCI_MSG_RF_PARAMETER_UPDATE 11
#define NCI_MSG_RF_ISO_DEP_NAK_PRESENCE 16
/**********************************************
 * NFCEE MANAGEMENT Group Opcode - 2
 **********************************************/
#define NCI_MSG_NFCEE_DISCOVER 0
#define NCI_MSG_NFCEE_MODE_SET 1
#define NCI_MSG_NFCEE_STATUS   2
#define NCI_MSG_NFCEE_PWR_LNK_CTRL 3
#define NCI_MSG_NFCEE_POWER_LINK_CTRL 4

/**********************************************
 * Vendor Command        - 0x0F
 **********************************************/
#define VENDOR_SET_SET_POWER_MODE  0  
#define VENDOR_SET_SCREEN_STATE 21  /*0x15*/



/* unknow cmd*/
#define CMD_UNKNOWN 0xFF

/* unknow rsp status*/
#define RSP_UNKNOWN 0xFF


//the max number of NDEF can be saved
#define MAX_NUM_NDEF_SAVED 16
//the max number of TLV can be saved
#define MAX_NUM_TLV_SAVED 1024


/**********************************************
 * Type 1 Tag related definitions
**********************************************/
/* Type 1 Tag Format related */
/* HRO value to indicate static Tag               */
#define T1T_STATIC_HR0 0x11
/* 0x1y, as long as (y!=1)                        */
#define T1T_DYNAMIC_HR0 0x12
/* HR0 value is 0x1y, indicates NDEF supported    */
#define T1T_NDEF_SUPPORTED 0x10

/* Type 1 Tag Commands (7 bits) */
/* read id                                      */
#define T1T_CMD_RID 0x78
/* read all bytes                               */
#define T1T_CMD_RALL 0x00
/* read (1 byte)                                */
#define T1T_CMD_READ 0x01
/* write with erase (1 byte)                    */
#define T1T_CMD_WRITE_E 0x53
/* write no erase (1 byte)                      */
#define T1T_CMD_WRITE_NE 0x1A
/* dynamic memory only */
/* read segment                                 */
#define T1T_CMD_RSEG 0x10
/* read (8 byte)                                */
#define T1T_CMD_READ8 0x02
/* write with erase (8 byte)                    */
#define T1T_CMD_WRITE_E8 0x54
/* write no erase (8 byte)                      */
#define T1T_CMD_WRITE_NE8 0x1B

//static mem CC0 position
#define T1T_STATIC_CC0_POS 0x8 //0 0001(block 1) 000(byte 0)
//static mem NDEF TLV LEN position
#define T1T_STATIC_NDEF_TLV_LEN_POS 0xc //0 0001(block 1) 100(byte 4)

//dynamic mem ADD CC0 position
#define T1T_DYNAMIC_ADD_CC0_POS 0x1 //block 1
//dynamic mem ADD NDEF position
#define T1T_DYNAMIC_ADD_NDEF_POS 0x2 //block 2

//dynamic mem ADDS CC0 position
#define T1T_DYNAMIC_ADDS_CC0_POS 0x0 //segment 0, block 0





/**********************************************
 * Type 2 Tag related definitions
**********************************************/
/* Type 2 Tag Commands  */
#define T2T_CMD_READ 0x30    /* read  4 blocks (16 bytes) */
#define T2T_CMD_WRITE 0xA2   /* write 1 block  (4 bytes)  */
#define T2T_CMD_SEC_SEL 0xC2 /* Sector select             */
#define T2T_RSP_ACK 0xA //The ACK Response has a value of Ah bit 1010

//The NACK Response has a value of 0h, 1h, 4h, or 5h   bit 0x0x

#define T2T_RSP_NACK5 0x5
#define T2T_RSP_NACK1 0x1 /* Nack can be either 1    */

//T2T mem CC0 position
#define T2T_CC_BLOCK_POS 0x3 //block 3

//T2T static  mem NDEF block position
#define T2T_STATIC_NDEF_BLOCK_POS 0x4 //block 4
//T2T dynamic mem NDEF block position
#define T2T_DYNAMIC_NDEF_BLOCK_POS 0x6 //block 6


/**********************************************
 * Type 3 Tag related definitions
**********************************************/
/* Definitions for constructing t3t command messages */

/* NFC Forum / Felica commands */
#define T3T_MSG_OPC_POLL_CMD 0x00
#define T3T_MSG_OPC_POLL_RSP 0x01
#define T3T_MSG_OPC_CHECK_CMD 0x06
#define T3T_MSG_OPC_CHECK_RSP 0x07
#define T3T_MSG_OPC_UPDATE_CMD 0x08
#define T3T_MSG_OPC_UPDATE_RSP 0x09

#define T3T_SYSTEM_CODE_NDEF 0x12FC /* System Code for NDEF tags */
/* Block service code. Set to T3T_SERVICE_CODE_NDEF (0x000B) for NDEF data */
#define T3T_SERVICE_CODE_NDEF 0x000B
//Service Code 0009h and Service Code 000Bh are available as Overlap Services.(write access to the NDEF data)
#define T3T_SERVICE_CODE_NDEF_WRITE 0x0009


/**********************************************
 * Type 4 Tag related definitions
**********************************************/
//the value use to set T4T_last_CMD_INFO (CLA INS P1 P2)
#define T4T_CMD_DEFAULT 0xFFFFFFFF

//T4T select contents 
//default contents
#define T4T_SEL_CONTENT_DEFAULT 0x0
//T4T select NDEF AID (spec 2.0)
#define T4T_SELECT_CONTENT_NDEF_2 0x1
//T4T select CC file
#define T4T_SELECT_CONTENT_CC_FILE 0x2
//T4T select NDEF file
#define T4T_SELECT_CONTENT_NDEF_FILE 0x3


#define T4T_CMD_SELECT_AID 0x00A40400
#define T4T_CMD_SELECT_FILE 0x00A4000C
#define T4T_CMD_READ_BINARY_BASE 0x00B00000
#define T4T_CMD_MASK 0xFFFF0000


//SNEP_SAP_IN_LLCP
#define SNEP_SAP_IN_LLCP 0x04
//gut connect SNEP server with server role
#define SNEP_SERVER 0x01
//dut connect SNEP with client role
#define SNEP_CLIENT 0x02
//dut other no SNEP SAP
#define NO_SNEP 0x00

/* send remaining fragments         */
#define NFA_SNEP_REQ_CODE_CONTINUE 0x00
/* return an NDEF message           */
#define NFA_SNEP_REQ_CODE_GET 0x01
/* accept an NDEF message           */
#define NFA_SNEP_REQ_CODE_PUT 0x02
/* do not send remaining fragments  */
#define NFA_SNEP_REQ_CODE_REJECT 0x7F

/* continue send remaining fragments    */
#define NFA_SNEP_RESP_CODE_CONTINUE 0x80
/* the operation succeeded              */
#define NFA_SNEP_RESP_CODE_SUCCESS 0x81
/* resource not found                   */
#define NFA_SNEP_RESP_CODE_NOT_FOUND 0xC0
/* resource exceeds data size limit     */
#define NFA_SNEP_RESP_CODE_EXCESS_DATA 0xC1
/* malformed request not understood     */
#define NFA_SNEP_RESP_CODE_BAD_REQ 0xC2
/* unsupported functionality requested  */
#define NFA_SNEP_RESP_CODE_NOT_IMPLM 0xE0
/* unsupported protocol version         */
#define NFA_SNEP_RESP_CODE_UNSUPP_VER 0xE1
/* do not send remaining fragments      */
#define NFA_SNEP_RESP_CODE_REJECT 0xFF



    //...to be continued juns
