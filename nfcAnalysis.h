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
