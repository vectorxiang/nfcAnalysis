#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "nfcAnalysis.h"
#include "tags_defs.h"
#include <map>
#include <stdlib.h>
#include <algorithm>
#include <vector>


using namespace std;


char nfc_log[1024]={'\0'};
FILE *w_fp;
int selected = -1;

//add for support anaylze data packet
uint8_t last_cmd = CMD_UNKNOWN;

uint8_t last_status = RSP_UNKNOWN;


//save the NDEF data
typedef struct {
  int NDEF_TLV_start_pos;  //the start byte pos of NDEF TLV, need to set default value -1, means don't find NDEF yet, will not use in T3T
  uint8_t NDEF_data[1024];   //the contents of NFC data
  uint8_t NDEF_data_len;    //the length of NFC data
  int saved_byte_num;  //the number of bytes already be saved
  uint8_t NDEF_data_bitmap[128];    //the len of NDEF_data/8, save the use of NDEF_data
} tNDEF_DATA_INFO;

//save the TLV ifo
typedef struct {
  int TLV_start_pos;    //the start byte pos of TLV, need to set default value -1, means don't save TLV yet
  uint8_t TLV_type;     //the type of TLV data
  uint8_t TLV_len;      //the len of TLV
} tTLV_INFO;

//save T3T NDEF block info in block list
typedef struct {
  int block_pos;        //the pos of block in check cmd
  int block_number;     //the block number
} tT3T_NDEF_Block_INFO;

typedef struct {
  int size;             //the number of blocks contains in blocks_info[]
  tT3T_NDEF_Block_INFO blocks_info_array[4096];     //the array saves block info
} tT3T_NDEF_Blocks;

//the array save each NDEF data
tNDEF_DATA_INFO tNDEF_data_info_array[MAX_NUM_NDEF_SAVED];
//the  index of unused NDEF data in tNDEF_data_info_array
int lAvailable_NDEF_array_index = 0;


//the array save each TLV data
tTLV_INFO tTLV_info_array[MAX_NUM_TLV_SAVED];
//the  index of unused TLV data in tTLV_info_array
int lAvailable_TLV_array_index = 0;
//the map save <TLV byte pos, index of TLV icfo in tTLV_info_array>
map<int, int> tTLV_pos_data_map;



//save the NDEF TLV position, records each TLV type pos
int lT2T_possible_NDEF_TLV_type_byte_pos;

//if T1T supported NDEF
static uint8_t uT1T_NDEF_supported = 0;
//if T1T has NDEF
static uint8_t uT1T_has_NDEF = 0;
//the len of T1T NDEF
static uint8_t uT1T_NDEF_len = 0;
//if T1T is dynamic mem map
static uint8_t uT1T_dynamic_mem = 0;

//the sector number of T2T READ cmd
static int lT2T_SECTOR_NUM = 0;
//the position of T2T READ cmd
static int lT2T_read_block_pos = -1;
//T2T if wait the SECTOR SELECT Command Packet 2
static uint8_t uT2T_wait_sec_SELECT = 0;
//if T2T has NDEF
static uint8_t uT2T_has_NDEF = 0;
//the totoal block number of T2T, get from CC2
static int lT2T_total_block_NUM = 0;

//T3T POLLING CMD send with system code NDEF (T3T_SYSTEM_CODE_NDEF 0x12FC)
static int iT3T_POLLING_CMD_NDEF_send = 0;
//T3T POLLING rsp with system code NDEF received
static int iT3T_POLLING_RSP_NDEF_rcvd = 0;
//T3T POLLING select NDEF system code
static int iT3T_POLLING_CMD_NDEF_selected = 0;


//T4T NDEF AID selected
static int iT4T_AID_SELECTED = T4T_SEL_CONTENT_DEFAULT;
//T4T NDEF CC selected
static int iT4T_FILE_SELECTED = T4T_SEL_CONTENT_DEFAULT;
//the map save T4T NDEF TLV's file ID <byte pos in ID, content of ID>
map<int, int> tT4T_NDEF_TLV_info_map;
//the map save T4T NDEF TLV's len <byte[0] in NDEF file, byte[1] in NDEF file>
map<int, int> tT4T_NDEF_TLV_len_map;

//NFC_DEP
//if SNEP is connected
static int iNFC_DEP_SNEP_Connected = 0;

void printControlOpration(char *time, char *action, uint8_t type, uint8_t *data,long data_length);
void analyzeData(char *time, char *action, uint8_t type, uint8_t *data,long data_length);
char * getPacketType(uint8_t type);
char * getStatusCodes(uint8_t code);
char * getRFInterface(uint8_t intf);
char * getRFProtocol(uint8_t proto);
char * getRFTecoAndMode(uint8_t teco);
char * getNfcDepType(uint8_t ptype);


char* print_data(uint8_t *data, int data_length);
char* analyze_NFC_NDEF(uint8_t *data, int data_length);
char* GetNDEFType(uint8_t TNF, uint8_t *type,uint8_t type_len);
char * getNFC_A_T1T_cmd(uint8_t cmd);
void analyze_NFC_A_T1T(char *time, char *action, uint8_t type, uint8_t *data,int data_length);
char * getNFC_A_T2T_cmd(uint8_t cmd);
void analyze_NFC_A_T2T(char *time, char *action, uint8_t type, uint8_t *data,int data_length);
void analyze_NFC_F_T3T(char *time, char *action, uint8_t type, uint8_t *data,int data_length);
void initialize_protocal_global_params(int selected);
int getT2T_byte_pos_from_block(int block_pos, int offset);

//get the block pos using byte_pos in mem
int getT2T_block_pos_from_byte(int byte_pos);
//get the block offset using byte_pos in mem
int getT2T_block_offset_from_byte(int byte_pos);
//get the byte pos in mem using data[] index
//data_offset is in [0, 16)
int getT2T_byte_pos_from_READ_params(int data_index, int Read_block_NO);
//get the data[] index using byte pos in mem
//byte_pos is in [(Read_block_NO<<2), (Read_block_NO<<2)+16)
int getT2T_READ_index_from_byte_pos(int byte_pos, int Read_block_NO);
//check if the byte pos contains in the READ rsp,
//byte_pos in [(Read_block_NO<<2), (Read_block_NO<<2)+16)
uint8_t checkT2T_byte_in_READ_rsp(int byte_pos, int Read_block_NO);
//check if the block pos contains in the READ rsp, 
//block_pos in [Read_block_NO, Read_block_NO+4)
uint8_t checkT2T_block_in_READ_rsp(int block_pos, int Read_block_NO);


void save_T2T_NFC_NDEF(uint8_t *data, int data_length, int byte_position, int array_index);



char* print_data(uint8_t *data, int data_length)
{
    static char data_string[4096];
    memset(data_string, 0, sizeof(data_string));
    for (int i = 0; i < data_length; i++)
        sprintf(data_string + i*3,"%02X ", data[i]);
    return data_string;

}

void GetFilename(char *file_path){
    char ch = '\/';
    char *q = strrchr(file_path,ch);
	
 	if(q == NULL){
		sprintf( nfc_log, "%s.nfc", file_path);
	}else
		sprintf( nfc_log, "%s.nfc", q+1);
}

void StringToData(char* string, uint8_t* data ,long len){
	char tmp[3]="00"; 
	long p;
	char *ptr;
	for (int i = 0; i < len; i++) {
		memcpy(tmp,&string[i*2],2);		
		p = strtol(tmp, &ptr, 16);
		data[i]=(uint8_t)(p&0xFF);
	}
}

int main(int argc ,char **argv)
{
	char file_path[128];
	char log_string[4096];
	char time[128] = {'\0'};
	char action[128] = {'\0'};
	char data_length[48] = {'\0'};
	char data_string[4096] = {'\0'};
	uint8_t data[128];
	uint8_t type = 0xFF;
	long data_length_int;
	FILE *r_fp; 	
	
	if(argc == 1){	//read from adb 
		w_fp = stdout;
		r_fp = popen( "adb logcat", "r" );
		if (NULL == r_fp)
		{
			printf("read adb logcat fail\n");
		    return -1;
		}
	}else if(argc == 2){	//read from log file
		strcpy(file_path, *(argv+1));
		printf("file path is %s\n",file_path);	
		GetFilename(file_path);	
		printf("output file is %s\n",nfc_log);
		r_fp=fopen(file_path,"r");
		if (NULL == r_fp)
		{
			printf("can not open %s\n,",file_path);
		    return -1;
		}
		w_fp=fopen(nfc_log,"w+");
		if (NULL == w_fp)
		{
			printf("create nfcAnalysis fail\n");
		    return -1;
		}
	}else{	//error parameters 
		printf("usage:\n");
		printf("read from adb logcat , input : nfcAnalysis\n");
		printf("read from logcat file ,input : nfcAnalysis logPath\n");
		return -1;
	}	
	
	
    while(fgets(log_string, 4096, r_fp)!=NULL){
		if(strlen(time)){
			memset(time, 0, sizeof(time));
			memset(action, 0, sizeof(action));
			memset(data_length, 0, sizeof(data_length));
			memset(data_string, 0, sizeof(data_string));
			memset(data, 0, sizeof(data));
			type = 0xFF;
		}
        if(strstr(log_string,ENABLE_NFC)){
			strncpy(time, log_string, 18);
			strncpy(action, ENABLE_NFC, strlen(ENABLE_NFC));
		}
        if(strstr(log_string,DISABLE_NFC)){
			strncpy(time, log_string, 18);
			strncpy(action, DISABLE_NFC, strlen(DISABLE_NFC));
		}

        if(strstr(log_string,NFC_ENABLED)){
			strncpy(time, log_string, 18);
			strncpy(action, NFC_ENABLED, strlen(NFC_ENABLED));
		}
        if(strstr(log_string,NFC_DISABLED)){
			strncpy(time, log_string, 18);
			strncpy(action, NFC_DISABLED, strlen(NFC_DISABLED));
		}		
		
        if(strstr(log_string,DATA_SEND)){
			strncpy(time, log_string, 18);
			strncpy(action, "==>", 3);
			sscanf(log_string,"%*[^=]=%[^=]=>%s",data_length,data_string);
			
		}
		if(strstr(log_string,DATA_RECEIVE)){
			strncpy(time, log_string, 18);
			strncpy(action, "<==", 3);	
			sscanf(log_string,"%*[^=]=%[^<]<=%s",data_length,data_string);			
		}
		
		if( (data_string != NULL) && strlen(data_string)){
			char *ptr;			
			data_length_int = strtol(data_length, &ptr, 10);
			if((data_length_int*2) == strlen(data_string)){
				StringToData(data_string, data ,data_length_int);
			}else{
				printf("data error at %s\n",time);
				return -1;
			}
			type = data[0]>>5;
		}
		
		if(strlen(time)){
			if(type == NCI_MT_DATA){
				analyzeData(time, action, type, data, data_length_int);
				fprintf (w_fp, "------  %s\n",data_string);
			}else if(type != 0xFF){
				printControlOpration(time, action, type, data,data_length_int);
				fprintf (w_fp, "------  %s\n",data_string);				
			}else
				fprintf (w_fp, "%s\t%s\n",time,action);
		}
    };
	
	fclose(w_fp);
	fclose(r_fp);
    return 1;
}

//save T4T NDEF block into tNDEF_data_info_array[0], data_length is the size of data,
//byte_index is the index of data[0] in NDEF
//the size of data[] is 16
void save_T4T_NFC_NDEF(uint8_t *data, int data_length, int index)
{
    for (int i = 0; i < data_length; i++)
    {
        if(0 == tNDEF_data_info_array[0].NDEF_data_len)
        {
            //save the NDEF len
             if (0 == i+index)
             {
                tT4T_NDEF_TLV_len_map[0] = data[0];
             }
             else if (1 == i+index)
             {
                tT4T_NDEF_TLV_len_map[1] = data[1];
             }
             if (2 == tT4T_NDEF_TLV_len_map.size())
             {
                tNDEF_data_info_array[0].NDEF_data_len = (tT4T_NDEF_TLV_len_map[0]<<8)|tT4T_NDEF_TLV_len_map[1];
                //fprintf (w_fp, "\n\ndata[0] is 0x%X, data[1] is 0x%X\n\n", data[0], data[1]);
             }
        }
        else
        {
            //save the NDEF data
            if (i+index > 1 && tNDEF_data_info_array[0].saved_byte_num < tNDEF_data_info_array[0].NDEF_data_len)
            {
                int index_in_NDEF_data = i+index-2;
                if ((tNDEF_data_info_array[0].NDEF_data_bitmap[index_in_NDEF_data>> 3] & (1 << (index_in_NDEF_data%8))) == 0)
                {
                    //fprintf (w_fp, "\n\t\t\t\t position = %d data= 0x%X\n\n",i+byte_pos_index, data[i]);
                    
                    //save the byte to NDEF_data
                    tNDEF_data_info_array[0].NDEF_data[index_in_NDEF_data] = data[i];
                    //set the bitmap bit
                    tNDEF_data_info_array[0].NDEF_data_bitmap[index_in_NDEF_data>> 3] |= (1 << (index_in_NDEF_data%8));
                    //increase the saved_byte_num
                    tNDEF_data_info_array[0].saved_byte_num++;
                    if (tNDEF_data_info_array[0].saved_byte_num == tNDEF_data_info_array[0].NDEF_data_len)
                    {
                        //fprintf (w_fp, "\t\t\t analyze NDEF info!\n");
                        analyze_NFC_NDEF(tNDEF_data_info_array[0].NDEF_data, tNDEF_data_info_array[0].NDEF_data_len);
                    }
                }
            }
        }
    }
}

//Type 4 Tag == ISO-DEP
void analyze_ISO_DEP(char *time, char *action, uint8_t type, uint8_t *data,long data_length){
	char ctrlcommand[128];
	char parameter[4096];
	memset(ctrlcommand, 0, sizeof(ctrlcommand));
	memset(parameter, 0, sizeof(parameter));

    //if select Type 4 2.0 NDEF application
    static int T4T_NDEF_2_AID_SELECT;

    //if the last cmd is SELECT cmd && the AID in last SELECT cmd is 2.0 NDEF application
    static int T4T_last_CMD_INFO = T4T_CMD_DEFAULT;
    //if the last cmd is READ cmd record the Le in READ cmd
    static int T4T_last_READ_LE = 0;
    //set T4T_selected_content with default value
    static int T4T_selected_content = T4T_SEL_CONTENT_DEFAULT;
    
	if( !strcmp(action,"==>") ){	//command
		uint8_t cla = data[0];
		uint8_t ins = data[1];
		uint8_t p1 = data[2];
		uint8_t p2 = data[3];

        //save the cmd
        T4T_last_CMD_INFO = ((int)cla << 24) | ((int)ins << 16) | ((int)p1 << 8) | ((int)p2);
        fprintf (w_fp, "\n\n\tCMD T4T_last_CMD_INFO is 0x%X\n", T4T_last_CMD_INFO);
        //set T4T_selected_content with default value
        T4T_selected_content = T4T_SEL_CONTENT_DEFAULT;
        T4T_last_READ_LE = 0;

		if( cla == T4T_CMD_CLASS && ins == T4T_CMD_INS_SELECT ){ // SELECT
			strcpy(ctrlcommand,"Select");
			if( p1==T4T_CMD_P1_SELECT_BY_NAME ){
				if( data[4]==T4T_NDEF_TAG_AID_LEN && ( !memcmp(&data[5], T4T_V10_NDEF_TAG_AID ,7) || 
					!memcmp(&data[5], T4T_V20_NDEF_TAG_AID ,7)) )
                {
                    if (!memcmp(&data[5], T4T_V20_NDEF_TAG_AID ,7))
                    {
                        T4T_selected_content = T4T_SELECT_CONTENT_NDEF_2;
                    }
					strcpy(parameter,"BY_NAME\t\tNDEF_Tag_Application");
                }
				else{ 
					char tmp[1024] = {'0'};
					memcpy(tmp, &data[5], data[4]);
					sprintf(parameter, "BY_NAME\t\t%s",tmp);
				}
			}else if( p1==T4T_CMD_P1_SELECT_BY_FILE_ID ){
				if( data[4]==T4T_FILE_ID_SIZE && !memcmp(&data[5], T4T_CC_FILE_ID ,2) )
                {
					strcpy(parameter,"BY_ID\t\tCC_FILE");
                    //select CC file
                    T4T_selected_content = T4T_SELECT_CONTENT_CC_FILE;
                    
                        fprintf (w_fp, "\n\n\tT4T_SELECT_CONTENT_CC_FILE\n\n");
                }
				else if( data[4]==T4T_FILE_ID_SIZE ){
                    //deal with select NDEF file, compare with file id saved before
                    //if save the whole NDEF file ID info in NDEF TLV, check if the file selected is NDEF file
                    if (2 == tT4T_NDEF_TLV_info_map.size() 
                        && tT4T_NDEF_TLV_info_map[0] == data[5] 
                        && tT4T_NDEF_TLV_info_map[1] == data[6])
                    {
                        T4T_selected_content = T4T_SELECT_CONTENT_NDEF_FILE;
                        fprintf (w_fp, "\n\n\tT4T_SELECT_CONTENT_NDEF_FILE 0x%X\n\n", (data[5]<<8|data[6]));
                    }
					sprintf(parameter,"BY_ID\t\t%02X%02X",data[5],data[6]);
				}
			}					
		}else if( cla == T4T_CMD_CLASS && ins == T4T_CMD_INS_READ_BINARY ){		//ReadBinary
			unsigned short offset = data[2]<<8|data[3];
			strcpy(ctrlcommand,"Read");
            T4T_last_READ_LE = data[data_length-1];
			sprintf(parameter, "Offset:%04X",offset);
			sprintf(parameter, "%s\t\tLen:%02X",parameter,data[data_length-1]);
		}else if( cla == T4T_CMD_CLASS && ins == T4T_CMD_INS_UPDATE_BINARY ){		//UpdateBinary
			unsigned short offset = data[2]<<8|data[3];
			strcpy(ctrlcommand,"Write");
			sprintf(parameter, "Offset:%04X",offset);
			sprintf(parameter, "%s\t\tLen:%02X",parameter,data[data_length-1]);
		}else if( cla == T4T_CMD_CLASS && ins == T4T_CMD_INS_READ_RECORD ){		//ReadRecord
			strcpy(ctrlcommand,"ReadRecord");
		}else if( cla == T4T_CMD_DES_CLASS && ins == T4T_CMD_INS_GET_HW_VERSION ){	
			strcpy(ctrlcommand,"GET_HW_VERSION");
		}else if( cla == T4T_CMD_DES_CLASS && ins == T4T_CMD_SELECT_APP ){	
			strcpy(ctrlcommand,"SELECT_APP");
		}					
	}else if( !strcmp(action,"<==") ){

		uint16_t status_words;
		BE_STREAM_TO_UINT16(status_words, (data+data_length-2));
		if(status_words == T4T_RSP_CMD_CMPLTED)
        {
			strcpy(parameter,"CMD_CMPLTED");
            int offset = 0; 
            fprintf (w_fp, "\n\n\tRSP T4T_last_CMD_INFO is 0x%X\n", T4T_last_CMD_INFO);
            if (T4T_CMD_READ_BINARY_BASE == (T4T_last_CMD_INFO & T4T_CMD_MASK))
            {
                offset = T4T_last_CMD_INFO & 0xFFFF ; 
                //reset the P1 P2 in T4T_last_CMD_INFO
                T4T_last_CMD_INFO = T4T_CMD_READ_BINARY_BASE;
            }
            switch (T4T_last_CMD_INFO)
            {
                case T4T_CMD_SELECT_AID:
                {
                    //last cmd select type 4 spec 2.0 NDEF AID
                    if (T4T_SELECT_CONTENT_NDEF_2 == T4T_selected_content)
                    {
                        //NDEF AID is selected
                        iT4T_AID_SELECTED = T4T_SELECT_CONTENT_NDEF_2;
                    }
                    //select other AID
                    else
                    {
                        iT4T_AID_SELECTED = T4T_SEL_CONTENT_DEFAULT;
                    }
                    break;
                }
                case T4T_CMD_SELECT_FILE:
                {
                    iT4T_FILE_SELECTED = T4T_SEL_CONTENT_DEFAULT;
                    if (T4T_SELECT_CONTENT_NDEF_2 == iT4T_AID_SELECTED)
                    {
                        if (T4T_SELECT_CONTENT_CC_FILE == T4T_selected_content)
                        {
                            iT4T_FILE_SELECTED = T4T_SELECT_CONTENT_CC_FILE;
                        }
                        else if(T4T_SELECT_CONTENT_NDEF_FILE == T4T_selected_content)
                        {
                            iT4T_FILE_SELECTED = T4T_SELECT_CONTENT_NDEF_FILE;
                        }
                    }
                    break;
                }
                case T4T_CMD_READ_BINARY_BASE:
                {
                    switch (iT4T_FILE_SELECTED)
                    {
                        case T4T_SELECT_CONTENT_CC_FILE:
                        {
                            fprintf (w_fp, "\n\n\toffset is %d, read_data_len is %d, READ T4T_SELECT_CONTENT_NDEF_FILE %s\n\n",
                                offset, T4T_last_READ_LE, print_data(data, data_length));
                            //if saving NDEF_TLV file ID related dyte save it into tT4T_NDEF_TLV_info
                            //use (offset<<8) + data_length - 2) for, le is optional param
                            if ((offset<<8) <= 9 && 9 < ((offset<<8) + T4T_last_READ_LE))
                            {
                                tT4T_NDEF_TLV_info_map[0] = data[9];
                            }
                            if ((offset<<8) <= 10 && 10 < ((offset<<8) + T4T_last_READ_LE))
                            {
                                tT4T_NDEF_TLV_info_map[1] = data[10];
                            }
                            break;
                        }
                        case T4T_SELECT_CONTENT_NDEF_FILE:
                        {
                            //save the NDEF data
                            save_T4T_NFC_NDEF(data, T4T_last_READ_LE, offset);
                            fprintf (w_fp, "\n\n\toffset is %d, read_data_len is %d, READ T4T_SELECT_CONTENT_NDEF_FILE %s\n\n",
                                offset, T4T_last_READ_LE, print_data(data, data_length));
                            break;
                        }
                        default:
                        {
                            break;
                        }
                    }
                }
                default:
                {
                    break;
                }
            }

        }
		else if(status_words == T4T_RSP_NOT_FOUND)
			strcpy(parameter,"NOT_FOUND");
		else if(status_words == T4T_RSP_WRONG_PARAMS)
			strcpy(parameter,"WRONG_PARAMS");
		else if(status_words == T4T_RSP_CLASS_NOT_SUPPORTED)
			strcpy(parameter,"CLASS_NOT_SUPPORTED");
		else if(status_words == T4T_RSP_WRONG_LENGTH)
			strcpy(parameter,"WRONG_LENGTH");
		else if(status_words == T4T_RSP_INSTR_NOT_SUPPORTED)
			strcpy(parameter,"INSTR_NOT_SUPPORTED");	
		else if(status_words == T4T_RSP_CMD_NOT_ALLOWED)
			strcpy(parameter,"CMD_NOT_ALLOWED");
		else if(status_words == SW_INCORRECT_P1P2)
			strcpy(parameter,"INCORRECT_P1P2");
		else if(status_words == SW_FILE_OR_APP_NOT_FOUND)
			strcpy(parameter,"FILE_OR_APP_NOT_FOUND");																												

        //the last cmd is handled, set the last cmd to default cmd
        T4T_last_CMD_INFO = T4T_CMD_DEFAULT;
	}
	fprintf (w_fp, "%s\t%s\t\t%s\t%s\t%s\n",time,action,getPacketType(type),ctrlcommand,parameter);
}

char * getNFC_SNEP_cmd(uint8_t cmd){
	static char SNEP_cmd[100];
	memset(SNEP_cmd, 0, sizeof(SNEP_cmd));
    switch(cmd)
    {
        case NFA_SNEP_REQ_CODE_CONTINUE:
            strcpy(SNEP_cmd,"NFA_SNEP_REQ_CODE_CONTINUE");
            break;
        case NFA_SNEP_REQ_CODE_GET:
            strcpy(SNEP_cmd,"NFA_SNEP_REQ_CODE_GET");
            break;
        case NFA_SNEP_REQ_CODE_PUT:
            strcpy(SNEP_cmd,"NFA_SNEP_REQ_CODE_PUT");
            break;
        case NFA_SNEP_REQ_CODE_REJECT:
            strcpy(SNEP_cmd,"sNFA_SNEP_REQ_CODE_REJECT");
        default:
            strcpy(SNEP_cmd,"UNDETERMINED");
            break;
    }

    return SNEP_cmd;
}

char * getNFC_SNEP_rsp(uint8_t rsp){
	static char SNEP_rsp[100];
	memset(SNEP_rsp, 0, sizeof(SNEP_rsp));
    switch(rsp)
    {
        case NFA_SNEP_RESP_CODE_CONTINUE:
            strcpy(SNEP_rsp,"NFA_SNEP_RESP_CODE_CONTINUE");
            break;
        case NFA_SNEP_RESP_CODE_SUCCESS:
            strcpy(SNEP_rsp,"NFA_SNEP_RESP_CODE_SUCCESS");
            break;
        case NFA_SNEP_RESP_CODE_NOT_FOUND:
            strcpy(SNEP_rsp,"NFA_SNEP_RESP_CODE_NOT_FOUND");
            break;
        case NFA_SNEP_RESP_CODE_EXCESS_DATA:
            strcpy(SNEP_rsp,"NFA_SNEP_RESP_CODE_EXCESS_DATA");
            break;
        case NFA_SNEP_RESP_CODE_BAD_REQ:
            strcpy(SNEP_rsp,"NFA_SNEP_RESP_CODE_BAD_REQ");
            break;
        case NFA_SNEP_RESP_CODE_NOT_IMPLM:
            strcpy(SNEP_rsp,"NFA_SNEP_RESP_CODE_NOT_IMPLM");
            break;
        case NFA_SNEP_RESP_CODE_UNSUPP_VER:
            strcpy(SNEP_rsp,"NFA_SNEP_RESP_CODE_UNSUPP_VER");
            break;
        case NFA_SNEP_RESP_CODE_REJECT:
            strcpy(SNEP_rsp,"NFA_SNEP_RESP_CODE_REJECT");
            break;
        default:
            strcpy(SNEP_rsp,"UNDETERMINED");
            break;
    }

    return SNEP_rsp;
}

void analyze_NFC_DEP(char *time, char *action, uint8_t type, uint8_t *data,long data_length){
	char ctrlcommand[128];
	char parameter[4096];

	memset(ctrlcommand, 0, sizeof(ctrlcommand));
	memset(parameter, 0, sizeof(parameter));
	uint8_t dsap = data[0]>>2;
	uint8_t ptype = ((data[0]&0x3)<<2)|((data[1]&0xC0)>>6);
	uint8_t ssap = data[1]&0x3F;
	sprintf(ctrlcommand,"Ptype: %s, DSAP: %02X, SSAP: %02X",getNfcDepType(ptype),dsap,ssap);
	if(ptype == 0x04){
		if(data[2] == 0x06)	//Service Name
			sprintf(parameter,"%s",&data[4]);
        else if (SNEP_SAP_IN_LLCP == dsap)
        {
            sprintf(parameter,"%s","urn:nfc:sn:snep");
        }
	}

	fprintf (w_fp, "%s\t%s\t\t%s\t%s\t%s\n",time,action,getPacketType(type),ctrlcommand,parameter);
    
    //connect complete
    if (ptype == 0x06)
    {
        // SNEP sap is connected
        if (SNEP_SAP_IN_LLCP == ssap)
        {
            //clear all NDEF data
            /////////////////////////////
            
            //tx cmd, action == "==>"
            if (action[0] == '=')
            {
                iNFC_DEP_SNEP_Connected = SNEP_SERVER;
                fprintf (w_fp, "\ndut is server in SNEP\n\n\n");
            }
            //rx rsp, action == "<=="
            else
            {
                iNFC_DEP_SNEP_Connected = SNEP_CLIENT;
                fprintf (w_fp, "\ndut is client in SNEP\n\n\n");
            }
        }
        //connect other sap
        else
        {
            iNFC_DEP_SNEP_Connected = NO_SNEP;
        }
    }

    //if SNEP is connected && is Information && sap is SNEP, analyze SNEP data from data[3]
    if (NO_SNEP != iNFC_DEP_SNEP_Connected && 0x0C == ptype && 
        (SNEP_SAP_IN_LLCP == ssap || SNEP_SAP_IN_LLCP == dsap))
    {
        //SNEP cmd, client "==>" or server "<=="
        if (SNEP_SAP_IN_LLCP == dsap)
        {
            last_cmd = data[4];
            switch (last_cmd)
            {
                case NFA_SNEP_REQ_CODE_CONTINUE:
                    fprintf (w_fp, "\nclient continue to get\n");
                    break;
                case NFA_SNEP_REQ_CODE_GET:
                    fprintf (w_fp, "\nclient want to get, NDEF is %s\n", print_data(&data[9], data_length-9));
                    analyze_NFC_NDEF(&data[9], data_length-9);
                    break;
                case NFA_SNEP_REQ_CODE_PUT:
                    fprintf (w_fp, "\nclient want to put, NDEF is %s\n", print_data(&data[9], data_length-9));
                    if (NFA_SNEP_RESP_CODE_CONTINUE == last_status)
                    {
                        //save to the last NDEF
                    }
                    else
                    {
                        //save to an new NDEF
                    }
                    analyze_NFC_NDEF(&data[9], data_length-9);
                    break;
                case NFA_SNEP_REQ_CODE_REJECT:
                    fprintf (w_fp, "\nclient reject to get\n");
                    break;
                default:
                    break;
            }
            if(NFA_SNEP_RESP_CODE_CONTINUE != last_status)
            {
                //the cmd is respond, hence set it to default cmd
                last_status = RSP_UNKNOWN;
            }
            fprintf (w_fp, "\nthe cmd of SNEP is %s\n\n\n", getNFC_SNEP_cmd(last_cmd));
        }
        //SNEP rsp, client "<==" or server "==>"
        else if (SNEP_SAP_IN_LLCP == ssap)
        {
            last_status = data[4];
            if (NFA_SNEP_RESP_CODE_SUCCESS == data[4])
            {
                if (NFA_SNEP_REQ_CODE_GET == last_cmd)
                {
                    //save to an new NDEF
                }
                else if (NFA_SNEP_REQ_CODE_CONTINUE == last_cmd)
                {
                    //save to the last NDEF
                }
            }
            if(NFA_SNEP_REQ_CODE_CONTINUE != last_cmd)
            {
                //the cmd is respond, hence set it to default cmd
                last_cmd = CMD_UNKNOWN;
            }
            fprintf (w_fp, "\nthe rsp of SNEP is %s\n\n\n", getNFC_SNEP_rsp(last_status));
        }
    }

}

void analyze_MIFARE_CLASSIC(char *time, char *action, uint8_t type, uint8_t *data,long data_length){
	char ctrlcommand[128];
	char parameter[4096];
	memset(ctrlcommand, 0, sizeof(ctrlcommand));
	memset(parameter, 0, sizeof(parameter));
	uint8_t reqId = data[0];
	if( !strcmp(action,"==>") ){	//command
		if( reqId == MFC_AUTH )
			strcpy(ctrlcommand,"MFC_AUTH");
	}else if( !strcmp(action,"<==") ){
		if(reqId == MFC_AUTH){
			strcpy(ctrlcommand,"MFC_AUTH");
			uint8_t status = data[1];
			if(status == 0x00)
				strcpy(parameter,"OK");
			else if(status == 0x03)
				strcpy(parameter,"FAILED");
		}
	}		

	fprintf (w_fp, "%s\t%s\t\t%s\t%s\t%s\n",time,action,getPacketType(type),ctrlcommand,parameter);
}

char* GetNDEFType(uint8_t TNF, uint8_t *type,uint8_t type_len){
    static char NDEF_type[128];
    memset(NDEF_type, 0, sizeof(NDEF_type));

    switch (TNF)
    {
        //Empty
        case 0x00:
            strcpy(NDEF_type, "EMPTY");
            break;
        //NFC Forum well-known type [NFC RTD]
        case 0x01:
            if (type_len > 0)
            {
                int len = type_len;
                print_data(type, 1);
                //global type
                if ((type[0] >= 'A' && type[0] <= 'Z')
                    || (type_len >= 13 && (strncmp((char*)type, "urn:nfc:wkt:", 12) == 0) && (type[12] >= 'A' && type[12] <= 'Z')))
                {
                    if (type_len == 1)
                    {
                        switch (type[0])
                        {
                            case 'T':
                                strcpy(NDEF_type, "\'T\': RTD Text");
                                break;
                            case 'U':
                                strcpy(NDEF_type, "\'U\': RTD URI");
                                break;
                            default:
                                sprintf(NDEF_type,"RTD UNKNOWN Type: %02X", type[0]);
                                break;
                        }
                    }
                    else if (type_len == 2)
                    {
                        if (0 == strncmp((char*)type, "Sp", 2))
                        {
                            strcpy(NDEF_type, "\"Sp\": RTD Smart Poster");
                        }
                    }
                    else if (type_len == 3)
                    {
                        if (0 == strncmp((char*)type, "Sig", 3))
                        {
                            strcpy(NDEF_type, "\"Sig\": RTD Signature");
                        }
                    }
                    else
                    {
                        sprintf(NDEF_type, "UNKNOWN Global RTD type: %s", print_data(type, type_len));
                    }
                }
                //local type
                else
                {
                    sprintf(NDEF_type, "Local RTD type: %s", print_data(type, type_len));
                }
            }
            else
            {
                strcpy(NDEF_type, "error RTD type len");
            }
            break;
        //Media-type as defined in RFC 2046 [RFC 2046]
        case 0x02:
            strcpy(NDEF_type, "Media-type");
            break;
        //Absolute URI as defined in RFC 3986
        case 0x03:
            strcpy(NDEF_type, "Absolute URI");
            break;
        //NFC Forum external type
        case 0x04:
            strcpy(NDEF_type, "NFC Forum external type");
            break;
        //Unknown
        case 0x05:
            strcpy(NDEF_type, "Unknown");
            break;
        //Unchanged
        case 0x06:
            strcpy(NDEF_type, "Unchanged");
            break;
        //Reserved
        case 0x07:
            strcpy(NDEF_type, "Reserved");
            break;
        default:
            sprintf(NDEF_type,"UNKNOWN TNF Type: 0x%02X, type is %s", TNF, print_data(type, type_len));
            break;
    }
    return NDEF_type;

}

//to be continued to  juns   analyze ME == 0
char* analyze_NFC_NDEF(uint8_t *data, int data_length)  //juns to be continued
{
    static char NDEF_data[4096];
    memset(NDEF_data, 0, sizeof(NDEF_data));
    for (int i = 0; i < data_length; i++)
        sprintf(NDEF_data + i*3,"%02X ", data[i]);
    //SR is byte 4, SR == 1, len_of_payload_len =1; SR == 0,len_of_payload_len =4
    uint8_t len_of_payload_len = ((data[0] & 0x10) >> 4)?1:4;
    //IL is byte 3, IL == 1, NDEF contains ID len, else NDEF does not contain ID and ID len 
    uint8_t len_of_ID_len = ((data[0] & 0x8) >> 3)?1:0;
    uint8_t NDEF_type_index = 2+len_of_payload_len+len_of_ID_len;
    //TNF is byte 0-2
    uint8_t NDEF_TNF = data[0] & 0x7;
    uint8_t type_len = data[1];

    char* string = NULL;
    string = GetNDEFType(NDEF_TNF, &data[NDEF_type_index], type_len);
    fprintf (w_fp, "\n\tanalyze_NFC_NDEF, type is: %s\n", string);
    fprintf (w_fp, "\n\tanalyze_NFC_NDEF, data_length is %d totoal NDEF data is: %s\n\n\n", data_length, print_data(data, data_length));
    return NDEF_data;

}

char * getNFC_A_T1T_cmd(uint8_t cmd){
	static char T1T_cmd[100];
	memset(T1T_cmd, 0, sizeof(T1T_cmd));
    switch(cmd)
    {
        case T1T_CMD_RID:
            strcpy(T1T_cmd,"T1T_CMD_RID");
            break;
        //static cmd
        case T1T_CMD_RALL:
            strcpy(T1T_cmd,"static T1T_CMD_RALL");
            break;
        case T1T_CMD_READ:
            strcpy(T1T_cmd,"static T1T_CMD_READ");
            break;
        case T1T_CMD_WRITE_E:
            strcpy(T1T_cmd,"static T1T_CMD_WRITE_E");
            break;
        case T1T_CMD_WRITE_NE:
            strcpy(T1T_cmd,"static T1T_CMD_WRITE_NE");
            break;
        //dynamic cmd
        case T1T_CMD_RSEG:
            strcpy(T1T_cmd,"dynamic T1T_CMD_RSEG");
            break;
        case T1T_CMD_READ8:
            strcpy(T1T_cmd,"dynamic T1T_CMD_READ8");
            break;
        case T1T_CMD_WRITE_E8:
            strcpy(T1T_cmd,"dynamic T1T_CMD_WRITE_E8");
            break;
        case T1T_CMD_WRITE_NE8:
            strcpy(T1T_cmd,"dynamic T1T_CMD_WRITE_NE8");
            break;

        default:
            strcpy(T1T_cmd,"UNDETERMINED");
            break;
    }

    return T1T_cmd;
}

void analyze_NFC_A_T1T(char *time, char *action, uint8_t type, uint8_t *data, int data_length)
{
    if (data_length >= 2)   //rsp packet only has 3 byte: ADD DAT Status
    {
        //tx cmd, action == "==>"
        if (action[0] == '=')
        {
           last_cmd = data[0];
        }
        //rx rsp, action == "<=="
        else if (action[0] == '<')
        {
            switch(last_cmd)
            {
                case T1T_CMD_RID:
                    if ((data[0] & 0xF0) == T1T_NDEF_SUPPORTED)
                    {
                        uT1T_NDEF_supported = 1;
                    }
                    if ((data[0] & 0x0F) != 1)
                    {
                        uT1T_dynamic_mem = 1;
                    }
                    break;
                //static mem only
                case T1T_CMD_RALL:  //only static mem map has this cmd, no situation to test now
                    if (data[10] == 0xE1) //CC0 NMN has NDEF
                    {
                        uT1T_has_NDEF = 1;
                        //NDEF is after CC
                        if (data[14] == 0x03)   //NDEF TLV type
                        {
                            //to be continued, juns, change to save then analyze
                            analyze_NFC_NDEF(&data[16], data[15]);  //data[15] len of NDEF, data[16] the begin byte
                        }
                    }
                    break;
                case T1T_CMD_READ:
                    switch (data[0])
                    {
                        case T1T_STATIC_CC0_POS:
                            if (data[1] == 0xE1) //CC0 NMN has NDEF
                            {
                                uT1T_has_NDEF = 1;
                            }
                            break;
                        case T1T_STATIC_NDEF_TLV_LEN_POS:
                            if (uT1T_has_NDEF)
                                uT1T_NDEF_len = data[1];
                            break;
                        default:
                            {
                                //analyze and save the byte, not implememted here
                            }
                            break;
                    }
                    break;
                //dynamic mem only
                case T1T_CMD_RSEG:  //will read 128 byte
                    {
                        if (data[0] == T1T_DYNAMIC_ADDS_CC0_POS)
                        {
                            if (data[9] == 0xE1)
                            {
                                uT1T_has_NDEF = 1;
                                if (data[23] == 0x03)   //NDEF TLV type
                                {
                                    uT1T_NDEF_len = data[24];
                                    
                                    //to be continued, juns, change to save then analyze
                                    analyze_NFC_NDEF(&data[25], data[24]);  //data[24] len of NDEF, data[25] the begin byte
                                }
                            }
                        }
                    }
                    break;
                case T1T_CMD_READ8:
                    {
                        if (data[0] == T1T_DYNAMIC_ADD_CC0_POS)
                        {
                            if (data[1] == 0xE1) //CC0 NMN has NDEF
                            {
                                uT1T_has_NDEF = 1;
                            }
                        }
                        else if (data[0] == T1T_DYNAMIC_ADD_NDEF_POS)
                        {
                            if (uT1T_has_NDEF == 1)    //it is NDEF TLV
                            {
                                if (data[7]== 0x03)
                                {
                                    uT1T_NDEF_len = data[8];
                                }
                            }
                        }
                        else if (uT1T_has_NDEF == 1 && uT1T_NDEF_len != 0 && (data[0] > 2) 
                            && (data[0] *8 - 16 < uT1T_NDEF_len))
                        {
                            //save the NDEF msg to arrary and check if the array is full, if full analyze it, need array initialize and destory
                        }
                    }
                    break;
                default:
                    break;
            }
        }
    }

    //...to be continued juns
    fprintf (w_fp, "%s\t%s\t\tuT1T_NDEF_supported: %d, uT1T_dynamic_mem: %d, cmd is %s\n",
                time,action,uT1T_NDEF_supported, uT1T_dynamic_mem, getNFC_A_T1T_cmd(last_cmd));
    
    //fprintf (w_fp, "\njunsheng_NFC print_data: %s\n\n", print_data(data, data_length));
}


char * getNFC_A_T2T_cmd(uint8_t cmd){
	static char T2T_cmd[100];
	memset(T2T_cmd, 0, sizeof(T2T_cmd));
    switch(cmd)
    {
        case T2T_CMD_READ:
            strcpy(T2T_cmd,"T2T_CMD_READ");
            break;
        case T2T_CMD_WRITE:
            strcpy(T2T_cmd,"T2T_CMD_WRITE");
            break;
        case T2T_CMD_SEC_SEL:
            strcpy(T2T_cmd,"T2T_CMD_SEC_SEL");
            break;
        default:
            strcpy(T2T_cmd,"UNDETERMINED");
            break;
    }

    return T2T_cmd;
}

//get byte pos in mem using block and offset
//offset is in [0,4)
int getT2T_byte_pos_from_block(int block_pos, int offset)
{
    return (block_pos<<2) + offset;
}

//get the block pos using byte_pos in mem
int getT2T_block_pos_from_byte(int byte_pos)
{
    return byte_pos>>2;
}

//get the block offset using byte_pos in mem
int getT2T_block_offset_from_byte(int byte_pos)
{
    return byte_pos & 3;
}

//get the byte pos in mem using data[] index
//data_offset is in [0, 16)
int getT2T_byte_pos_from_READ_params(int data_index, int Read_block_NO)
{
    return (Read_block_NO<<2) + data_index;
}

//get the data[] index using byte pos in mem
//byte_pos is in [(Read_block_NO<<2), (Read_block_NO<<2)+16)
int getT2T_READ_index_from_byte_pos(int byte_pos, int Read_block_NO)
{
    return byte_pos - (Read_block_NO<<2);
}

//check if the byte pos contains in the READ rsp,
//byte_pos in [(Read_block_NO<<2), (Read_block_NO<<2)+16)
uint8_t checkT2T_byte_in_READ_rsp(int byte_pos, int Read_block_NO)
{
    return ((byte_pos >= (Read_block_NO<<2)) && (byte_pos < (Read_block_NO<<2)+16));
}

//check if the block pos contains in the READ rsp, 
//block_pos in [Read_block_NO, Read_block_NO+4)
uint8_t checkT2T_block_in_READ_rsp(int block_pos, int Read_block_NO)
{
    return ((block_pos >= Read_block_NO) && (block_pos < Read_block_NO+4));
}

/*
int find_Unuse_index_in_NDEF_info_array()
{
    for (int i = 0; i < MAX_NUM_NDEF_SAVED; i++)
    {
        if (tNDEF_data_info_array[i].NDEF_TLV_start_pos == -1)
        {
            return i;
        }
    }
    //fail to find unuse index
    return -1;
}


//find the first unuse index in [start_index, end_index]
int find_Unuse_index_in_TLVinfo_array_binary(int start_index, int end_index)
{
    if (start_index > end_index || start_index < 0 || end_index >= MAX_NUM_TLV_SAVED || tTLV_info_array[end_index] != -1)
    {
        return -1;
    }
    if (tTLV_info_array[start_index] == -1)
    {
        return start_index;
    }
    if(tTLV_info_array[(start_index + end_index)/2].TLV_start_pos == -1)
    {
        return find_Unuse_index_in_TLVinfo_array_binary(start_index+1, (start_index + end_index)/2);
    }
    else
    {
        return find_Unuse_index_in_TLVinfo_array_binary((start_index + end_index)/2+1, end_index);
    }
}
*/

//save the T2T NDEF to tNDEF_data_info, if save the complete NDEF, will trigger the NDEF analysis
//data is the array contains NDEF, data_length is the len of data to be saved,
//byte_position is the position of data[0] in the total NDEF
void save_T2T_NFC_NDEF(uint8_t *data, int data_length, int byte_position, int array_index = -1)
{
    fprintf (w_fp, "\tsave_NFC_NDEF data, byte_position: %d, data_len is %d, data is %s\n", byte_position, data_length, print_data(data, data_length));

    if (-1 != array_index)
    {
        //check if array_index is correct
        if (tNDEF_data_info_array[array_index].NDEF_data_len == 0
                || (tNDEF_data_info_array[array_index].NDEF_TLV_start_pos + 2) > byte_position
                || byte_position >= (tNDEF_data_info_array[array_index].NDEF_TLV_start_pos + 2 + tNDEF_data_info_array[array_index].NDEF_data_len))
        {
            //incorrect array_index
            array_index = -1;
        }
    }
    if (-1 == array_index)
    {
        //caculate the index of tNDEF_data_info_array
        for (int i = 0; i<lAvailable_NDEF_array_index; i++)
        {
            //i < lAvailable_NDEF_array_index ensure tNDEF_data_info_array[i].NDEF_TLV_start_pos != -1
            if (tNDEF_data_info_array[i].NDEF_data_len != 0
                && (tNDEF_data_info_array[i].NDEF_TLV_start_pos + 2) <= byte_position
                && byte_position < (tNDEF_data_info_array[i].NDEF_TLV_start_pos + 2 + tNDEF_data_info_array[i].NDEF_data_len))
            {
                array_index = i;
                break;
            }
        }
        //fail to find NDEF data corresponding index
        return;
    }
    
    int byte_pos_index = byte_position - tNDEF_data_info_array[array_index].NDEF_TLV_start_pos - 2;
    int i_max = min(data_length, (int)tNDEF_data_info_array[array_index].NDEF_data_len - byte_pos_index);
    if (tNDEF_data_info_array[array_index].saved_byte_num < tNDEF_data_info_array[array_index].NDEF_data_len)
    {
        //fprintf (w_fp, "\n\t\t\t i_max = %d byte_pos_index= %d\n\n",i_max, byte_pos_index);
        for (int i = 0; i < i_max; i++)
        {
            //fprintf (w_fp, "\n\t\t\t\t position = %d data= 0x%X, NDEF_data_bitmap[%d]= 0x%x & 0x%X\n\n",i+byte_pos_index, data[i],
            //    (i+byte_pos_index)>> 3, tNDEF_data_info_array[array_index].NDEF_data_bitmap[(i+byte_pos_index)>> 3], (1 << ((i+byte_pos_index)%8)));
            
            //if the byte has not be saved before, save it, 
            //the bit in NDEF_data_bitmap is NDEF_data_bitmap[(i+byte_position)/8] & (1 << ((i+byte_position)%8)) )
            if ((tNDEF_data_info_array[array_index].NDEF_data_bitmap[(i+byte_pos_index)>> 3] & (1 << ((i+byte_pos_index)%8))) == 0)
            {
                //fprintf (w_fp, "\n\t\t\t\t position = %d data= 0x%X\n\n",i+byte_pos_index, data[i]);
                
                //save the byte to NDEF_data
                tNDEF_data_info_array[array_index].NDEF_data[i+byte_pos_index] = data[i];
                //set the bitmap bit
                tNDEF_data_info_array[array_index].NDEF_data_bitmap[(i+byte_pos_index)>> 3] |= (1 << ((i+byte_pos_index)%8));
                //increase the saved_byte_num
                tNDEF_data_info_array[array_index].saved_byte_num++;
                if (tNDEF_data_info_array[array_index].saved_byte_num == tNDEF_data_info_array[array_index].NDEF_data_len)
                {
                    //fprintf (w_fp, "\t\t\t analyze NDEF info!\n");
                    analyze_NFC_NDEF(tNDEF_data_info_array[array_index].NDEF_data, tNDEF_data_info_array[array_index].NDEF_data_len);
                }
            }
        }
    }
    //already save the complete NDEF, just return 
    else
    {
        return;
    }

}


void analyze_NFC_A_T2T(char *time, char *action, uint8_t type, uint8_t *data,int data_length){
    fprintf (w_fp, "%s\t%s\t\t%s\t  data_len is %d, data is %s\n",time,action,getPacketType(type), data_length, print_data(data, data_length));
    //tx cmd, action == "==>"
    if (action[0] == '=')
    {
        //the cmd is not SECTOR SELECT Command Packet 2, then save the cmd
        if (data_length != 4 || last_cmd != T2T_CMD_SEC_SEL || uT2T_wait_sec_SELECT != 1)
        {
            last_cmd = data[0];
        }
        if (T2T_CMD_READ == last_cmd)
        {
            lT2T_read_block_pos = data[1] + (lT2T_SECTOR_NUM << 8);
        }
        else if (T2T_CMD_SEC_SEL == last_cmd)
        {
            //to be continued, SECTOR SELECT Command Packet 2   len == 4,  packet 1 len == 2    //the type 2 tag mem < 1024 (ie block less than 256), so can not test here
            if (2 == data_length && T2T_CMD_SEC_SEL == data[0]) //the cmd is SECTOR SELECT Command Packet 1
            {
                
            }
            else if (4 == data_length)
            {
                //wait for the ACK NACK to update T2T_SECTOR_NUM
            }
            else    //it is an UNDETERMINED cmd, save the cmd
            {
                last_cmd = data[0];
                fprintf (w_fp, "\t UNDETERMINED cmd data_len, data_len is %d, cmd is %s\n", data_length, getNFC_A_T2T_cmd(last_cmd));
            }
            fprintf (w_fp, "\t T2T_CMD_SEC_SEL: %s\n\n", print_data(data, data_length));
        }
    }
    //rx rsp, action == "<=="
    else if (action[0] == '<')
    {
        //need to distinguish READ rsp with ACK and NACK rsp
        if (17 == data_length)  //16 byte + 1 status byte
        {
            if (T2T_CMD_READ == last_cmd)
            {
                //if rsp of read CC block
                if (-1 == lT2T_read_block_pos)
                {
                    fprintf (w_fp, "\t lT2T_read_block_pos has not set, return error!!!\n\n");
                    last_cmd = CMD_UNKNOWN; //the last cmd has been responsed 
                    return;
                }
                //if READ rsp contains CC
                if (checkT2T_byte_in_READ_rsp(T2T_CC_BLOCK_POS, lT2T_read_block_pos))    //need to distinguish ACK and NACK rsp
                {
                    //Byte 0 is equal to E1h (magic number) to indicate that NFC Forum defined data is stored
                    //the block3 byte 0 contains data[0] == mem[4*block_pos], data[x] = mem[12], x= 12 - 4* block_pos
                    //CC0 NMN has NDEF
                    if(0xE1 == data[getT2T_READ_index_from_byte_pos(getT2T_byte_pos_from_block(T2T_CC_BLOCK_POS, 0),lT2T_read_block_pos)])
                    {
                        uT2T_has_NDEF = 1;
                        fprintf (w_fp, "\tuT2T_has_NDEF: %d\n\n",uT2T_has_NDEF);
                    }
                    //Byte 2 indicates the memory size of the data area of the Type 2 Tag Platform,
                    //byte 2 multiplied by 8 is equal to the data area size measured in bytes
                    //byte 2 multiplied by 2 is equal to the block number contains in the Tag
                    //T2T: size of total_mem = data area size + 16 byte (4 block)
                    lT2T_total_block_NUM = ((int)data[getT2T_READ_index_from_byte_pos(getT2T_byte_pos_from_block(T2T_CC_BLOCK_POS, 2),lT2T_read_block_pos)] << 1) +4;
                    fprintf (w_fp, "\tlT2T_total_block_NUM is %d, the size of mem is %d byte", lT2T_total_block_NUM, (lT2T_total_block_NUM<<2));
                    if (lT2T_total_block_NUM == 16)
                    {
                        fprintf (w_fp, "\tstatic mem\n\n");
                    }
                    else if (lT2T_total_block_NUM > 16)
                    {
                        fprintf (w_fp, "\tdynamic mem\n\n");
                    }
                    else
                    {
                        fprintf (w_fp, "\twrong mem!!!\n\n");
                    }
                }
                if (1 == uT2T_has_NDEF && lT2T_read_block_pos >0)    //T2T has NDEF && READ contain TLV
                {
                    //analyze TLV
                    //check if the len of TLV contains in the READ rsp
                    if (checkT2T_byte_in_READ_rsp(lT2T_possible_NDEF_TLV_type_byte_pos+1, lT2T_read_block_pos))
                    {
                        //if it is the len of last TLV, save it
                        map<int, int>::iterator iter;
                        iter = tTLV_pos_data_map.find(lT2T_possible_NDEF_TLV_type_byte_pos);
                        if (iter != tTLV_pos_data_map.end() && tTLV_info_array[iter->second].TLV_len == 0)
                        {
                            tTLV_info_array[lAvailable_TLV_array_index].TLV_len = data[getT2T_READ_index_from_byte_pos(lT2T_possible_NDEF_TLV_type_byte_pos+1, lT2T_read_block_pos)];
                            lT2T_possible_NDEF_TLV_type_byte_pos += 2 + tTLV_info_array[lAvailable_TLV_array_index].TLV_len;
                            //check if it is NDEF TLV, yes, save it to tNDEF_data_info_array
                            if (0x03 == tTLV_info_array[lAvailable_TLV_array_index].TLV_type)
                            {
                                if (lAvailable_NDEF_array_index < MAX_NUM_NDEF_SAVED)
                                {
                                    tNDEF_data_info_array[lAvailable_NDEF_array_index].NDEF_data_len = tTLV_info_array[lAvailable_TLV_array_index].TLV_len;
                                    tNDEF_data_info_array[lAvailable_NDEF_array_index].NDEF_TLV_start_pos = tTLV_info_array[lAvailable_TLV_array_index].TLV_start_pos;
                                    //check if data exist, yes -> save the data
                                    if (checkT2T_byte_in_READ_rsp(lT2T_possible_NDEF_TLV_type_byte_pos+2, lT2T_read_block_pos))
                                    {
                                        save_T2T_NFC_NDEF(&data[getT2T_READ_index_from_byte_pos(lT2T_possible_NDEF_TLV_type_byte_pos+2, lT2T_read_block_pos)],
                                            min((int)tNDEF_data_info_array[lAvailable_NDEF_array_index].NDEF_data_len, 16-getT2T_READ_index_from_byte_pos(lT2T_possible_NDEF_TLV_type_byte_pos+2, lT2T_read_block_pos)),
                                            lT2T_possible_NDEF_TLV_type_byte_pos+2,
                                            lAvailable_NDEF_array_index);
                                    }
                                }
                                lAvailable_NDEF_array_index++;
                            }
                        }
                        
                    }
                    while (checkT2T_byte_in_READ_rsp(lT2T_possible_NDEF_TLV_type_byte_pos, lT2T_read_block_pos))
                    {
                        //fprintf (w_fp, "\t\t\t test     lT2T_possible_NDEF_TLV_type_byte_pos is %d, lT2T_read_block_pos is %d\n",
                        //    lT2T_possible_NDEF_TLV_type_byte_pos, lT2T_read_block_pos);
                        map<int, int>::iterator iter;
                        iter = tTLV_pos_data_map.find(lT2T_possible_NDEF_TLV_type_byte_pos);
                        //if the TLV not be saved before, save it
                        if (iter == tTLV_pos_data_map.end())
                        {
                            //save this TLV
                            if (lAvailable_TLV_array_index < MAX_NUM_TLV_SAVED)
                            {
                                tTLV_info_array[lAvailable_TLV_array_index].TLV_start_pos = lT2T_possible_NDEF_TLV_type_byte_pos;
                                tTLV_info_array[lAvailable_TLV_array_index].TLV_type = data[getT2T_READ_index_from_byte_pos(lT2T_possible_NDEF_TLV_type_byte_pos, lT2T_read_block_pos)];
                                tTLV_pos_data_map.insert(pair<int, int>(lT2T_possible_NDEF_TLV_type_byte_pos, lAvailable_TLV_array_index));
                                if (checkT2T_byte_in_READ_rsp(lT2T_possible_NDEF_TLV_type_byte_pos+1, lT2T_read_block_pos))
                                {
                                    //save the TLV len
                                    tTLV_info_array[lAvailable_TLV_array_index].TLV_len = data[getT2T_READ_index_from_byte_pos(lT2T_possible_NDEF_TLV_type_byte_pos+1, lT2T_read_block_pos)];
                                    //check if it is NDEF TLV, yes, save it to tNDEF_data_info_array
                                    if (0x03 == tTLV_info_array[lAvailable_TLV_array_index].TLV_type)
                                    {
                                        if (lAvailable_NDEF_array_index < MAX_NUM_NDEF_SAVED)
                                        {
                                            tNDEF_data_info_array[lAvailable_NDEF_array_index].NDEF_data_len = tTLV_info_array[lAvailable_TLV_array_index].TLV_len;
                                            tNDEF_data_info_array[lAvailable_NDEF_array_index].NDEF_TLV_start_pos = tTLV_info_array[lAvailable_TLV_array_index].TLV_start_pos;
                                            //check if data exist, yes -> save the data
                                            if (checkT2T_byte_in_READ_rsp(lT2T_possible_NDEF_TLV_type_byte_pos+2, lT2T_read_block_pos))
                                            {
                                                save_T2T_NFC_NDEF(&data[getT2T_READ_index_from_byte_pos(lT2T_possible_NDEF_TLV_type_byte_pos+2, lT2T_read_block_pos)],
                                                    min((int)tNDEF_data_info_array[lAvailable_NDEF_array_index].NDEF_data_len, 16-getT2T_READ_index_from_byte_pos(lT2T_possible_NDEF_TLV_type_byte_pos+2, lT2T_read_block_pos)),
                                                    lT2T_possible_NDEF_TLV_type_byte_pos+2,
                                                    lAvailable_NDEF_array_index);
                                            }
                                        }
                                        lAvailable_NDEF_array_index++;
                                    }
                                    lT2T_possible_NDEF_TLV_type_byte_pos = 2 + tTLV_info_array[lAvailable_TLV_array_index].TLV_len + lT2T_possible_NDEF_TLV_type_byte_pos;
                                    lAvailable_TLV_array_index++;
                                }
                                else
                                {
                                    lAvailable_TLV_array_index++;
                                    break;
                                }
                            }
                            else
                            {
                                fprintf (w_fp, "\ttTLV_info_array is full and can not save more!!!\n");
                            }
                        }
                    }
                    //deal with data contains only NDEF data without NDEF TLV type and len
                    //check if the max {data[0], pos 16} is belong to NDEF data
                    int pos_of_fisrt_data = max(16, getT2T_byte_pos_from_block(lT2T_read_block_pos, 0));
                    for (int i = 0; i <lAvailable_NDEF_array_index; i++)
                    {
                        //i < lAvailable_NDEF_array_index ensure tNDEF_data_info_array[i].NDEF_TLV_start_pos != -1
                        if (tNDEF_data_info_array[i].NDEF_data_len != 0
                            && (tNDEF_data_info_array[i].NDEF_TLV_start_pos + 2) <= pos_of_fisrt_data
                            && pos_of_fisrt_data < (tNDEF_data_info_array[i].NDEF_TLV_start_pos + 2 + tNDEF_data_info_array[i].NDEF_data_len))
                        {
                            save_T2T_NFC_NDEF(&data[getT2T_READ_index_from_byte_pos(pos_of_fisrt_data, lT2T_read_block_pos)],
                                min((int)tNDEF_data_info_array[i].NDEF_data_len +tNDEF_data_info_array[i].NDEF_TLV_start_pos+2-pos_of_fisrt_data, 16-getT2T_READ_index_from_byte_pos(pos_of_fisrt_data, lT2T_read_block_pos)),
                                pos_of_fisrt_data,
                                i);
                            break;
                        }
                    }
                    //fail to find NDEF data corresponding index, just do nothing
                }
                fprintf (w_fp, "\tT2T_CMD_READ rsp\n");
            }
            else
            {
                fprintf (w_fp, "\tUNDETERMINED rsp, data_len is %d, cmd is %s data is %s\n", data_length, getNFC_A_T2T_cmd(last_cmd), print_data(data, data_length));
            }
            last_cmd = CMD_UNKNOWN; //the last cmd has been responsed 
        }
        else if (2 == data_length)  // 16byte + 1 status byte  ACK and NACK rsp
        {
            //NACK + T2T_CMD_SEC_SEL -> update T2T_CMD_SEC_SEL params -> SECTOR SELECT Command Packet 2
            //do not set last_cmd to CMD_UNKNOWN; //the last cmd has not been responsed  
            //uT2T_wait_sec_SELECT = 1;

            //default
            last_cmd = CMD_UNKNOWN; //the last cmd has been responsed 
        }
        else
        {
            fprintf (w_fp, "\tUNDETERMINED rsp data_len, data_len is %d, cmd is %s data is %s\n", data_length, getNFC_A_T2T_cmd(last_cmd), print_data(data, data_length));
            last_cmd = CMD_UNKNOWN; //the last cmd has been responsed 
        }
    }


    //...to be continued juns
}

//save T3T NDEF block into tNDEF_data_info_array[0], block_position is the block num in NDEF service code
//the size of data[] is 16
void save_T3T_NFC_NDEF(uint8_t *data, int block_position)
{
    if(block_position < 0)
    {
        fprintf (w_fp, "\n\t wrong block_position: %d in save_T3T_NFC_NDEF!!!\n\n", block_position);
        return;
    }

    //the control block
    if (0 == block_position && 0 == tNDEF_data_info_array[0].NDEF_data_len)
    {
        //byte 11 to Byte 13 SHALL be Ln, which is the actual size of the stored NDEF data in bytes.
        //Byte 11 SHALL be the upper byte, Byte 12 SHALL be the middle byte, and Byte 13 SHALL be the lower byte.
        //The number of blocks containing NDEF data (Nbc) can be calculated by the formula Nbc=ceil(Ln/16).
        tNDEF_data_info_array[0].NDEF_data_len = (data[11]<<8) + (data[12]<<4) + data[13];
        fprintf (w_fp, "\n\tNDEF_data_len: %d \n\n", tNDEF_data_info_array[0].NDEF_data_len);
    }
    //save the NDEF data block
    else
    {
        if (tNDEF_data_info_array[0].NDEF_data_len > 0
            && tNDEF_data_info_array[0].saved_byte_num < tNDEF_data_info_array[0].NDEF_data_len)
        {
            //fprintf (w_fp, "\t\tsave_T3T_NFC_NDEF, block_position: %d, data is %s\n", block_position, print_data(data, min(16, tNDEF_data_info_array[0].NDEF_data_len - ((block_position-1) << 4))));
            if(0 == tNDEF_data_info_array[0].NDEF_data_bitmap[(block_position - 1)<<1])
            {
                //save the data min (16, tNDEF_data_info_array[0].NDEF_data_len - (block_position << 4)), & update NDEF_data_bitmap
                memcpy(&tNDEF_data_info_array[0].NDEF_data[(block_position - 1)<<4], data,
                    min(16, tNDEF_data_info_array[0].NDEF_data_len - ((block_position-1) << 4)));
                for (int i = 0; i<2; i++)
                {
                    tNDEF_data_info_array[0].NDEF_data_bitmap[block_position-1+i] = ((uint8_t)0xFF) << (8-(min(8, tNDEF_data_info_array[0].NDEF_data_len - ((block_position-1) << 4)- (i<<3))));
                }
                tNDEF_data_info_array[0].saved_byte_num = tNDEF_data_info_array[0].saved_byte_num + min(16, tNDEF_data_info_array[0].NDEF_data_len - ((block_position-1) << 4));
                //fprintf (w_fp, "\njunsheng_NFC saved_byte_num is %d !\n\n", tNDEF_data_info_array[0].saved_byte_num);

                if(tNDEF_data_info_array[0].saved_byte_num == tNDEF_data_info_array[0].NDEF_data_len)
                {
                    //analyze the NDEF data
                    //fprintf (w_fp, "\nanalyze_NFC_NDEF!\n\n");
                    analyze_NFC_NDEF(tNDEF_data_info_array[0].NDEF_data, tNDEF_data_info_array[0].NDEF_data_len);
                }
            }
        }
    }
}


void analyze_NFC_F_T3T(char *time, char *action, uint8_t type, uint8_t *data, int data_length){
    static tT3T_NDEF_Blocks NDEF_blocks = {0, {{0,0}}};
    fprintf (w_fp, "%s\t%s\t\t%s\t analyze_NFC_F_T3T data_len is %d, data is %s\n",time,action,getPacketType(type), data_length, print_data(data, data_length));
    //tx cmd, action == "==>"
    if (action[0] == '=')
    {
        //clear NDEF_block_pos_vec
        NDEF_blocks.size = 0;
        
        //data[0] is len, data[1] is cmd
        if (T3T_MSG_OPC_CHECK_CMD == data[1])
        {
            //if NDEF system code is selected, check if exist NDEF service 
            if (1 == iT3T_POLLING_CMD_NDEF_selected)
            {

                int NDEF_svc_pos = -1;
                int NDEF_svc_write_pos = -1;
                
                fprintf (w_fp, "\t size of Service Code List: %d\n\n", data[10]);
                //traverse Service Code List to check the exist of T3T_SYSTEM_CODE_NDEF,
                //the Service num contains in list is data[10]
                for (int i = 0; i < data[10]; i++)
                {
                    if (T3T_SERVICE_CODE_NDEF == (((int)data[12 + 2*i]<<8) + data[11 + 2*i]))
                    {
                        NDEF_svc_pos = i;
                        fprintf (w_fp, "\t the NDEF service pos is: %d\n\n", NDEF_svc_pos);
                    }
                    else if (T3T_SERVICE_CODE_NDEF_WRITE == (((int)data[12 + 2*i]<<8) + data[11 + 2*i]))
                    {
                        NDEF_svc_write_pos = i;
                    }
                }
                //the service code list contains NDEF service, save the pos of NDEF blocks in Block list
                if (-1 != NDEF_svc_pos || -1 != NDEF_svc_write_pos)
                {
                    //Number of Blocks = data[11+ 2*data[10]]
                    for (int i = 0, cur_block_pos = 12+2*data[10]; i < data[11 + 2*data[10]]; i++)
                    {
                        int len_of_block_number = (data[cur_block_pos]>>7)? 2:3;
                        if(NDEF_svc_pos == (data[cur_block_pos] & 0xF) || NDEF_svc_write_pos == (data[cur_block_pos] & 0xF))
                        {
                            //save the block number
                            int block_number;
                            if (len_of_block_number == 3)
                            {
                                block_number = ((int)data[cur_block_pos+2]<<8) + data[cur_block_pos+1];
                            }
                            else
                            {
                                block_number = data[cur_block_pos + 1];
                            }
                            NDEF_blocks.blocks_info_array[NDEF_blocks.size].block_number = block_number;
                            NDEF_blocks.blocks_info_array[NDEF_blocks.size].block_pos = i;
                            //fprintf (w_fp, "\t the NDEF block[%d] pos is: %d, block number is %d\n\n",
                            //    NDEF_blocks.size, i, block_number);
                            NDEF_blocks.size++;
                        }
                        cur_block_pos += len_of_block_number;
                    }
                }
            }

        }

    }
    //rx rsp, action == "<=="
    else if (action[0] == '<')
    {
        //data[0] is len, data[1] is cmd
        if (T3T_MSG_OPC_CHECK_RSP == data[1])
        {
            //if Status Flag1 data[10]== 0, && Status Flag2 data[11]== 0, && has NDEF block
            if (0 == data[10] && 0 == data[11] && NDEF_blocks.size != 0)
            {
                //save NDEF block into tNDEF_data_info_array[0]
                for (int i = 0; i < NDEF_blocks.size; i++)
                {
                    save_T3T_NFC_NDEF(&data[13 + (NDEF_blocks.blocks_info_array[i].block_pos<<4)], 
                        NDEF_blocks.blocks_info_array[i].block_number);
                }
            }
        }
        NDEF_blocks.size = 0;
    }

}


void analyzeData(char *time, char *action, uint8_t type, uint8_t *data, long data_length){
	data+=3; 
	data_length-=3;

    /*
	if( selected == NCI_PROTOCOL_ISO_DEP ){	//PROTOCOL_ISO_DEP
		analyze_ISO_DEP(time, action, type, data, data_length);
	}else if( selected == NCI_PROTOCOL_NFC_DEP ){ //PROTOCOL_NFC_DEP
		analyze_NFC_DEP(time, action, type, data, data_length);
	}else if( selected == NCI_PROTOCOL_MIFARE_CLASSIC ){ //MIFARE_CLASSIC
		analyze_MIFARE_CLASSIC(time, action, type, data, data_length);
	}
	else
		fprintf (w_fp, "%s\t%s\t\t%s\n",time,action,getPacketType(type));
    */

    switch (selected)
    {
        //PROTOCOL_ISO_DEP
        case NCI_PROTOCOL_ISO_DEP:
            analyze_ISO_DEP(time, action, type, data, data_length);
            break;
        //PROTOCOL_NFC_DEP
        case NCI_PROTOCOL_NFC_DEP:
            analyze_NFC_DEP(time, action, type, data, data_length);
            break;
        //MIFARE_CLASSIC
        case NCI_PROTOCOL_MIFARE_CLASSIC:
            analyze_MIFARE_CLASSIC(time, action, type, data, data_length);
            break;
        //type 1 tag
        case NCI_PROTOCOL_T1T:
            analyze_NFC_A_T1T(time, action, type, data, data_length);
            break;
        //type 2 tag
        case NCI_PROTOCOL_T2T:
            analyze_NFC_A_T2T(time, action, type, data, data_length);
            break;
        //type 3 tag
        case NCI_PROTOCOL_T3T:
            analyze_NFC_F_T3T(time, action, type, data, data_length);
            break;
        default:
            fprintf (w_fp, "%s\t%s\t\t%s\n", time, action, getPacketType(type));

    }
}

void initialize_protocal_global_params(int selected)
{
    last_cmd = CMD_UNKNOWN;
    last_status = RSP_UNKNOWN;

    //initialize the tNDEF_data_info_array
    for (int i = 0; i < MAX_NUM_NDEF_SAVED; i++)
    {
        tNDEF_data_info_array[i].NDEF_TLV_start_pos = -1;
        memset(tNDEF_data_info_array[i].NDEF_data, 0, sizeof(tNDEF_data_info_array[i].NDEF_data));
        tNDEF_data_info_array[i].NDEF_data_len = 0;
        tNDEF_data_info_array[i].saved_byte_num = 0;
        //initialize the NDEF_data_bitmap
        memset(tNDEF_data_info_array[i].NDEF_data_bitmap, 0, sizeof(tNDEF_data_info_array[i].NDEF_data_bitmap));
    }
    //initialize the index of unused NDEF data in tNDEF_data_info_array
    lAvailable_NDEF_array_index = 0;


    //initialize TLV info array
    for (int i = 0; i < MAX_NUM_TLV_SAVED; i++)
    {
        tTLV_info_array[i].TLV_len = 0;
        tTLV_info_array[i].TLV_start_pos = -1;
    }

    //the index of unused TLV data in tTLV_info_array
    lAvailable_TLV_array_index = 0;
    //initialize the map save <TLV byte pos, index of TLV icfo in tTLV_info_array>
    tTLV_pos_data_map.clear();

    switch (selected)
    {
        //PROTOCOL_ISO_DEP
        case NCI_PROTOCOL_ISO_DEP:
            //T4T NDEF AID selected
            iT4T_AID_SELECTED = T4T_SEL_CONTENT_DEFAULT;
            //T4T NDEF CC selected
            iT4T_FILE_SELECTED = T4T_SEL_CONTENT_DEFAULT;
            //the map save T4T NDEF TLV's file ID <byte pos in ID, content of ID>
            tT4T_NDEF_TLV_info_map.clear();
            //the map save T4T NDEF TLV's len <byte[0] in NDEF file, byte[1] in NDEF file>
            tT4T_NDEF_TLV_len_map.clear();
            break;
        //PROTOCOL_NFC_DEP
        case NCI_PROTOCOL_NFC_DEP:
            iNFC_DEP_SNEP_Connected = 0;
            //to be continued juns...
            break;
        //MIFARE_CLASSIC
        case NCI_PROTOCOL_MIFARE_CLASSIC:
            //to be continued juns...
            break;
        //type 1 tag
        case NCI_PROTOCOL_T1T:
            //if T1T supported NDEF
            uT1T_NDEF_supported = 0;
            //if T1T has NDEF
            uT1T_has_NDEF = 0;
            //the len of T1T NDEF
            uT1T_NDEF_len = 0;
            //if T1T is dynamic mem map
            uT1T_dynamic_mem = 0;

        //type 2 tag
        case NCI_PROTOCOL_T2T:
            //the position of T2T READ cmd
            lT2T_read_block_pos = -1;
            //the possible position of T2T NDEF TLV type byte pos is 16
            lT2T_possible_NDEF_TLV_type_byte_pos = 16;
            //the sector number of T2T READ cmd
            lT2T_SECTOR_NUM = 0;
            //T2T if wait the SECTOR SELECT Command Packet 2
            uT2T_wait_sec_SELECT = 0;//to be continued juns...
            //if T2T has NDEF
            uT2T_has_NDEF = 0;
            //the totoal sector number of T2T
            lT2T_total_block_NUM = 0;
            //to be continued juns...
            break;
        //type 3 tag
        case NCI_PROTOCOL_T3T:
            //T3T POLLING CMD send with system code NDEF (T3T_SYSTEM_CODE_NDEF 0x12FC)
            iT3T_POLLING_CMD_NDEF_send = 0;
            //T3T POLLING rsp with system code NDEF received
            iT3T_POLLING_RSP_NDEF_rcvd = 0;
            //T3T POLLING select NDEF system code
            iT3T_POLLING_CMD_NDEF_selected = 0;
            break;
        default:
            //to be continued juns...
            break;

    }

}


void printControlOpration(char *time, char *action, uint8_t type, uint8_t *data,long data_length){
	char ctrlcommand[128];
	char parameter[4096];
	memset(ctrlcommand, 0, sizeof(ctrlcommand));
	memset(parameter, 0, sizeof(parameter));
	uint8_t gid = data[0]&0x0f;
	uint8_t oid = data[1]&0x3F;	
	if(gid == NCI_GID_CORE){
		switch (oid){
			case NCI_MSG_CORE_RESET :
				strcpy(ctrlcommand,"RESET");
				if(type == NCI_MT_CMD){
					if(data[3]==0x01)
						strcpy(parameter,"Reset Configuration");
					else if(data[3]==0x00)
						strcpy(parameter,"Keep Configuration");	
				}			
				break;
			case NCI_MSG_CORE_INIT :
				strcpy(ctrlcommand,"INIT");
				break;
			case NCI_MSG_CORE_SET_CONFIG :
				strcpy(ctrlcommand,"SET_CONFIG");
				break;
			case NCI_MSG_CORE_GET_CONFIG :
				strcpy(ctrlcommand,"GET_CONFIG");
				break;
			case NCI_MSG_CORE_CONN_CREATE :
				strcpy(ctrlcommand,"CONN_CREATE");
				break;
			case NCI_MSG_CORE_CONN_CLOSE :
				strcpy(ctrlcommand,"CONN_CLOSE");
				break;
			case NCI_MSG_CORE_CONN_CREDITS :
				strcpy(ctrlcommand,"CONN_CREDITS");
				break;
			case NCI_MSG_CORE_GEN_ERR_STATUS :
				strcpy(ctrlcommand,"GEN_ERR_STATUS");
				sprintf(parameter,"%s",getStatusCodes(data[3]));
				break;
			case NCI_MSG_CORE_INTF_ERR_STATUS :
				strcpy(ctrlcommand,"INTF_ERR_STATUS");
				sprintf(parameter,"%s",getStatusCodes(data[3]));
				break;
			case NCI_MSG_CORE_SET_POWER_SUB_STATE :
				strcpy(ctrlcommand,"SET_POWER_SUB_STATE");
				break;				
			default :
				strcpy(ctrlcommand,"UNKNOWN");
				break;
		}	
	}else if(gid == NCI_GID_RF_MANAGE){
		switch (oid){
			case NCI_MSG_RF_DISCOVER_MAP :
				strcpy(ctrlcommand,"DISCOVER_MAP");
				break;			
			case NCI_MSG_RF_SET_ROUTING :
				strcpy(ctrlcommand,"SET_ROUTING");
				if( type == NCI_MT_CMD ){
					int Entries_Number = data[4];
					uint8_t *p = &data[5];
					for(int i=0;i<Entries_Number;i++){
						char entry_type[100];
						char entry_parameter[50];
						char power_state[100] = "Switched_on";

						memset(entry_parameter,0,sizeof(entry_parameter));
						memset(entry_type,0,sizeof(entry_type));
						uint8_t entry_length=*(p+1);
						if(*p == 0x00){	//Technology-based routing entry
							strcpy(entry_type,"Techo");
							if(*(p+4) == 0x00 )
								strcpy(entry_parameter,"NFC_RF_TECHNOLOGY_A");
							else if(*(p+4) == 0x01)
								strcpy(entry_parameter,"NFC_RF_TECHNOLOGY_B");
							else if(*(p+4) == 0x02 )
								strcpy(entry_parameter,"NFC_RF_TECHNOLOGY_F");
							else if(*(p+4) == 0x03 )
								strcpy(entry_parameter,"NFC_RF_TECHNOLOGY_15693");
							else if(*(p+4)>=0x80 && *(p+4)<=0xFE)
								strcpy(entry_parameter,"For_proprietary_use");
							else
								strcpy(entry_parameter,"UNKNOWN");
						}else if(*p == 0x01){	//Protocol-based routing entry
							strcpy(entry_type,"Proto");

							strcpy(entry_parameter,getRFProtocol(*(p+4)));					
						}else if( *p == 0x02 ){		//AID-based routing entry
							strcpy(entry_type,"AID");
							strcpy(entry_parameter,"AID: ");
							for(int i=0;i< (entry_length-2);i++)
								snprintf(&entry_parameter[i * 2+5], 3, "%02X", *(p+4+i));
						}

						if(*(p+3)&0x01 != 0x01)
							memset(power_state, 0, sizeof(power_state));
						else{
							if(*(p+3)&0x02)
								strcat(power_state, "|Switched_off");
							if(*(p+3)&0x40)
								strcat(power_state, "|Screen_locked");
							if(*(p+3)&0x80)
								strcat(power_state, "|Screen_off");							
						}
						sprintf(parameter,"%s\n\t\t%s\t\tRoute:%02X\tPower:%02X ( %s )\t\t%s",
								parameter,entry_type,*(p+2),*(p+3), power_state, entry_parameter);
						p = p+2+entry_length;
					}
				}
				break;			
			case NCI_MSG_RF_GET_ROUTING :
				strcpy(ctrlcommand,"GET_ROUTING");
				break;			
			case NCI_MSG_RF_DISCOVER :
				strcpy(ctrlcommand,"RF_DISCOVER");
				if( type == NCI_MT_CMD ){
					int configNum = *(data+3);
					for(int i=0 ;i<configNum;i++){
						sprintf(parameter,"%s\t%s",parameter,getRFTecoAndMode(*(data+4+2*i)));				
					}
				}else if(type == NCI_MT_NTF){
					sprintf(parameter,"Dis_ID:%d , Proto: %s , Techo:%s",*(data+3), getRFProtocol(*(data+4)),
						getRFTecoAndMode(*(data+5)));			
				}
				break;			
			case NCI_MSG_RF_DISCOVER_SELECT :
				strcpy(ctrlcommand,"DISCOVER_SELECT");
				if( type == NCI_MT_CMD ){
					sprintf(parameter,"Dis_ID:%d , Intf: %s , Proto: %s",*(data+3),getRFInterface(*(data+5)),
						getRFProtocol(*(data+4)));	
				}
				break;			
			case NCI_MSG_RF_INTF_ACTIVATED :
				strcpy(ctrlcommand,"INTF_ACTIVATED");			
				sprintf(parameter,"Dis_ID:%d , Intf: %s , Proto: %s , Techo:%s",*(data+3),getRFInterface(*(data+4)),
						getRFProtocol(*(data+5)), getRFTecoAndMode(*(data+6)));
				selected = *(data+5);
                //initialize global params according to protocal selected
                initialize_protocal_global_params(selected);
				break;			
			case NCI_MSG_RF_DEACTIVATE :
				strcpy(ctrlcommand,"DEACTIVATE");
				selected = -1;
                //add for support anaylze data packet
                last_cmd = CMD_UNKNOWN;
                initialize_protocal_global_params(selected);
				break;			
			case NCI_MSG_RF_FIELD :
				strcpy(ctrlcommand,"FILD");
				if(data[3]&0x01)
					strcpy(parameter,"detected_field");
				else
					strcpy(parameter,"no_field");	
				break;			
			case NCI_MSG_RF_T3T_POLLING :
				strcpy(ctrlcommand,"T3T_POLLING");
				if( type == NCI_MT_CMD ){
					sprintf(parameter,"%s\t T3T_POLLING cmd data is %s",parameter, print_data(data, data_length));
                    if (data[3] == 0x12 && data[4] == 0xFC)
                    {
                        //T3T POLLING CMD send with system code NDEF (T3T_SYSTEM_CODE_NDEF 0x12FC)
                        iT3T_POLLING_CMD_NDEF_send = 1;
                    }
                    else
                    {
                        iT3T_POLLING_CMD_NDEF_send = 0;
                    }
				}else if(type == NCI_MT_NTF){

					sprintf(parameter,"%s\t T3T_POLLING NTF data is %s",parameter, print_data(data, data_length));
                    if (1 == iT3T_POLLING_CMD_NDEF_send && data[3] == 0 && 1 == iT3T_POLLING_RSP_NDEF_rcvd)
                    {
                        //NDEF system code is selected
                        iT3T_POLLING_CMD_NDEF_selected = 1;
                    }
                    else
                    {
                        iT3T_POLLING_CMD_NDEF_selected = 0;
                    }
                    sprintf(parameter,"%s\n\t\t\t\t\t\t\t\t\t\t\t T3T_POLLING NTF iT3T_POLLING_CMD_NDEF_selected is %d",parameter,
                        iT3T_POLLING_CMD_NDEF_selected);
				}
                else if (type == NCI_MT_RSP)
                {
                    sprintf(parameter,"%s\t T3T_POLLING RSP data is %s",parameter, print_data(data, data_length));
                    //cmd is NDEF && status is ok
                    if (1 == iT3T_POLLING_CMD_NDEF_send && data[3] == 0)
                    {
				        //T3T POLLING rsp with system code NDEF received
                        iT3T_POLLING_RSP_NDEF_rcvd = 1;
                    }
                    else
                    {
                        iT3T_POLLING_RSP_NDEF_rcvd = 0;
                    }
                }
				break;			
			case NCI_MSG_RF_EE_ACTION :
				strcpy(ctrlcommand,"EE_ACTION");
				break;			
			case NCI_MSG_RF_EE_DISCOVERY_REQ :
				strcpy(ctrlcommand,"EE_DISCOVERY_REQ");
				break;			
			case NCI_MSG_RF_PARAMETER_UPDATE :
				strcpy(ctrlcommand,"PARAMETER_UPDATE");
				break;			
			case NCI_MSG_RF_ISO_DEP_NAK_PRESENCE :
				strcpy(ctrlcommand,"ISO_DEP_NAK_PRESENCE");
				break;
			default :
				strcpy(ctrlcommand,"UNKNOWN");				
		}
	}else if(gid == NCI_GID_EE_MANAGE){
		switch (oid){		
			case NCI_MSG_NFCEE_DISCOVER :
				strcpy(ctrlcommand,"NFCEE_DISCOVER");
				break;	
			case NCI_MSG_NFCEE_MODE_SET :
				strcpy(ctrlcommand,"NFCEE_MODE_SET");
				break;	
			case NCI_MSG_NFCEE_STATUS   :
				strcpy(ctrlcommand,"NFCEE_STATUS");
				break;	
			case NCI_MSG_NFCEE_PWR_LNK_CTRL :
				strcpy(ctrlcommand,"NFCEE_PWR_LNK_CTRL");
				break;	
			case NCI_MSG_NFCEE_POWER_LINK_CTRL :
				strcpy(ctrlcommand,"NFCEE_POWER_LINK_CTRL");
				break;	
			default :
				strcpy(ctrlcommand,"UNKNOWN");
		}
	}else if(gid == NCI_GID_PROP){
	//add from PN553 user manual  +++
		switch (oid){	
			case VENDOR_SET_SET_POWER_MODE :
				strcpy(ctrlcommand,"VENDOR_SET_SET_POWER_MODE");
				if(type == NCI_MT_CMD){
					if(data[3]==0x00)
						strcpy(parameter,"Standby Mode disabled");
					else if(data[3]==0x01)
						strcpy(parameter,"Standby Mode enabled");
					else if(data[3]==0x02 || data[3]==0x03)
						strcpy(parameter,"Autonomous mode enabled");	
				}
				break;		
			case VENDOR_SET_SCREEN_STATE :
				strcpy(ctrlcommand,"VENDOR_SET_SCREEN_STATE");
				if(type == NCI_MT_CMD){
					if(data[3]==0x00)
						strcpy(parameter,"Screen_On");
					else if(data[3]==0x01)
						strcpy(parameter,"Screen_Off");
					else if(data[3]==0x02)
						strcpy(parameter,"Screen_Locked");	
				}
				break;	
			default :
				strcpy(ctrlcommand,"VENDOR_CMD");
		}
	//add from PN553 user manual  ---
	}else{
		strcpy(ctrlcommand,"UNKNOWN");	
	}
	if(strlen(parameter) == 0)
		fprintf (w_fp, "%s\t%s\t\t%s\t\t%s\n",time,action,getPacketType(type),ctrlcommand);
	else
		fprintf (w_fp, "%s\t%s\t\t%s\t\t%s\t\t%s\n",time,action,getPacketType(type),ctrlcommand,parameter);
	
}

char * getPacketType(uint8_t type){
	static char data_type[12];
	memset(data_type, 0, sizeof(data_type));
	if( type == NCI_MT_DATA ){
		strncpy(data_type, "DATA", strlen("DATA"));
	}
	else if( type == NCI_MT_CMD ){
		strncpy(data_type, "CMD", strlen("CMD"));
	}
	else if( type == NCI_MT_RSP ){
		strncpy(data_type, "RSP", strlen("RSP"));
	}
	else if( type == NCI_MT_NTF ){
		strncpy(data_type, "NTF", strlen("NTF"));
	}else
		strncpy(data_type, "", strlen(""));
	return data_type;
}

char * getStatusCodes(uint8_t code){
	static char status[50];
	memset(status, 0, sizeof(status));
	if( code == 0x00 ){
		sprintf(status, "STATUS_OK");
	}else if( code == 0x01 ){
		sprintf(status, "STATUS_REJECTED");
	}else if( code == 0x02 ){
		sprintf(status, "STATUS_RF_FRAME_CORRUPTED");
	}else if( code == 0x03 ){
		sprintf(status, "STATUS_FAILED");
	}else if( code == 0x04 ){
		sprintf(status, "STATUS_NOT_INITIALIZED");
	}else if( code == 0x05 ){
		sprintf(status, "STATUS_SYNTAX_ERROR");
	}else if( code == 0x06 ){
		sprintf(status, "STATUS_SEMANTIC_ERROR");
	}else if( code == 0x09 ){
		sprintf(status, "STATUS_INVALID_PARAM");
	}else if( code == 0x0A ){
		sprintf(status, "STATUS_MESSAGE_SIZE_EXCEEDED");
	}else if( code == 0xA0 ){
		sprintf(status, "DISCOVERY_ALREADY_STARTED");
	}else if( code == 0xA1 ){
		sprintf(status, "DISCOVERY_TARGET_ACTIVATION_FAILED");
	}else if( code == 0xA2 ){
		sprintf(status, "DISCOVERY_TEAR_DOWN");
	}else if( code == 0xB0 ){
		sprintf(status, "RF_TRANSMISSION_ERROR");
	}else if( code == 0xB1 ){
		sprintf(status, "RF_PROTOCOL_ERROR");
	}else if( code == 0xB2 ){
		sprintf(status, "RF_TIMEOUT_ERROR");
	}else if( code == 0xC0 ){
		sprintf(status, "NFCEE_INTERFACE_ACTIVATION_FAILED");
	}else if( code == 0xC1 ){
		sprintf(status, "NFCEE_TRANSMISSION_ERROR");
	}else if( code == 0xC2 ){
		sprintf(status, "NFCEE_PROTOCOL_ERROR");
	}else if( code == 0xC3 ){
		sprintf(status, "NFCEE_TIMEOUT_ERROR");
	//add from PN553 user manual  +++
	}else if( code == 0xE1 ){
		sprintf(status, "STATUS_BOOT_TRIM_CORRUPTED");
	}else if( code == 0xE4 ){
		sprintf(status, "STATUS_EMVCO_PCD_COLLISION");
	}else if( code == 0xE5 ){
		sprintf(status, "PH_NCI_STATUS_WIRED_SESSION_ABORTED");
	}else if( code == 0xE6 ){
		sprintf(status, "PH_NCI_STATUS_WIRED_SESSION_ABORT_DUE_TO_TIMEOUT");
	//add from PN553 user manual  ---
	}else if( code>=0xE0 && code<=0XFF ){
		sprintf(status, "For proprietary use");
	}else
		sprintf(status, "UNKNOWN");
	return status;
}

char * getRFInterface(uint8_t intf){
	static char RF_inf[24];
	memset(RF_inf, 0, sizeof(RF_inf));
	if(intf == 0x00 )
		strcpy(RF_inf,"NFCEE_Direct");
	else if(intf == 0x01)
		strcpy(RF_inf,"Frame");
	else if(intf == 0x02 )
		strcpy(RF_inf,"ISO-DEP");
	else if(intf == 0x03 )
		strcpy(RF_inf,"NFC_DEP");
	//add from PN553 user manual  +++
	else if(intf == 0x80 )
		strcpy(RF_inf,"TAG-CMD");
	else if(intf == 0x82 )
		strcpy(RF_inf,"NFCEE_UICC_Direct");
	else if(intf == 0x83 )
		strcpy(RF_inf,"NFCEE_eSE_Direct");
	else if(intf == 0x84 )
		strcpy(RF_inf,"NFCEE_UICC2_Direct");
	//add from PN553 user manual  ---
	else if(intf>=0x80 && intf<=0xFE)
		strcpy(RF_inf,"proprietary_use");
	else
		strcpy(RF_inf,"UNKNOWN");	
	return RF_inf;
}

char * getRFProtocol(uint8_t proto){
	static char RF_proto[24];
	memset(RF_proto, 0, sizeof(RF_proto));
	if(proto == NCI_PROTOCOL_UNKNOWN )
		strcpy(RF_proto,"UNDETERMINED");
	else if(proto == NCI_PROTOCOL_T1T)
		strcpy(RF_proto,"T1T");
	else if(proto == NCI_PROTOCOL_T2T )
		strcpy(RF_proto,"T2T");
	else if(proto == NCI_PROTOCOL_T3T )
		strcpy(RF_proto,"T3T");
	else if(proto == NCI_PROTOCOL_ISO_DEP )
		strcpy(RF_proto,"ISO_DEP");
	else if(proto == NCI_PROTOCOL_NFC_DEP )
		strcpy(RF_proto,"NFC_DEP");
	else if(proto == NCI_PROTOCOL_15693 )
		strcpy(RF_proto,"15693");
	//add from PN553 user manual  +++
	else if(proto == NCI_PROTOCOL_MIFARE_CLASSIC )
		strcpy(RF_proto,"MIFARE_CLASSIC");
	else if(proto == NCI_PROTOCOL_KOVIO )
		strcpy(RF_proto,"KOVIO");
	else if(proto == 0x82 )
		strcpy(RF_proto,"X");
	else if(proto == 0x83 )
		strcpy(RF_proto,"Y");
	else if(proto == NCI_PROTOCOL_ISO7816 )
		strcpy(RF_proto,"SELECT_7816_AID");
	//add from PN553 user manual  ---
	else if(proto>=0x80 && proto<=0xFE)
		strcpy(RF_proto,"proprietary_use");
	else
		strcpy(RF_proto,"UNKNOWN");		
	return RF_proto;
}

char * getRFTecoAndMode(uint8_t teco){
	static char RF_techo[24];
	memset(RF_techo, 0, sizeof(RF_techo));
	if(teco == 0x00 )
		strcpy(RF_techo,"A_PASSIVE_POLL");
	else if(teco == 0x01)
		strcpy(RF_techo,"B_PASSIVE_POLL");
	else if(teco == 0x02 )
		strcpy(RF_techo,"F_PASSIVE_POLL");
	else if(teco == 0x03 )
		strcpy(RF_techo,"A_ACTIVE_POLL");
	else if(teco == 0x05 )
		strcpy(RF_techo,"F_ACTIVE_POLL");
	else if(teco == 0x06 )
		strcpy(RF_techo,"15693_PASSIVE_POLL");
	else if(teco == 0x80 )
		strcpy(RF_techo,"A_PASSIVE_LISTEN");
	else if(teco == 0x81 )
		strcpy(RF_techo,"B_PASSIVE_LISTEN");
	else if(teco == 0x82 )
		strcpy(RF_techo,"F_PASSIVE_LISTEN");
	else if(teco == 0x83 )
		strcpy(RF_techo,"A_ACTIVE_LISTEN");
	else if(teco == 0x85 )
		strcpy(RF_techo,"F_PASSIVE_LISTEN");
	else if(teco == 0x86 )
		strcpy(RF_techo,"F_ACTIVE_LISTEN");
	else
		strcpy(RF_techo,"UNKNOWN");	
	return RF_techo;
}

char * getNfcDepType(uint8_t ptype){
	static char nfc_dep_ptype[48];
	memset(nfc_dep_ptype, 0, sizeof(nfc_dep_ptype));
	if(ptype == 0x00 )
		strcpy(nfc_dep_ptype,"SYMM");
	else if(ptype == 0x01)
		strcpy(nfc_dep_ptype,"Parameter_Exchange");
	else if(ptype == 0x02 )
		strcpy(nfc_dep_ptype,"Aggregated_Frame");
	else if(ptype == 0x03 )
		strcpy(nfc_dep_ptype,"Unnumbered_Infor");
	else if(ptype == 0x04 )
		strcpy(nfc_dep_ptype,"CONNECT");		
	else if(ptype == 0x05 )
		strcpy(nfc_dep_ptype,"DISCONNECT");
	else if(ptype == 0x06 )
		strcpy(nfc_dep_ptype,"Connect_Complete");
	else if(ptype == 0x07 )
		strcpy(nfc_dep_ptype,"Disconnect_Mode");	
	else if(ptype == 0x08 )
		strcpy(nfc_dep_ptype,"Frame_Reject");
	else if(ptype == 0x09 )
		strcpy(nfc_dep_ptype,"Service_Name_Loopup");
	else if(ptype == 0x0C )
		strcpy(nfc_dep_ptype,"Information");
	else if(ptype == 0x0D )
		strcpy(nfc_dep_ptype,"Receive_Ready");
	else if(ptype == 0x0E )
		strcpy(nfc_dep_ptype,"Receive_Not_Ready");
	else
		strcpy(nfc_dep_ptype,"UNKNOWN");	
	return nfc_dep_ptype;
}
