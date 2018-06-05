#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "nfcAnalysis.h"

#define ENABLE_NFC "Enabling NFC"
#define DISABLE_NFC "Disabling NFC"
#define NFC_ENABLED "NFC Enabled"
#define NFC_DISABLED "NFC Disabled"
#define DATA_SEND "NxpNciX"
#define DATA_RECEIVE "NxpNciR"

char nfc_log[1024]={'\0'};
FILE *w_fp;

void printControlOpration(char *time, char *action, uint8_t type,char *data_string, uint8_t *data,long data_length);
char * getPacketType(uint8_t type);
char * getStatusCodes(uint8_t code);
char * getRFInterface(uint8_t intf);
char * getRFProtocol(uint8_t proto);
char * getRFTecoAndMode(uint8_t teco);

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
	
	if(argc!=2){
		printf("Pls input : nfcAnalysis filepath");
		return -1;
	}
	strcpy(file_path, *(argv+1));
    printf("file path is %s\n",file_path);
	
	GetFilename(file_path);
	
	printf("output file is %s\n",nfc_log);
		
	w_fp=fopen(nfc_log,"w+");
    if (NULL == w_fp)
    {
		printf("create nfcAnalysis fail\n");
        return -1;
    }
	FILE *r_fp=fopen(file_path,"r");
    if (NULL == r_fp)
    {
		printf("can not open %s\n,",file_path);
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
			if(type == NCI_MT_DATA)
				fprintf (w_fp, "%s\t%s\t\t%s\t\t\t%s\n",time,action,getPacketType(type),data_string);
			else if(type != 0xFF){
				printControlOpration(time, action, type,data_string, data,data_length_int);				
			}else
				fprintf (w_fp, "%s\t%s\n",time,action);
		}
    };
	
	fclose(w_fp);
	fclose(r_fp);
    return 1;
}

void printControlOpration(char *time, char *action, uint8_t type,char *data_string, uint8_t *data,long data_length){
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
				if(type == NCI_MT_NTF){
					sprintf(parameter,"Dis_ID:%d , Proto: %s , Techo:%s",*(data+3), getRFProtocol(*(data+4)),
						getRFTecoAndMode(*(data+5)));			
				}
				break;			
			case NCI_MSG_RF_DISCOVER_SELECT :
				strcpy(ctrlcommand,"DISCOVER_SELECT");
				if( type == NCI_MT_CMD )
					sprintf(parameter,"Dis_ID:%d , Intf: %s , Proto: %s",*(data+3),getRFInterface(*(data+5)),
						getRFProtocol(*(data+4)));
				break;			
			case NCI_MSG_RF_INTF_ACTIVATED :
				strcpy(ctrlcommand,"INTF_ACTIVATED");			
				sprintf(parameter,"Dis_ID:%d , Intf: %s , Proto: %s , Techo:%s",*(data+3),getRFInterface(*(data+4)),
						getRFProtocol(*(data+5)), getRFTecoAndMode(*(data+6)));
				break;			
			case NCI_MSG_RF_DEACTIVATE :
				strcpy(ctrlcommand,"DEACTIVATE");
				break;			
			case NCI_MSG_RF_FIELD :
				strcpy(ctrlcommand,"FILD");
				break;			
			case NCI_MSG_RF_T3T_POLLING :
				strcpy(ctrlcommand,"T3T_POLLING");
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
	fprintf (w_fp, "------  %s\n",data_string);
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
	if(proto == 0x00 )
		strcpy(RF_proto,"UNDETERMINED");
	else if(proto == 0x01)
		strcpy(RF_proto,"T1T");
	else if(proto == 0x02 )
		strcpy(RF_proto,"T2T");
	else if(proto == 0x03 )
		strcpy(RF_proto,"T3T");
	else if(proto == 0x04 )
		strcpy(RF_proto,"ISO_DEP");
	else if(proto == 0x05 )
		strcpy(RF_proto,"NFC_DEP");
	else if(proto == 0x06 )
		strcpy(RF_proto,"15693");
	//add from PN553 user manual  +++
	else if(proto == 0x80 )
		strcpy(RF_proto,"MIFARE_CLASSIC");
	else if(proto == 0x81 )
		strcpy(RF_proto,"KOVIO");
	else if(proto == 0x82 )
		strcpy(RF_proto,"X");
	else if(proto == 0x83 )
		strcpy(RF_proto,"Y");
	else if(proto == 0xA0 )
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
