/* mmiplookup.c
 * Parse ipaddress field of the message into structured data using
 * MaxMindDB.
 *
 * Copyright 2013 Rao Chenlin.
 *
 * This file is part of rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "rsyslog.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include <json.h>

#define JSON_IPLOOKUP_NAME "!iplocation"

/* ipip */
#ifndef _IPIP_H_
#define _IPIP_H_

int init(const char* ipdb);
int destroy();
int find(const char *ip, char *result);
#endif //_IPIP_H_

typedef unsigned char byte;
typedef unsigned int uint;
#define B2IL(b) (((b)[0] & 0xFF) | (((b)[1] << 8) & 0xFF00) | (((b)[2] << 16) & 0xFF0000) | (((b)[3] << 24) & 0xFF000000))
#define B2IU(b) (((b)[3] & 0xFF) | (((b)[2] << 8) & 0xFF00) | (((b)[1] << 16) & 0xFF0000) | (((b)[0] << 24) & 0xFF000000))

struct {
    byte *data;
    byte *index;
    uint *flag;
    uint offset;
} ipip;

int destroy() {
    if (!ipip.offset) {
        return 0;
    }
    free(ipip.flag);
    free(ipip.index);
    free(ipip.data);
    ipip.offset = 0;
    return 0;
}

int init(const char *ipdb) {
    if (ipip.offset) {
        return 0;
    }
    FILE *file = fopen(ipdb, "rb");
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    ipip.data = (byte *) malloc(size * sizeof(byte));
    size_t r = fread(ipip.data, sizeof(byte), (size_t) size, file);

    if (r == 0) {
        return 0;
    }

    fclose(file);

    uint length = B2IU(ipip.data);

    ipip.index = (byte *) malloc(length * sizeof(byte));
    memcpy(ipip.index, ipip.data + 4, length);

    ipip.offset = length;

    ipip.flag = (uint *) malloc(256 * sizeof(uint));
    memcpy(ipip.flag, ipip.index, 256 * sizeof(uint));

    return 0;
}

int find(const char *ip, char *result) {
    uint ips[4];
    int num = sscanf(ip, "%d.%d.%d.%d", &ips[0], &ips[1], &ips[2], &ips[3]);
    if (num == 4) {
        uint ip_prefix_value = ips[0];
        uint ip2long_value = B2IU(ips);
        uint start = ipip.flag[ip_prefix_value];
        uint max_comp_len = ipip.offset - 1028;
        uint index_offset = 0;
        uint index_length = 0;
        for (start = start * 8 + 1024; start < max_comp_len; start += 8) {
            if (B2IU(ipip.index + start) >= ip2long_value) {
                index_offset = B2IL(ipip.index + start + 4) & 0x00FFFFFF;
                index_length = ipip.index[start + 7];
                break;
            }
        }
        memcpy(result, ipip.data + ipip.offset + index_offset - 1024, index_length);
        result[index_length] = '\0';
    }
    return 0;
}


MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
/* module name */
MODULE_CNFNAME("mmiplookup")


DEFobjCurrIf(errmsg);
DEF_OMOD_STATIC_DATA

/* config variables */
typedef struct _instanceData {
        char *pszKey;
        char *pszMmipFile;
        struct {
                int     nmemb;
                uchar **name;
        } fieldList;
} instanceData;

typedef struct wrkrInstanceData {
        instanceData *pData;
} wrkrInstanceData_t;

struct modConfData_s {
        /* our overall config object */
        rsconf_t *pConf;
};

/* modConf ptr to use for the current load process */
static modConfData_t *loadModConf = NULL;
/* modConf ptr to use for the current exec process */
static modConfData_t *runModConf  = NULL;


/* tables for interfacing with the v6 config system
 * action (instance) parameters */
static struct cnfparamdescr actpdescr[] = {
        { "key",      eCmdHdlrGetWord, 0 },
        { "mmipfile", eCmdHdlrGetWord, 0 },
};
static struct cnfparamblk actpblk = {
        CNFPARAMBLK_VERSION,
        sizeof(actpdescr)/sizeof(struct cnfparamdescr),
        actpdescr
};


BEGINbeginCnfLoad
CODESTARTbeginCnfLoad
        loadModConf = pModConf;
        pModConf->pConf = pConf;
ENDbeginCnfLoad

BEGINendCnfLoad
CODESTARTendCnfLoad
ENDendCnfLoad

BEGINcheckCnf
CODESTARTcheckCnf
ENDcheckCnf

BEGINactivateCnf
CODESTARTactivateCnf
        runModConf = pModConf;
ENDactivateCnf

BEGINfreeCnf
CODESTARTfreeCnf
ENDfreeCnf


BEGINcreateInstance
CODESTARTcreateInstance
ENDcreateInstance

BEGINcreateWrkrInstance
CODESTARTcreateWrkrInstance
        init(pData->pszMmipFile);
ENDcreateWrkrInstance


BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
ENDisCompatibleWithFeature


BEGINfreeInstance
CODESTARTfreeInstance
ENDfreeInstance


BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
	destroy();
ENDfreeWrkrInstance

static inline void
setInstParamDefaults(instanceData *pData)
{
        pData->pszKey = NULL;
        pData->pszMmipFile = NULL;
}

BEGINnewActInst
        struct cnfparamvals *pvals;
        int i;
CODESTARTnewActInst
        dbgprintf("newActInst (mmiplookup)\n");
        if ((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
                ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
        }

        CODE_STD_STRING_REQUESTnewActInst(1)
        CHKiRet(OMSRsetEntry(*ppOMSR, 0, NULL, OMSR_TPL_AS_MSG));
        CHKiRet(createInstance(&pData));
        setInstParamDefaults(pData);

        for (i = 0; i < actpblk.nParams; ++i) {
                if (!pvals[i].bUsed)
                        continue;
                if (!strcmp(actpblk.descr[i].name, "key")) {
                        pData->pszKey = es_str2cstr(pvals[i].val.d.estr, NULL);
                        continue;
                }
                if (!strcmp(actpblk.descr[i].name, "mmipfile")) {
                        pData->pszMmipFile = es_str2cstr(pvals[i].val.d.estr, NULL);
                        continue;
                }
         
                dbgprintf("mmiplookup: program error, non-handled"
                        " param '%s'\n", actpblk.descr[i].name);
        }

        if (pData->pszKey == NULL) {
                dbgprintf("mmiplookup: action requires a key");
                ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
        }

        if (pData->pszMmipFile == NULL) {
                dbgprintf("mmiplookup: action requires a mmipfile");
                ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
        }

CODE_STD_FINALIZERnewActInst
        cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst


BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
ENDdbgPrintInstInfo


BEGINtryResume
CODESTARTtryResume
ENDtryResume


BEGINdoAction_NoStrings
        smsg_t **ppMsg = (smsg_t **) pMsgData;
        smsg_t *pMsg   = ppMsg[0];
		struct json_object *json;
		struct json_object *keyjson;
        char *pszValue;
        char result[128];
        instanceData *const pData = pWrkrData->pData;
CODESTARTdoAction
		json =  json_object_new_object();
		if(json == NULL) {
			ABORT_FINALIZE(RS_RET_ERR);
		}
		keyjson =  json_object_new_object();
		if(json == NULL) {
			ABORT_FINALIZE(RS_RET_ERR);
		}
        /* key is given, so get the property json */
        msgPropDescr_t pProp;
        msgPropDescrFill(&pProp, (uchar*)pData->pszKey, strlen(pData->pszKey));
        rsRetVal localRet = msgGetJSONPropJSON(pMsg, &pProp, &keyjson);
        msgPropDescrDestruct(&pProp);
        if (localRet != RS_RET_OK) {
                /* key not found in the message. nothing to do */
               ABORT_FINALIZE(RS_RET_OK);
        }
        /* key found, so get the value */
        pszValue = (char*)json_object_get_string(keyjson);
    	json_object_put(keyjson);

        int findstatus = find(pszValue, result);
        if (findstatus != 0){
               dbgprintf("Error from call to getaddrinfo for %s \n", pszValue);
			   if(json != NULL) {
					/* Release json object as we are not going to add it to pMsg */
					json_object_put(json);
				}
                ABORT_FINALIZE(RS_RET_OK);
        }

        char *token = strtok( result, "\t");
        int i = 1;
        while( token != NULL )
        {
        /* While there are tokens in "string" */
                if (i == 1) {
                         json_object_object_add(json,"country",json_object_new_string(token));
                }else if(i == 2){
                         json_object_object_add(json,"province",json_object_new_string(token));
                }else if(i == 3){
                         json_object_object_add(json,"city",json_object_new_string(token));
                }else if(i == 4){
                        json_object_object_add(json,"isp",json_object_new_string(token));
                }
                /* Get next token: */
                token = strtok( NULL, "\t");
                i++;
        }
finalize_it:
	//ok
	if (json){
        msgAddJSON(pMsg, (uchar *)JSON_IPLOOKUP_NAME, json, 0, 0);
	}

ENDdoAction


BEGINparseSelectorAct
CODESTARTparseSelectorAct
CODE_STD_STRING_REQUESTparseSelectorAct(1)
        if (strncmp((char*) p, ":mmiplookup:", sizeof(":mmiplookup:") - 1)) {
                errmsg.LogError(0, RS_RET_LEGA_ACT_NOT_SUPPORTED,
                        "mmiplookup supports only v6+ config format, use: "
                        "action(type=\"mmiplookup\" ...)");
        }
        ABORT_FINALIZE(RS_RET_CONFLINE_UNPROCESSED);
CODE_STD_FINALIZERparseSelectorAct
ENDparseSelectorAct

 
BEGINmodExit
CODESTARTmodExit
        objRelease(errmsg, CORE_COMPONENT);
ENDmodExit


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_STD_OMOD8_QUERIES
CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_QUERIES
ENDqueryEtryPt


BEGINmodInit()
CODESTARTmodInit
        /* we only support the current interface specification */
        *ipIFVersProvided = CURR_MOD_IF_VERSION;
CODEmodInit_QueryRegCFSLineHdlr
        dbgprintf("mmiplookup: module compiled with rsyslog version %s.\n", VERSION);
        CHKiRet(objUse(errmsg, CORE_COMPONENT));
ENDmodInit
