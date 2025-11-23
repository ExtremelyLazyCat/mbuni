#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include "mms_recvpdp.h"
#include "mmsc_cfg.h"
#include "mmsc.h"

#define PDPSIZE 65535

struct pdpData* pdpTable[PDPSIZE];
static int maxUser = -1; //an array index of the highest user in the pdpTable array, highest value is PDPSIZE - 1.
static int port;

static void dumpPDPTable()
{
	struct in_addr inet_addr;
	debug("mms.recvpdp", 0, "PDP Table Contents:");
	for (int i = 0; i <= maxUser + 1; i++) {
		if(pdpTable[i] != NULL) {
			inet_addr.s_addr = pdpTable[i]->ip_addr;
			debug("mms.recvpdp", 0, "[%i: IP=%s(%i), MSISDN=%s]", i, octstr_get_cstr(gw_netaddr_to_octstr(AF_INET, &inet_addr)), pdpTable[i]->ip_addr, pdpTable[i]->msisdn);
		}
		else
			debug("mms.recvpdp", 0, "[%i: NULL]", i);
	}
}

static int pdpSearch(uint32_t targetIp)
{
    int low = 0, high = maxUser;

    while (low <= high) {
        int mid = low + (high - low) / 2;

        if (pdpTable[mid]->ip_addr == targetIp)
            return mid;
        
        if (pdpTable[mid]->ip_addr < targetIp)
            low = mid + 1;

        else
            high = mid - 1;
    }

    return -1;
}


/* We want to find the index where:
   pdpTable[index - 1] < target < pdpTable[index].
   In this modified binary search, this is true when:
   pdpTable[low] < target < pdpTable[high], and
   there is a difference of 1 between low and high.
*/

static int pdpInsertionIndex(uint32_t targetIp)
{	
	if (maxUser < 0)
		return 0;
	
	if (targetIp < pdpTable[0]->ip_addr)
		return 0;
	
	if (targetIp > pdpTable[maxUser]->ip_addr)
		return maxUser + 1;
	
	int low = 0, high = maxUser, mid;

    while (low + 1 != high) {
        mid = low + (high - low) / 2;
        if (pdpTable[mid]->ip_addr < targetIp)
            low = mid;
        else
            high = mid;
    }
		
	return high;
}

static void pdpAddIndex(int where, struct pdpData* pdpDat)
{
    int pdpLen = PDPSIZE;
    int bound = maxUser + 1;
    int i;
	
    if (bound >= pdpLen) {
		mms_warning(0, "mms_recvpdp", NULL, "Overflow in pdp table! ignoring addition of ip %u. Increase PDPSIZE in mms_recvpdp.c", pdpDat->ip_addr);
        gw_free((void *) pdpDat->msisdn);
		gw_free(pdpDat);
		return;
    }
	
    struct pdpData* temp = pdpTable[where];
    struct pdpData* swap = pdpDat;
    for (i = where; i < bound; i++) {
        pdpTable[i] = swap;
        swap = temp;
        temp = pdpTable[i + 1];
    }
	
    pdpTable[i] = swap; //boundary case so we don't read OOB
}

static void pdpAdd(const char* ip_addr, const char* msisdn)
{
	struct in_addr inet_addr;
    int r = inet_aton(ip_addr, &inet_addr);
    if (!r) {
		mms_warning(0, "mms_recvpdp", NULL, "Failed to convert %s to an IP!", ip_addr);
        return;
    }
	
	struct pdpData* pDat = (struct pdpData *) gw_malloc(sizeof(struct pdpData));
	if (pDat == NULL) {
		mms_error(0, "mms_recvpdp", NULL, "gw_malloc for pDat failed in pdpAdd");
		return;
	}
	pDat->ip_addr = inet_addr.s_addr;
	pDat->msisdn = msisdn;
	
	int index = pdpSearch(inet_addr.s_addr);
	if (index > 0) {
		gw_free((void *) pdpTable[index]->msisdn);
		gw_free(pdpTable[index]);
		pdpTable[index] = pDat;
		return;
	}
	
    int insertionIndex = pdpInsertionIndex(inet_addr.s_addr);
    pdpAddIndex(insertionIndex, pDat);
	maxUser++;
}

static void pdpDel(const char* ip_addr)
{
    /* We often receive a pdp_del for IP=UNDEFINED
	   even if the PDP context is still active 
	 */
	if (!strcmp(ip_addr, "UNDEFINED")) {
		debug("mms.recvpdp", 0, "Ignoring operation for IP Address = \"UNDEFINED\""); 
		return;                                                            
	}
	
	struct in_addr inet_addr;
    int r = inet_aton(ip_addr, &inet_addr);
	
	if (!r) {
		mms_warning(0, "mms_recvpdp", NULL, "Failed to convert IP %s to a number!", ip_addr);
        return;
    }
	
	int location = pdpSearch(inet_addr.s_addr);
    int i;

    if (location < 0) {
        mms_warning(0, "mms_recvpdp", NULL, "Failed to delete PDP context(not found) for IP: %s", ip_addr);
        return;
    }

	gw_free((void*) pdpTable[location]->msisdn);
	gw_free(pdpTable[location]);
    
    for (i = location; i <= maxUser; i++)
        pdpTable[i] = pdpTable[i + 1];

    pdpTable[i] = NULL;
	maxUser--;
}

const char* ipToMSISDN(const char* ip_addr)
{
    struct in_addr inet_addr;
    int r = inet_aton(ip_addr, &inet_addr);
    if (!r) {
		mms_warning(0, "mms_recvpdp", NULL, "Failed to convert IP %s to a number!", ip_addr);
        return NULL;
    }

    int search = pdpSearch(inet_addr.s_addr);
    if (search < 0) {
		mms_warning(0, "mms_recvpdp", NULL, "Failed to find IP %s in PDP Table!\n", ip_addr);
        return NULL;
    }

    return pdpTable[search]->msisdn;
}

static int parseSockMsg(char* buffer) {
	char* token = strtok(buffer, "_");
	char* msisdn;
	char* ip_addr; 
	int operation = -1;
	if(strcmp("pdp", token) != 0)
		goto invalid;
	token = strtok(NULL, ",");
	if(!strcmp("add", token))
		operation = 0;
	else if(!strcmp("del", token))
		operation = 1;
	else
		goto invalid;
	token = strtok(NULL, ",");
	ip_addr = (char *) gw_malloc(sizeof(token));
	if(ip_addr == NULL) {
		mms_error(0, "mms_recvpdp", NULL, "Error parsing sock message: malloc failed");
		return -1;
	}
	strcpy((char*) ip_addr, token);
	token = strtok(NULL, ",");
	msisdn = gw_malloc(sizeof(token));
	if(msisdn == NULL) {
		mms_error(0, "mms_recvpdp", NULL, "Error parsing sock message: malloc failed");
		gw_free(ip_addr);
		return -1;
	}
	strcpy((char*) msisdn, token);
	if(operation == 0) //add
		pdpAdd(ip_addr, msisdn);
	if(operation == 1) //del
		pdpDel(ip_addr);
	
	dumpPDPTable();
	return 0;
invalid:
	mms_warning(0, "mms_recvpdp", NULL, "Invalid data received on PDP socket, ignoring");
	return -1;
}


static void* sockThread(void* args) {
	int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);
    char buffer[1024] = { 0 };
	
	for (;;) {
		memset(buffer, 0, sizeof(buffer));
		if ((server_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		mms_error(0, "mms_recvpdp", NULL, "socket() failed!");
			exit(EXIT_FAILURE);
		}

		if (setsockopt(server_fd, SOL_SOCKET,
					   SO_REUSEADDR | SO_REUSEPORT, &opt,
					   sizeof(opt))) {
		mms_error(0, "mms_recvpdp", NULL, "setsockopt() failed!");
			exit(EXIT_FAILURE);
		}
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = INADDR_ANY;
		address.sin_port = htons(port);

		if (bind(server_fd, (struct sockaddr*)&address,
				 sizeof(address))
			< 0) {
		mms_error(0, "mms_recvpdp", NULL, "bind() failed!");
			exit(EXIT_FAILURE);
		}

		recvfrom(server_fd, buffer, 1024 - 1, 0,
				 (struct sockaddr *)&address, &addrlen);
		debug("mms.recvpdp", 0, "Received data on PDP Socket %s", buffer);
		parseSockMsg(buffer);
		close(server_fd);
	}
}

void startPDPListener(int pdpPort)
{
	if (pdpPort < 0) {
		mms_info(0, "mmsc", NULL, "Not starting PDP Listener Thread, no port provided");
		return;
	}
		
    mms_info(0, "mmsc", NULL, "Starting PDP Listener Thread at port %i", pdpPort);
    port = pdpPort;
	pthread_t pdp_thread;
	memset(&pdpTable, 0, sizeof(pdpTable));
	pthread_create(&pdp_thread, NULL, sockThread, NULL);
}
