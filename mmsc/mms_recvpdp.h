#pragma once

struct pdpData
{
    uint32_t ip_addr;
    const char* msisdn;
};

void startPDPListener(int pdpPort);
const char* ipToMSISDN(const char* ip_addr);
