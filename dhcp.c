// DHCP Library
// Jason Losh

// edited / project by Nafiul Arefeen

//-----------------------------------------------------------------------------
// Hardware Target
//-----------------------------------------------------------------------------

// Target Platform: -
// Target uC:       -
// System Clock:    -

// Hardware configuration:
// -

//-----------------------------------------------------------------------------
// Device includes, defines, and assembler directives
//-----------------------------------------------------------------------------

#include <stdio.h>
#include "dhcp.h"
#include "arp.h"
#include "timer.h"

#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5
#define DHCPNAK      6
#define DHCPRELEASE  7
#define DHCPINFORM   8

#define DHCP_DISABLED   0
#define DHCP_INIT       1
#define DHCP_SELECTING  2
#define DHCP_REQUESTING 3
#define DHCP_TESTING_IP 4
#define DHCP_BOUND      5
#define DHCP_RENEWING   6
#define DHCP_REBINDING  7
#define DHCP_INITREBOOT 8 // not used since ip not stored over reboot
#define DHCP_REBOOTING  9 // not used since ip not stored over reboot

// ------------------------------------------------------------------------------
//  Globals
// ------------------------------------------------------------------------------

uint32_t xid = 0;
uint32_t leaseSeconds = 0;
uint32_t leaseT1 = 0;
uint32_t leaseT2 = 0;

// use these variables if you want
bool discoverNeeded = false;
bool requestNeeded = false;
bool releaseNeeded = false;

bool ipConflictDetectionMode = false;

uint8_t dhcpOfferedIpAdd[4];
uint8_t dhcpServerIpAdd[4];

uint8_t dhcpState = DHCP_INIT;
bool    dhcpEnabled = true;

//added flags
bool requestSent = false;
bool gratuitousArpNeeded = false;
// ------------------------------------------------------------------------------
//  Structures
// ------------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Subroutines
//-----------------------------------------------------------------------------

// State functions

void setDhcpState(uint8_t state)
{
    dhcpState = state;
}

uint8_t getDhcpState()
{
    return dhcpState;
}

// New address functions
// Manually requested at start-up
// Discover messages sent every 15 seconds

void callbackDhcpGetNewAddressTimer()
{
    if (dhcpState == DHCP_SELECTING || dhcpState == DHCP_REQUESTING)
    {
        dhcpState = DHCP_INIT;
    }
}

void requestDhcpNewAddress()
{
    dhcpState = DHCP_INIT;

}

// Renew functions


void callbackDhcpT1PeriodicTimer()
{

}
void callbackDhcpT2PeriodicTimer()
{
}
// End of lease timer
void callbackDhcpLeaseEndTimer()
{
    stopTimer(callbackDhcpT1PeriodicTimer);
    stopTimer(callbackDhcpT2PeriodicTimer);
    stopTimer(callbackDhcpLeaseEndTimer);

    uint8_t zeroIp[4] = {0, 0, 0, 0};
    setIpAddress(zeroIp);

    requestSent = false;
    gratuitousArpNeeded = false;
    dhcpState = DHCP_INIT;
}

void callbackDhcpT2HitTimer()
{
    if (dhcpState == DHCP_RENEWING)
    {
        stopTimer(callbackDhcpT1PeriodicTimer);

        uint32_t leaseEndOffset = leaseSeconds - leaseT2;
        restartTimer(callbackDhcpLeaseEndTimer);
        startOneshotTimer(callbackDhcpLeaseEndTimer, leaseEndOffset);

        dhcpState = DHCP_REBINDING;
    }
}


void callbackDhcpT1HitTimer()
{
    if(dhcpState == DHCP_BOUND)
    {
        stopTimer(callbackDhcpT1PeriodicTimer);
        uint32_t t2Offset = leaseT2 - leaseT1;
        callbackDhcpLeaseEndTimer(callbackDhcpT2HitTimer);
        startOneshotTimer(callbackDhcpT2HitTimer, t2Offset);

        dhcpState = DHCP_RENEWING;
    }
}

// Rebind functions

void rebindDhcp()
{
    if (dhcpState == DHCP_RENEWING)
    {
        dhcpState = DHCP_REBINDING;
    }
}




// Release functions

void releaseDhcp()
{
    if (dhcpState == DHCP_BOUND || dhcpState == DHCP_RENEWING || dhcpState == DHCP_REBINDING)
    {
        stopTimer(callbackDhcpT1HitTimer);
        stopTimer(callbackDhcpT1PeriodicTimer);
        stopTimer(callbackDhcpT2HitTimer);
        stopTimer(callbackDhcpT2PeriodicTimer);
        stopTimer(callbackDhcpLeaseEndTimer);

        releaseNeeded = true;

        requestSent = false;
        gratuitousArpNeeded = false;

        uint8_t zeroIp[4] = {0, 0, 0, 0};
        setIpAddress(zeroIp);


    }
}

void renewDhcp()
{
    if (dhcpState == DHCP_BOUND || dhcpState == DHCP_RENEWING || dhcpState == DHCP_REBINDING)
    {
        stopTimer(callbackDhcpT1HitTimer);
        stopTimer(callbackDhcpT1PeriodicTimer);
        stopTimer(callbackDhcpT2HitTimer);
        stopTimer(callbackDhcpT2PeriodicTimer);
        stopTimer(callbackDhcpLeaseEndTimer);

        releaseNeeded = true;
        requestSent = false;
        gratuitousArpNeeded = false;

        uint8_t zeroIp[4] = {0, 0, 0, 0};
        setIpAddress(zeroIp);
        dhcpState = DHCP_INIT;
    }

}

// IP conflict detection

void callbackDhcpRequestRetryTimer()
{
    if (dhcpState == DHCP_REQUESTING)
    {
        requestSent = false;
    }
}
void callbackDhcpIpConflictWindow()
{
    ipConflictDetectionMode = false;

    if (dhcpState == DHCP_TESTING_IP)
    {
        setIpAddress(dhcpOfferedIpAdd);
        dhcpState = DHCP_BOUND;
        restartTimer(callbackDhcpT1HitTimer);
        startOneshotTimer(callbackDhcpT1HitTimer, leaseT1);
        gratuitousArpNeeded = true;
    }
}

void requestDhcpIpConflictTest()
{
    ipConflictDetectionMode = true;
    restartTimer(callbackDhcpIpConflictWindow);
    startOneshotTimer(callbackDhcpIpConflictWindow, 2);
}

bool isDhcpIpConflictDetectionMode()
{
    return ipConflictDetectionMode;
}

// Lease functions

uint32_t getDhcpLeaseSeconds()
{
    return leaseSeconds;
}

// Determines whether packet is DHCP
// Must be a UDP packet
bool isDhcpResponse(etherHeader* ether)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    udpHeader *udp = (udpHeader*)((uint8_t*)ip + ipHeaderLength);
    dhcpFrame *dhcp = (dhcpFrame*)udp->data;

    bool response = false;

    // checking if UDP then the correct ports and the cookie
    if (ip->protocol == PROTOCOL_UDP && ntohs(udp->sourcePort) == 67 && ntohs(udp->destPort) == 68 && ntohl(dhcp->magicCookie) == 0x63825363)
    {

        response = true;

    }

    return response;
}

// Send DHCP message
void sendDhcpMessage(etherHeader *ether, uint8_t type)
{


    uint8_t DHCP_Buffer[sizeof(dhcpFrame) + 50] = {};
    dhcpFrame *discover = (dhcpFrame*)DHCP_Buffer;
    uint32_t count = 0;
    int i;
    uint8_t localHwAddress[HW_ADD_LENGTH];
    uint8_t localIpAddress[4];


    if(xid == 0)
    {
        xid = random32();
    }



    discover->op = 1;
    discover->htype = 1;
    discover->hlen = 6;
    discover->hops = 0;
    discover->xid = htonl(xid);
    discover->secs = 0;
    if (dhcpState == DHCP_RENEWING)
    {
        discover->flags = 0;
    }
    else
    {
        discover->flags = htons(0x8000);
    }

    if (type == DHCPRELEASE || dhcpState == DHCP_RENEWING || dhcpState == DHCP_REBINDING)
    {
        getIpAddress(localIpAddress);
        for (i = 0; i < 4; i++)
        {
            discover->ciaddr[i] = localIpAddress[i];
        }
    }

    getEtherMacAddress(localHwAddress);
    for (i = 0; i < 6; i++)
    {
        discover->chaddr[i] = localHwAddress[i];
    }
//    for (i = 6; i < 16; i++)
//    {
//        discover->chaddr[i] = 0;
//    }

    discover->magicCookie = htonl(0x63825363);

    discover->options[count++] = 53;
    discover->options[count++] = 1;
    discover->options[count++] = type;

    if (type == DHCPDISCOVER)
    {
        discover->options[count++] = 61;
        discover->options[count++] = 7;
        discover->options[count++] = 1;
        for (i = 0; i < 6; i++)
        {
            discover->options[count++] = localHwAddress[i];
        }

         discover->options[count++] = 12;
         discover->options[count++] = 4;
         discover->options[count++] = 'R';
         discover->options[count++] = 'A';
         discover->options[count++] = 'I';
         discover->options[count++] = 'A';


        discover->options[count++] = 55;

        discover->options[count++] = 8; // len

        discover->options[count++] = 1;
        discover->options[count++] = 3;
        discover->options[count++] = 6;
        discover->options[count++] = 50;
        discover->options[count++] = 51;
        discover->options[count++] = 54;
        discover->options[count++] = 58;
        discover->options[count++] = 59;
    }
    else if(type == DHCPREQUEST)
    {

                discover->options[count++] = 50;
                discover->options[count++] = 4;
                for (i = 0; i < 4; i++)
                {
                    discover->options[count++] = dhcpOfferedIpAdd[i];
                }

                discover->options[count++] = 54;
                discover->options[count++] = 4;
                for (i = 0; i < 4; i++)
                {
                    discover->options[count++] = dhcpServerIpAdd[i];
                }

                discover->options[count++] = 61;
                discover->options[count++] = 7;
                discover->options[count++] = 1;
                for (i = 0; i < 6; i++)
                {
                    discover->options[count++] = localHwAddress[i];
                }

    }
    else if (type == DHCPRELEASE)
    {
        // RELEASE message options

        discover->options[count++] = 54;
        discover->options[count++] = 4;
        for (i = 0; i < 4; i++)
        {
            discover->options[count++] = dhcpServerIpAdd[i];
        }
    }
    else if (type == DHCPDECLINE)
    {
        discover->options[count++] = 50;
        discover->options[count++] = 4;
        for (i = 0; i < 4; i++)
        {
            discover->options[count++] = dhcpOfferedIpAdd[i];
        }

        discover->options[count++] = 54;
        discover->options[count++] = 4;
        for (i = 0; i < 4; i++)
        {
            discover->options[count++] = dhcpServerIpAdd[i];
        }
    }

    // ending 255

    discover->options[count++] = 255;

    socket DHCPsocket;


    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        DHCPsocket.remoteHwAddress[i] = 0xFF;
    }

    for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        DHCPsocket.remoteIpAddress[i] = 255;
    }
    DHCPsocket.localPort = 68;
    DHCPsocket.remotePort = 67;

    sendUdpMessage(ether, DHCPsocket, DHCP_Buffer, (uint16_t)(sizeof(dhcpFrame) + count));


    if (type == DHCPRELEASE)
    {
        releaseNeeded = false;
    }

}

uint8_t* getDhcpOption(etherHeader *ether, uint8_t option, uint8_t* length)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    udpHeader *udp = (udpHeader*)((uint8_t*)ip + ipHeaderLength);
    dhcpFrame *dhcp = (dhcpFrame*)udp->data;

    uint8_t *options = dhcp->options;
    uint16_t i = 0;

    while (options[i] != 255 && i < 255)
    {
        if (options[i] == option)
        {
            *length = options[i + 1];
            return &options[i + 2];  // +2 to account for the offset by the type and length
        }
        else if (options[i] == 0)
        {
            i++;
        }
        else
        {

            i += 2 + options[i + 1]; // skipping the option by the len, type and options

        }
    }

    *length = 0;
    return NULL;
}

// Determines whether packet is DHCP offer response to DHCP discover
// Must be a UDP packet
bool isDhcpOffer(etherHeader *ether, uint8_t ipOfferedAdd[])
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    udpHeader *udp = (udpHeader*)((uint8_t*)ip + ipHeaderLength);
    dhcpFrame *dhcp = (dhcpFrame*)udp->data;

    bool offer = false;
    uint8_t *optionData;
    uint8_t optionLength;

    //checking if its DHCP and if the xid match
    if (isDhcpResponse(ether) && ntohl(dhcp->xid) == xid)
    {
        optionData = getDhcpOption(ether, 53, &optionLength);
        //checking for options that make it an offer
        if (optionData != NULL && optionLength == 1)
        {
            if (*optionData == DHCPOFFER)
            {
                offer = true;

                ipOfferedAdd[0] = dhcp->yiaddr[0];
                ipOfferedAdd[1] = dhcp->yiaddr[1];
                ipOfferedAdd[2] = dhcp->yiaddr[2];
                ipOfferedAdd[3] = dhcp->yiaddr[3];
            }
        }

    }

    return offer;
}


// Determines whether packet is DHCP ACK response to DHCP request
// Must be a UDP packet
bool isDhcpAck(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    udpHeader *udp = (udpHeader*)((uint8_t*)ip + ipHeaderLength);
    dhcpFrame *dhcp = (dhcpFrame*)udp->data;

    bool ack = false;
    uint8_t *optionData;
    uint8_t optionLength;

   // checking if xid matches and is a dhcp response
    if (isDhcpResponse(ether) && ntohl(dhcp->xid) == xid)
    {
        optionData = getDhcpOption(ether, 53, &optionLength);
        //checking and finding the correct options for an ack
        if (optionData != NULL && optionLength == 1)
        {
            if (*optionData == DHCPACK)
            {
                ack = true;
            }
        }
    }

    return ack;
}

// Handle a DHCP ACK
void handleDhcpAck(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    udpHeader *udp = (udpHeader*)((uint8_t*)ip + ipHeaderLength);
    dhcpFrame *dhcp = (dhcpFrame*)udp->data;

    uint8_t i;
    uint8_t *optionData;
    uint8_t optionLength;
    uint32_t leaseTime;

    stopTimer(callbackDhcpGetNewAddressTimer);

    for (i = 0; i < 4; i++)
    {
        dhcpOfferedIpAdd[i] = dhcp->yiaddr[i];
    }

    // getting subnet mask for 1
    optionData = getDhcpOption(ether, 1, &optionLength);
    if (optionData != NULL && optionLength == 4)
    {
        uint8_t mask[4];
        for (i = 0; i < 4; i++)
        {
            mask[i] = optionData[i];
        }
        setIpSubnetMask(mask);
    }

    // getting router for 3
    optionData = getDhcpOption(ether, 3, &optionLength);
    if (optionData != NULL && optionLength >= 4)
    {
        uint8_t gw[4];
        for (i = 0; i < 4; i++)
        {
            gw[i] = optionData[i];
        }
        setIpGatewayAddress(gw);
    }

    // getting server for 6
    optionData = getDhcpOption(ether, 6, &optionLength);
    if (optionData != NULL && optionLength >= 4)
    {
        uint8_t dns[4];
        for (i = 0; i < 4; i++)
        {
            dns[i] = optionData[i];
        }
        setIpDnsAddress(dns);
    }

    // getting lease time 51
    optionData = getDhcpOption(ether, 51, &optionLength);
    if (optionData != NULL && optionLength == 4)
    {
        leaseTime = (optionData[0] << 24) | (optionData[1] << 16) | (optionData[2] << 8) | optionData[3];

        leaseSeconds = leaseTime;
        leaseT1 = leaseTime / 2;
        leaseT2 = (leaseTime * 7) / 8;
        // using fixed vaules for testing
//        leaseSeconds = 60;
//        leaseT1 = 30;
//        leaseT2 = 45;
    }
    requestSent = false;
    dhcpState = DHCP_TESTING_IP;
    requestDhcpIpConflictTest();
}

// Message requests

bool isDhcpDiscoverNeeded()
{
    return (dhcpState == DHCP_INIT);
}

bool isDhcpRequestNeeded()
{
    return !requestSent;
}

bool isDhcpReleaseNeeded()
{
    return releaseNeeded;
}

void sendDhcpPendingMessages(etherHeader *ether)
{
    uint8_t zeroIp[4] = {0, 0, 0, 0};

    if (isDhcpReleaseNeeded())
    {
        sendDhcpMessage(ether, DHCPRELEASE);
        return;
    }

    if (!dhcpEnabled)
    {
        if (dhcpState != DHCP_DISABLED)
        {
            dhcpState = DHCP_DISABLED;
        }
        return;
    }

    if (dhcpState == DHCP_DISABLED && dhcpEnabled)
    {
        dhcpState = DHCP_INIT;
    }

    if (dhcpState == DHCP_INIT)
    {
        sendDhcpMessage(ether, DHCPDISCOVER);
        restartTimer(callbackDhcpGetNewAddressTimer);
        startOneshotTimer(callbackDhcpGetNewAddressTimer, 15);
        dhcpState = DHCP_SELECTING;
    }

    // waiting for offer
    else if (dhcpState == DHCP_SELECTING)
    {
    }
    else if (dhcpState == DHCP_REQUESTING)
    {
        if (isDhcpRequestNeeded())
        {
            sendDhcpMessage(ether, DHCPREQUEST);
            requestSent = true;
            restartTimer(callbackDhcpGetNewAddressTimer);
            startOneshotTimer(callbackDhcpGetNewAddressTimer, 15);

        }

    }

    else if (dhcpState == DHCP_TESTING_IP)
    {
        sendArpRequest(ether, zeroIp, dhcpOfferedIpAdd);
    }
    else if (dhcpState == DHCP_BOUND)
    {
        if (gratuitousArpNeeded)
        {

            sendArpRequest(ether, dhcpOfferedIpAdd, dhcpOfferedIpAdd);
            gratuitousArpNeeded = false;
        }
    }
    else if (dhcpState == DHCP_DISABLED)
    {
    }
    else if (dhcpState == DHCP_RENEWING)
    {
        if (isDhcpRequestNeeded())
        {
            sendDhcpMessage(ether, DHCPREQUEST);
            requestSent = true;
            restartTimer(callbackDhcpT1PeriodicTimer);
            startOneshotTimer(callbackDhcpT1PeriodicTimer, 5);
        }
    }
    else if (dhcpState == DHCP_REBINDING)
    {
        if (isDhcpRequestNeeded())
        {
            sendDhcpMessage(ether, DHCPREQUEST);
            requestSent = true;
            restartTimer(callbackDhcpT2PeriodicTimer);
            startOneshotTimer(callbackDhcpT2PeriodicTimer, 5);
        }
    }

}

void processDhcpResponse(etherHeader *ether)
{
    uint8_t i;
    uint8_t *optionData;
    uint8_t optionLength;

    if (dhcpState == DHCP_SELECTING)
    {
        if (isDhcpOffer(ether, dhcpOfferedIpAdd))
        {
            stopTimer(callbackDhcpGetNewAddressTimer);

            optionData = getDhcpOption(ether, 54, &optionLength);
            if (optionData != NULL && optionLength == 4)
            {
                for (i = 0; i < 4; i++)
                {
                    dhcpServerIpAdd[i] = optionData[i];
                }
            }

            dhcpState = DHCP_REQUESTING;
        }
    }
    else if (dhcpState == DHCP_REQUESTING)
    {
        if (isDhcpAck(ether))
        {
            handleDhcpAck(ether);
        }
    }
    else if (dhcpState == DHCP_RENEWING || dhcpState == DHCP_REBINDING)
    {
        if (isDhcpAck(ether))
        {
            // Stop all existing timers
            stopTimer(callbackDhcpT1HitTimer);
            stopTimer(callbackDhcpT1PeriodicTimer);
            stopTimer(callbackDhcpT2HitTimer);
            stopTimer(callbackDhcpT2PeriodicTimer);
            stopTimer(callbackDhcpLeaseEndTimer);

            // Extract new lease info from ACK
            ipHeader *ip = (ipHeader*)ether->data;
            uint8_t ipHeaderLength = ip->size * 4;
            udpHeader *udp = (udpHeader*)((uint8_t*)ip + ipHeaderLength);
            dhcpFrame *dhcp = (dhcpFrame*)udp->data;
            uint8_t *optData;
            uint8_t optLen;
            uint32_t newLeaseTime;

            for (i = 0; i < 4; i++)
            {
                dhcpOfferedIpAdd[i] = dhcp->yiaddr[i];
            }
            setIpAddress(dhcpOfferedIpAdd);

            optData = getDhcpOption(ether, 1, &optLen);
            if (optData != NULL && optLen == 4)
            {
                uint8_t mask[4];
                for (i = 0; i < 4; i++)
                    mask[i] = optData[i];
                setIpSubnetMask(mask);
            }

            optData = getDhcpOption(ether, 3, &optLen);
            if (optData != NULL && optLen >= 4)
            {
                uint8_t gw[4];
                for (i = 0; i < 4; i++)
                    gw[i] = optData[i];
                setIpGatewayAddress(gw);
            }

            optData = getDhcpOption(ether, 6, &optLen);
            if (optData != NULL && optLen >= 4)
            {
                uint8_t dns[4];
                for (i = 0; i < 4; i++)
                    dns[i] = optData[i];
                setIpDnsAddress(dns);
            }

            optData = getDhcpOption(ether, 51, &optLen);
            if (optData != NULL && optLen == 4)
            {
                newLeaseTime = (optData[0] << 24) | (optData[1] << 16) | (optData[2] << 8) | optData[3];
                leaseSeconds = newLeaseTime;
                leaseT1 = newLeaseTime / 2;
                leaseT2 = (newLeaseTime * 7) / 8;
//                leaseSeconds = 60;
//                leaseT1 = 30;
//                leaseT2 = 45;

            }

            dhcpState = DHCP_BOUND;
            requestSent = false;
            restartTimer(callbackDhcpT1HitTimer);
            startOneshotTimer(callbackDhcpT1HitTimer, leaseT1);
        }
    }
}

void processDhcpArpResponse(etherHeader *ether)
{
    // Check if we're in IP conflict detection mode
    if (ipConflictDetectionMode && dhcpState == DHCP_TESTING_IP)
    {
        arpPacket *arp = (arpPacket*)ether->data;
        uint8_t i;
        bool isConflict = true;

        for (i = 0; i < IP_ADD_LENGTH; i++)
        {
            if (arp->sourceIp[i] != dhcpOfferedIpAdd[i])
            {
                isConflict = false;
                break;
            }
        }

        if (isConflict)
        {

            stopTimer(callbackDhcpIpConflictWindow);
            ipConflictDetectionMode = false;


            sendDhcpMessage(ether, DHCPDECLINE);

            dhcpState = DHCP_INIT;
        }
    }
}

// DHCP control functions

void enableDhcp()
{
    dhcpEnabled = true;
//    if (dhcpState == DHCP_DISABLED)
//    {
      dhcpState = DHCP_INIT;
//    }
}

void disableDhcp()
{
    dhcpEnabled = false;
    dhcpState = DHCP_DISABLED;
}

bool isDhcpEnabled()
{
    return dhcpEnabled;
}

