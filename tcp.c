// TCP Library
// Jason Losh
//-----------------------------------------------------------------------------
// Hardware Target
//-----------------------------------------------------------------------------
// Target Platform: -
// Target uC: -
// System Clock: -
// Hardware configuration:
// -
//-----------------------------------------------------------------------------
// Device includes, defines, and assembler directives
//-----------------------------------------------------------------------------
#include <stdio.h>
#include <string.h>
#include "arp.h"
#include "tcp.h"
#include "timer.h"
// ------------------------------------------------------------------------------
// Globals
// ------------------------------------------------------------------------------
#define MAX_TCP_PORTS   4
#define MAX_TCP_SOCKETS 10
#define TCP_WINDOW_SIZE 1460

// socket table is defined in socket.c
extern socket sockets[MAX_TCP_SOCKETS];

// List of TCP ports this device will listen on
uint16_t tcpPorts[MAX_TCP_PORTS];

// Number of valid entries in tcpPorts[]
uint8_t tcpPortCount = 0;

// Simple TCP state array for opened ports
uint8_t tcpState[MAX_TCP_PORTS];

// ------------------------------------------------------------------------------
// Local helpers
// ------------------------------------------------------------------------------

/*
 * Returns the TCP header length in BYTES.
 *
 * In TCP, the header length is stored in 32-bit words, not bytes.
 * So if the header length field says "5", that means:
 * 5 words * 4 bytes/word = 20 bytes.
 *
 * This matters because the TCP payload starts AFTER the TCP header.
 * If this length is wrong, payload parsing will be wrong.
 */
static uint8_t getTcpHeaderLengthBytes(tcpHeader *tcp)
{
    return (uint8_t)((ntohs(tcp->offsetFields) >> OFS_SHIFT) * 4);
}

/*
 * Extracts the TCP flags field.
 *
 * The lower bits of offsetFields contain flags such as:
 * SYN, ACK, FIN, RST, PSH
 *
 * We mask with 0x01FF to keep only the 9 TCP flag bits.
 */
static uint16_t getTcpFlags(tcpHeader *tcp)
{
    return (uint16_t)(ntohs(tcp->offsetFields) & 0x01FF);
}

/*
 * Returns total TCP segment length = TCP header + TCP payload.
 *
 * IP total length includes:
 *   IP header + TCP header + TCP payload
 *
 * So:
 *   TCP segment length = IP total length - IP header length
 *
 * This value is useful for checksum and validation.
 */
static uint16_t getTcpSegmentLength(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint16_t ipLength = ntohs(ip->length);
    uint16_t ipHeaderLength = ip->size * 4;

    return ipLength - ipHeaderLength;
}

/*
 * Returns only the TCP payload length (no TCP header).
 *
 * This is:
 *   payload = total TCP segment length - TCP header length
 *
 * We need payload length to:
 * 1. know if data was received
 * 2. update ACK number correctly
 *
 * If payload length is wrong, the receiver and sender get out of sync.
 */
static uint16_t getTcpPayloadLength(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;

    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    uint16_t tcpSegmentLength = ntohs(ip->length) - ipHeaderLength;
    uint16_t tcpHeaderLength = getTcpHeaderLengthBytes(tcp);

    // If header length is bigger than the TCP segment itself,
    // this is invalid, so return 0.
    if (tcpSegmentLength < tcpHeaderLength)
        return 0;

    return tcpSegmentLength - tcpHeaderLength;
}

/*
 * Returns a pointer to the start of TCP payload data.
 *
 * This is the first byte AFTER the TCP header.
 *
 * Later this will be useful for application protocols like MQTT,
 * since MQTT data is carried inside the TCP payload.
 */
static uint8_t *getTcpPayload(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;

    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
    uint8_t tcpHeaderLength = getTcpHeaderLengthBytes(tcp);

    return ((uint8_t*)tcp + tcpHeaderLength);
}

/*
 * Returns how much TCP sequence space this packet consumes.
 *
 * TCP sequence numbers advance by:
 * - 1 for SYN
 * - 1 for FIN
 * - N for N bytes of payload
 *
 * This helper is useful when figuring out how far to advance ACK.
 */
static uint32_t tcpControlLength(tcpHeader *tcp, uint16_t payloadLength)
{
    uint16_t flags = getTcpFlags(tcp);
    uint32_t amount = payloadLength;

    if (flags & SYN) amount++;
    if (flags & FIN) amount++;

    return amount;
}

/*
 * Adds the TCP pseudo-header into the checksum sum.
 *
 * TCP checksum includes more than just the TCP bytes.
 * It also includes:
 * - source IP
 * - destination IP
 * - protocol
 * - TCP length
 *
 * This is required by the TCP standard.
 */
static void sumTcpPseudoHeader(ipHeader *ip, uint16_t tcpLength, uint32_t *sum)
{
    sumIpWords(ip->sourceIp, 4, sum);
    sumIpWords(ip->destIp, 4, sum);

    // Reserved byte + protocol byte
    *sum += 0;
    *sum += PROTOCOL_TCP << 8;

    // TCP length added as two bytes
    *sum += (tcpLength & 0x00FF) << 8;
    *sum += (tcpLength & 0xFF00) >> 8;
}

/*
 * Calculates TCP checksum for a packet.
 *
 * Steps:
 * 1. Clear the checksum field
 * 2. Sum the pseudo-header
 * 3. Sum the TCP header and payload
 * 4. Return final 16-bit checksum
 *
 * This is used both when:
 * - verifying received packets
 * - creating packets to send
 */
static uint16_t calcTcpChecksum(ipHeader *ip, tcpHeader *tcp, uint16_t tcpLength)
{
    uint32_t sum = 0;

    // Checksum field must be zero while calculating
    tcp->checksum = 0;

    sumTcpPseudoHeader(ip, tcpLength, &sum);
    sumIpWords(tcp, tcpLength, &sum);

    return getIpChecksum(sum);
}

/*
 * Compares two IP addresses.
 *
 * Returns true if they are exactly the same.
 * Used to match incoming packets to an existing socket.
 */
static bool isIpAddressMatch(const uint8_t a[4], const uint8_t b[4])
{
    return memcmp(a, b, 4) == 0;
}

/*
 * Compares two MAC addresses.
 *
 * Returns true if they are exactly the same.
 * Included as a helper for hardware-layer matching.
 */
static bool isHwAddressMatch(const uint8_t a[6], const uint8_t b[6])
{
    return memcmp(a, b, 6) == 0;
}

/*
 * Finds an existing socket that matches this incoming TCP packet.
 *
 * A TCP connection is identified by:
 * - local port
 * - remote port
 * - remote IP
 *
 * If a matching active socket is found, return pointer to it.
 * Otherwise return NULL.
 */
static socket *findSocketByTuple(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;

    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    uint16_t srcPort = ntohs(tcp->sourcePort);
    uint16_t dstPort = ntohs(tcp->destPort);

    uint8_t i;

    for (i = 0; i < MAX_TCP_SOCKETS; i++)
    {
        if (sockets[i].state != TCP_CLOSED &&
            sockets[i].localPort == dstPort &&
            sockets[i].remotePort == srcPort &&
            isIpAddressMatch(sockets[i].remoteIpAddress, ip->sourceIp))
        {
            return &sockets[i];
        }
    }

    return NULL;
}

/*
 * Finds a listening socket that matches the destination port
 * of an incoming TCP packet.
 *
 * This is used when a SYN arrives for a port that the device
 * is listening on.
 */
static socket *findListeningSocket(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;

    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    uint16_t dstPort = ntohs(tcp->destPort);

    uint8_t i;

    for (i = 0; i < MAX_TCP_SOCKETS; i++)
    {
        if (sockets[i].state == TCP_LISTEN &&
            sockets[i].localPort == dstPort)
        {
            return &sockets[i];
        }
    }

    return NULL;
}

/*
 * Allocates a new socket for an incoming TCP connection.
 *
 * This is typically called when a SYN arrives on an open port.
 *
 * The new socket is filled in with:
 * - remote IP
 * - remote port
 * - remote MAC
 * - local port
 *
 * based on the incoming packet.
 */
static socket *allocateSocketFromIncomingTcp(etherHeader *ether)
{
    socket *s = newSocket();

    if (s != NULL)
    {
        memset(s, 0, sizeof(socket));
        getSocketInfoFromTcpPacket(ether, s);
    }

    return s;
}


// ------------------------------------------------------------------------------
// State access
// ------------------------------------------------------------------------------

/*
 * Stores TCP state for a given listening-port instance.
 *
 * This array is separate from per-socket state.
 * It can be used to remember the state associated with each
 * registered TCP port entry.
 */
void setTcpState(uint8_t instance, uint8_t state)
{
    tcpState[instance] = state;
}

/*
 * Returns stored TCP state for a given listening-port instance.
 */
uint8_t getTcpState(uint8_t instance)
{
    return tcpState[instance];
}
// ------------------------------------------------------------------------------
// Packet classifiers
// ------------------------------------------------------------------------------

/*
 * Determines whether an incoming Ethernet frame contains a valid TCP packet.
 *
 * Checks:
 * 1. Ethernet frame must contain IP
 * 2. IP protocol field must say TCP
 * 3. TCP checksum must be correct
 *
 * Returns true only if all checks pass.
 */
bool isTcp(etherHeader* ether)
{
    ipHeader *ip;
    tcpHeader *tcp;
    uint8_t ipHeaderLength;
    uint16_t tcpLength;
    uint16_t rxChecksum;
    uint16_t calc;

    // Must be an IP packet first
    if (!isIp(ether))
        return false;

    ip = (ipHeader*)ether->data;

    // IP protocol must be TCP
    if (ip->protocol != PROTOCOL_TCP)
        return false;

    // Find TCP header
    ipHeaderLength = ip->size * 4;
    tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    // Total TCP bytes = IP total length - IP header length
    tcpLength = ntohs(ip->length) - ipHeaderLength;

    // Save received checksum
    rxChecksum = tcp->checksum;

    // Recalculate checksum
    calc = calcTcpChecksum(ip, tcp, tcpLength);

    // Restore original checksum field
    tcp->checksum = rxChecksum;

    return (calc == rxChecksum);
}

/*
 * Returns true if the packet is valid TCP and has SYN set.
 *
 * SYN is used to begin a TCP connection.
 */
bool isTcpSyn(etherHeader *ether)
{
    ipHeader *ip;
    tcpHeader *tcp;
    uint8_t ipHeaderLength;
    uint16_t flags;

    if (!isTcp(ether))
        return false;

    ip = (ipHeader*)ether->data;
    ipHeaderLength = ip->size * 4;
    tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    flags = getTcpFlags(tcp);

    return ((flags & SYN) != 0);
}

/*
 * Returns true if the packet is valid TCP and has ACK set.
 *
 * ACK is used throughout TCP to acknowledge received sequence numbers.
 */
bool isTcpAck(etherHeader *ether)
{
    ipHeader *ip;
    tcpHeader *tcp;
    uint8_t ipHeaderLength;
    uint16_t flags;

    if (!isTcp(ether))
        return false;

    ip = (ipHeader*)ether->data;
    ipHeaderLength = ip->size * 4;
    tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    flags = getTcpFlags(tcp);

    return ((flags & ACK) != 0);
}

// ------------------------------------------------------------------------------
// Port list
// ------------------------------------------------------------------------------

/*
 * Configures which TCP ports this device is listening on.
 *
 * For each port:
 * - store it in tcpPorts[]
 * - mark its state as TCP_LISTEN
 * - allocate a listening socket
 *
 * This supports passive-open behavior:
 * the board sits in LISTEN until a remote device sends SYN.
 */
void setTcpPortList(uint16_t ports[], uint8_t count)
{
    uint8_t i;

    if (count > MAX_TCP_PORTS)
        count = MAX_TCP_PORTS;

    tcpPortCount = count;

    for (i = 0; i < count; i++)
    {
        tcpPorts[i] = ports[i];
        tcpState[i] = TCP_LISTEN;
    }

    // Create listening sockets for the configured ports
    for (i = 0; i < count; i++)
    {
        socket *s = newSocket();
        if (s != NULL)
        {
            memset(s, 0, sizeof(socket));
            s->localPort = ports[i];
            s->state = TCP_LISTEN;
        }
    }
}

/*
 * Returns true if the destination port of the incoming packet
 * matches one of the open TCP ports for this device.
 *
 * Used by main loop to decide whether to process packet or reject it.
 */
bool isTcpPortOpen(etherHeader *ether)
{
    ipHeader *ip;
    tcpHeader *tcp;
    uint8_t ipHeaderLength;
    uint16_t dstPort;
    uint8_t i;

    if (!isTcp(ether))
        return false;

    ip = (ipHeader*)ether->data;
    ipHeaderLength = ip->size * 4;
    tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    dstPort = ntohs(tcp->destPort);

    for (i = 0; i < tcpPortCount; i++)
    {
        if (tcpPorts[i] == dstPort)
            return true;
    }

    return false;
}

// ------------------------------------------------------------------------------
// TCP transmit
// ------------------------------------------------------------------------------

/*
 * Sends a TCP response with no payload.
 *
 * This is a convenience wrapper around sendTcpMessage().
 * Used for control packets such as:
 * - ACK
 * - SYN+ACK
 * - FIN+ACK
 * - ACK+RST
 */
void sendTcpResponse(etherHeader *ether, socket* s, uint16_t flags)
{
    sendTcpMessage(ether, s, flags, NULL, 0);
}

/*
 * Builds and sends an outgoing TCP packet.
 *
 * This function creates:
 * - Ethernet header
 * - IP header
 * - TCP header
 * - optional TCP payload
 *
 * It then calculates TCP checksum and transmits the frame.
 *
 * The function also updates local sequence number after sending:
 * - +1 if SYN sent
 * - +1 if FIN sent
 * - +dataSize if payload sent
 */
void sendTcpMessage(etherHeader *ether, socket *s, uint16_t flags, uint8_t data[], uint16_t dataSize)
{
    ipHeader *rxIp;
    tcpHeader *rxTcp;
    ipHeader *txIp;
    tcpHeader *txTcp;
    uint8_t ipHeaderLength;
    uint8_t localMac[6];
    uint8_t localIp[4];
    uint16_t tcpHeaderLength = 20;
    uint16_t tcpLength = tcpHeaderLength + dataSize;
    uint16_t ipLength = 20 + tcpLength;
    uint16_t frameLength = 14 + ipLength;
    uint8_t i;

    // Get this device's MAC and IP
    getEtherMacAddress(localMac);
    getIpAddress(localIp);

    if (ether == NULL || s == NULL)
        return;

    // Reference incoming packet info if needed
    rxIp = (ipHeader*)ether->data;
    ipHeaderLength = rxIp->size * 4;
    rxTcp = (tcpHeader*)((uint8_t*)rxIp + ipHeaderLength);

    // Build Ethernet header
    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        ether->destAddress[i] = s->remoteHwAddress[i];
        ether->sourceAddress[i] = localMac[i];
    }
    ether->frameType = htons(TYPE_IP);

    // Build IP header
    txIp = (ipHeader*)ether->data;
    txIp->rev = 4;
    txIp->size = 5;                  // no IP options, so 20-byte IP header
    txIp->typeOfService = 0;
    txIp->length = htons(ipLength);
    txIp->id = 0;
    txIp->flagsAndOffset = 0;
    txIp->ttl = 64;
    txIp->protocol = PROTOCOL_TCP;
    txIp->headerChecksum = 0;

    for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        txIp->sourceIp[i] = localIp[i];
        txIp->destIp[i] = s->remoteIpAddress[i];
    }

    // Calculate IP header checksum
    calcIpChecksum(txIp);

    // Build TCP header
    txTcp = (tcpHeader*)((uint8_t*)txIp + 20);
    txTcp->sourcePort = htons(s->localPort);
    txTcp->destPort = htons(s->remotePort);
    txTcp->sequenceNumber = htonl(s->sequenceNumber);
    txTcp->acknowledgementNumber = htonl(s->acknowledgementNumber);
    txTcp->offsetFields = htons((5 << OFS_SHIFT) | (flags & 0x01FF));
    txTcp->windowSize = htons(TCP_WINDOW_SIZE);
    txTcp->checksum = 0;
    txTcp->urgentPointer = 0;

    // Copy payload if present
    if (dataSize > 0 && data != NULL)
        memcpy(txTcp->data, data, dataSize);

    // Calculate TCP checksum
    txTcp->checksum = calcTcpChecksum(txIp, txTcp, tcpLength);

    // Send packet out on Ethernet
    putEtherPacket(ether, frameLength);

    // Advance local sequence number for anything we sent
    if ((flags & SYN) != 0)
        s->sequenceNumber++;

    if ((flags & FIN) != 0)
        s->sequenceNumber++;

    s->sequenceNumber += dataSize;
}

// ------------------------------------------------------------------------------
// Pending transmissions
// ------------------------------------------------------------------------------

/*
 * Placeholder for future queued TCP transmissions.
 *
 * Right now the repo does not yet have a TCP send queue
 * or active-open request queue.
 *
 * Later this function can be used for:
 * - initiating outgoing TCP client connections
 * - sending queued payload data
 * - retransmissions
 */
void sendTcpPendingMessages(etherHeader *ether)
{
    (void)ether;
}

// ------------------------------------------------------------------------------
// ARP callback hook
// ------------------------------------------------------------------------------

/*
 * Placeholder for future TCP behavior tied to ARP resolution.
 *
 * For example, if later you add active TCP connect for MQTT,
 * this function can be used to react once ARP learns the broker MAC.
 */
void processTcpArpResponse(etherHeader *ether)
{
    (void)ether;
}

// ------------------------------------------------------------------------------
// Receive processing
// ------------------------------------------------------------------------------

/*
 * Main TCP state machine.
 *
 * This function processes every valid incoming TCP packet and decides:
 * - is it for an existing socket?
 * - is it a new SYN for an open listening port?
 * - does it complete a handshake?
 * - does it carry payload that needs ACK?
 * - is it closing the connection?
 *
 * This is the core of TCP behavior in the file.
 */
void processTcpResponse(etherHeader *ether)
{
    ipHeader *ip;
    tcpHeader *tcp;
    socket *s;
    uint8_t ipHeaderLength;
    uint16_t flags;
    uint16_t payloadLength;
    uint32_t seq;
    uint32_t ack;

    // Ignore anything that is not valid TCP
    if (!isTcp(ether))
        return;

    // Locate IP and TCP headers
    ip = (ipHeader*)ether->data;
    ipHeaderLength = ip->size * 4;
    tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    // Extract useful packet fields
    flags = getTcpFlags(tcp);
    payloadLength = getTcpPayloadLength(ether);
    seq = ntohl(tcp->sequenceNumber);
    ack = ntohl(tcp->acknowledgementNumber);

    // First, try to find an existing socket that matches this connection
    s = findSocketByTuple(ether);

    // If no existing socket is found, check if this is a new SYN
    // for one of our open listening ports
    if (s == NULL && (flags & SYN) && isTcpPortOpen(ether))
    {
        socket *listenSock = findListeningSocket(ether);
        if (listenSock != NULL)
        {
            s = allocateSocketFromIncomingTcp(ether);
            if (s != NULL)
            {
                // Move new socket into SYN_RECEIVED state
                s->state = TCP_SYN_RECEIVED;

                // Choose a simple local initial sequence number
                s->sequenceNumber = 0x1000;

                // ACK should expect the next byte after SYN
                s->acknowledgementNumber = seq + 1;

                // Reply with SYN+ACK
                sendTcpResponse(ether, s, SYN | ACK);
            }
        }
        return;
    }

    // If no valid socket exists, ignore this packet
    if (s == NULL)
        return;

    // Process packet based on socket state
    switch (s->state)
    {
        case TCP_LISTEN:
        {
            // In LISTEN, wait for SYN
            if (flags & SYN)
            {
                s->state = TCP_SYN_RECEIVED;
                s->sequenceNumber = 0x1000;
                s->acknowledgementNumber = seq + 1;

                // Reply with SYN+ACK
                sendTcpResponse(ether, s, SYN | ACK);
            }
            break;
        }

        case TCP_SYN_RECEIVED:
        {
            // Waiting for final ACK of handshake
            if ((flags & ACK) && ack == s->sequenceNumber)
            {
                s->state = TCP_ESTABLISHED;
            }
            break;
        }

        case TCP_SYN_SENT:
        {
            // Client-side state:
            // we already sent SYN and are waiting for SYN+ACK
            if ((flags & SYN) && (flags & ACK))
            {
                s->acknowledgementNumber = seq + 1;

                // Send final ACK of handshake
                sendTcpResponse(ether, s, ACK);

                s->state = TCP_ESTABLISHED;
            }
            break;
        }

        case TCP_ESTABLISHED:
        {
            uint32_t segLen = tcpControlLength(tcp, payloadLength);

            if (segLen > 0)
            {
                s->acknowledgementNumber = seq + segLen;
                sendTcpResponse(ether, s, ACK);
            }

            if (flags & FIN)
                s->state = TCP_CLOSE_WAIT;

            break;
        }

        case TCP_CLOSE_WAIT:
        {
            // Passive close:
            // peer already sent FIN, and we ACKed it.
            // Now send our own FIN+ACK to finish closing.
            sendTcpResponse(ether, s, FIN | ACK);
            s->state = TCP_LAST_ACK;
            break;
        }

        case TCP_LAST_ACK:
        {
            // Waiting for final ACK of our FIN
            if (flags & ACK)
            {
                s->state = TCP_CLOSED;
            }
            break;
        }

        case TCP_FIN_WAIT_1:
        {
            // We initiated close and already sent FIN

            if (flags & ACK)
                s->state = TCP_FIN_WAIT_2;

            if (flags & FIN)
            {
                s->acknowledgementNumber = seq + 1;
                sendTcpResponse(ether, s, ACK);
                s->state = TCP_TIME_WAIT;
            }
            break;
        }

        case TCP_FIN_WAIT_2:
        {
            // Waiting for peer FIN
            if (flags & FIN)
            {
                s->acknowledgementNumber = seq + 1;
                sendTcpResponse(ether, s, ACK);
                s->state = TCP_TIME_WAIT;
            }
            break;
        }

        case TCP_TIME_WAIT:
        {
            // Minimal implementation:
            // close immediately instead of waiting 2*MSL
            s->state = TCP_CLOSED;
            break;
        }

        default:
            break;
    }
}
