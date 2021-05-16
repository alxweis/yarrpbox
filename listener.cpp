/****************************************************************************
   Program:     $Id: listener.cpp 40 2016-01-02 18:54:39Z rbeverly $
   Date:        $Date: 2016-01-02 10:54:39 -0800 (Sat, 02 Jan 2016) $
   Description: yarrp listener thread
****************************************************************************/
#include "yarrp.h"
#include <signal.h>
#include <options.h>
static volatile bool run = true;

void intHandler(int dummy) {
    run = false;
}

void           *
listener(void *args) {
    fd_set rfds;
    Traceroute *trace = reinterpret_cast < Traceroute * >(args);
    struct timeval timeout;
    unsigned char buf[PKTSIZE];
    uint32_t nullreads = 0;
    int n, len;
    TTLHisto *ttlhisto = NULL;
    uint32_t elapsed = 0;
    struct ip *ip = NULL;
    struct icmp *ippayload = NULL;
    int rcvsock; /* receive (icmp) socket file descriptor */

    /* block until main thread says we're ready. */
    trace->lock(); 
    trace->unlock(); 

    if ((rcvsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        cerr << "yarrp listener socket error:" << strerror(errno) << endl;
    }

    while (true) {
        if (nullreads >= MAXNULLREADS)
            break;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        FD_ZERO(&rfds);
        FD_SET(rcvsock, &rfds);
        n = select(rcvsock + 1, &rfds, NULL, NULL, &timeout);
        /* only timeout if we're also probing (not listen-only mode) */
        if ((n == 0) and (trace->config->probe)) {
            nullreads++;
            cerr << ">> Listener: timeout " << nullreads;
            cerr << "/" << MAXNULLREADS << endl;
            continue;
        }
        if (n > 0) {
            nullreads = 0;
            len = recv(rcvsock, buf, PKTSIZE, 0);
            if (len == -1) {
                cerr << ">> Listener: read error: " << strerror(errno) << endl;
                continue;
            }
            ip = (struct ip *)buf;
            if ((ip->ip_v == IPVERSION) and (ip->ip_p == IPPROTO_ICMP)) {
                ippayload = (struct icmp *)&buf[ip->ip_hl << 2];
                elapsed = trace->elapsed();

                uint16_t packetSize = ntohs(ip->ip_len);
                unsigned char *ptr = (unsigned char *) ippayload;
                struct ip *quotation = (struct ip *) (ptr + 8); // 8 bytes for icmp header
                uint16_t icmpPayloadSize = packetSize - ((ip->ip_hl<<2) + 8);
                uint16_t  probesize = ntohs(quotation->ip_len);
                uint16_t tcpQuotesize = icmpPayloadSize - (sizeof(struct ip)); // Actual size of TCP portion seen in quote

                bool partialQuote = false;
                unsigned char * tmp = (unsigned char *) quotation;
                struct tcphdr_options *tcp_op = (struct tcphdr_options *) (ptr + 8 + (quotation->ip_hl << 2));
                uint16_t indicatedTcpQuoteSize = (tcp_op->tcp.th_off << 2); 
                
                /* Partial quote if 20 bytes of IP header + first 8 of TCP header, 
                   Also partial quote if size smaller than the full quote size & tcp offset unmodified 
                   Third condidtion to address 28 byte partial quotes that are immediately followed by mpls ext. */
                if(trace->config->midbox_detection && (icmpPayloadSize <= 28 || icmpPayloadSize < probesize || (icmpPayloadSize > 28 && tcp_op->tcp.th_off == 0))) {
                    struct in_addr hop; // Source from which partial quote received
                    char src[INET_ADDRSTRLEN]; 
                    uint8_t hop_ttl;

                    char target[INET_ADDRSTRLEN]; 
                    memset(&hop, 0, sizeof(struct in_addr));
                    hop = ip->ip_src;
                    hop_ttl = (ntohs(quotation->ip_id)) & 0xFF;

                    inet_ntop(AF_INET, &hop, src, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &(quotation->ip_dst), target, INET_ADDRSTRLEN);
                       
                    if (tcp_op->tcp.th_off == 0 && icmpPayloadSize > 28 ){
                        debug(DEBUG, "        TCP Offset:0  ");
                        debug(DEBUG, "        Quote size:  " << icmpPayloadSize);
                    }
                       
                    uint8_t expectedOffset = 0;
                    if(trace->config->wScale == 0)
                        expectedOffset = 12;
                    else
                        expectedOffset = 13;

                    if(icmpPayloadSize <= 28 || (tcp_op->tcp.th_off == expectedOffset) || (tcp_op->tcp.th_off != expectedOffset && indicatedTcpQuoteSize > tcpQuotesize) || (icmpPayloadSize > 28 && tcp_op->tcp.th_off == 0)){ 
                        partialQuote = true;
                    }
                }

                ICMP *icmp = new ICMP4(ip, ippayload, elapsed, trace->config->coarse, partialQuote, trace);                       
        
                if (verbosity > LOW) 
                    icmp->print();
                /* ICMP message not from this yarrp instance, skip. */
                if (icmp->getInstance() != trace->config->instance) {
                    if (verbosity > HIGH)
                        cerr << ">> Listener: packet instance mismatch." << endl;
                    trace->stats->badIpid+=1;    
                    delete icmp;
                    continue;
                }
                if ((icmp->getSport() == 0) && trace->config->midbox_detection) {
                    trace->stats->badResp+=1;
                    delete icmp;
                    continue;
                }
                else if (icmp->getSport() == 0)
                    trace->stats->badResp+=1; 
                   
                /* Fill mode logic. */
                if (trace->config->fillmode) {
                    if ( (icmp->getTTL() >= trace->config->maxttl) and
                         (icmp->getTTL() <= trace->config->fillmode) ) {
                        trace->stats->fills+=1;
                        trace->probe(icmp->quoteDst(), icmp->getTTL() + 1); 
                    }
                }
    
                icmp->write(&(trace->config->out), trace->stats->count, quotation, icmpPayloadSize, NULL);
#if 0
                Status *status = NULL;
                if (trace->tree != NULL) 
                    status = (Status *) trace->tree->get(icmp->quoteDst());
                if (status) {
                    status->result(icmp->quoteTTL(), elapsed);
                }
#endif
                /* TTL tree histogram */
                if (trace->ttlhisto.size() > icmp->quoteTTL()) {
                    /* make certain we received a valid reply before adding  */
                    if ( (icmp->getSport() != 0) and 
                         (icmp->getDport() != 0) ) 
                    {
                        ttlhisto = trace->ttlhisto[icmp->quoteTTL()];
                        ttlhisto->add(icmp->getSrc(), elapsed);
                    }
                }
                if (verbosity > DEBUG) 
                    trace->dumpHisto();
                delete icmp;
            }
        }
    }
    return NULL;
}
