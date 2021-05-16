/****************************************************************************
   Program:     $Id: listener.cpp 40 2016-01-02 18:54:39Z rbeverly $
   Date:        $Date: 2016-01-02 10:54:39 -0800 (Sat, 02 Jan 2016) $
   Description: yarrp listener thread
****************************************************************************/
#include "yarrp.h"
#include <signal.h>
#include <options.h>

static volatile bool run = true;
void intHandler(int dummy);

#ifndef _LINUX
int bpfinit(char *dev, size_t *bpflen) {
    int rcvsock = -1;

    debug(DEVELOP, ">> Listener6 BPF");
    rcvsock = bpfget();
    if (rcvsock < 0) fatal("bpf open error\n");
    struct ifreq bound_if;
    strcpy(bound_if.ifr_name, dev);
    if (ioctl(rcvsock, BIOCSETIF, &bound_if) > 0) fatal("ioctl err\n");
    uint32_t enable = 1;
    if (ioctl(rcvsock, BIOCSHDRCMPLT, &enable) <0) fatal("ioctl err\n");
    if (ioctl(rcvsock, BIOCIMMEDIATE, &enable) <0) fatal("ioctl err\n");
    struct bpf_program fcode = {0};
    struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IPV6, 0, 3),
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 20),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_ICMPV6, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, (u_int)-1),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };
    fcode.bf_len = sizeof(insns) / sizeof(struct bpf_insn);
    fcode.bf_insns = &insns[0];
    if(ioctl(rcvsock, BIOCSETF, &fcode) < 0) fatal("set filter\n");
    ioctl(rcvsock, BIOCGBLEN, bpflen);
    return rcvsock;
}
#endif

void *listener6(void *args) {
    fd_set rfds;
    Traceroute6 *trace = reinterpret_cast < Traceroute6 * >(args); 
    struct timeval timeout;
    unsigned char *buf = (unsigned char *) calloc(1,PKTSIZE);
    /*unsigned char *buf = NULL;
    buf = (unsigned char *) calloc(1,PKTSIZE);*/
    uint32_t nullreads = 0;
    int n, len;
    TTLHisto *ttlhisto = NULL;
    uint32_t elapsed = 0;
    struct ip6_hdr *ip = NULL;                /* IPv6 hdr */
    struct icmp6_hdr *ippayload = NULL;       /* ICMP6 hdr */
    int rcvsock;                              /* receive (icmp) socket file descriptor */

    /* block until main thread says we're ready. */
    trace->lock(); 
    trace->unlock(); 

#ifdef _LINUX
    if ((rcvsock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        cerr << "yarrp listener socket error:" << strerror(errno) << endl;
    }
#else
    /* Init BPF */
    size_t blen = 0;
    rcvsock = bpfinit(trace->config->int_name, &blen);
    unsigned char *bpfbuf = (unsigned char *) calloc(1,blen);
    struct bpf_hdr *bh = NULL;
#endif

    signal(SIGINT, intHandler);
    while (true and run) {
        buf = (unsigned char *) calloc(1,PKTSIZE);
        
        if (nullreads >= MAXNULLREADS)
            break;
#ifdef _LINUX
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        FD_ZERO(&rfds);
        FD_SET(rcvsock, &rfds);
        n = select(rcvsock + 1, &rfds, NULL, NULL, &timeout);
        if (n == 0) {
            nullreads++;
            cerr << ">> Listener: timeout " << nullreads;
            cerr << "/" << MAXNULLREADS << endl;
            continue;
        }
	if (n == -1) {
            fatal("select error");
        }
        nullreads = 0;
        len = recv(rcvsock, buf, PKTSIZE, 0); 
#else
        len = read(rcvsock, bpfbuf, blen);
	unsigned char *p = bpfbuf;
reloop:
        bh = (struct bpf_hdr *)p;
	buf = p + bh->bh_hdrlen;  /* realign buf */
#endif
        if (len == -1) {
            fatal("%s %s", __func__, strerror(errno));
        }
        ip = (struct ip6_hdr *)(buf + ETH_HDRLEN);
        if (ip->ip6_nxt == IPPROTO_ICMPV6) {
            ippayload = (struct icmp6_hdr *)&buf[ETH_HDRLEN + sizeof(struct ip6_hdr)];
            elapsed = trace->elapsed();
            if ( (ippayload->icmp6_type == ICMP6_TIME_EXCEEDED) or
                 (ippayload->icmp6_type == ICMP6_DST_UNREACH) or
                 (ippayload->icmp6_type == ICMP6_ECHO_REPLY) ) {
                bool partialQuote = false;
                uint16_t quoteSize = ntohs(ip->ip6_plen) - (sizeof(struct icmp6_hdr)); 
                if(trace->config->midbox_detection && (trace->config->type == TR_TCP6_SYN || trace->config->type == TR_TCP6_ACK)) {
                    uint16_t replySize = ntohs(ip->ip6_plen); // external ipv6 header excluded
                    // Full quote with external IP header excluded
                    uint16_t fullQuoteSize = (sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr_options) + sizeof(struct ypayload));
                    unsigned char *ptr = (unsigned char *) ippayload;
                    struct tcphdr_options *tcp_op = (struct tcphdr_options *) (ptr + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr));
                    if(replySize < fullQuoteSize && (tcp_op->tcp.th_off == 12)) {
                        trace->stats->v6PartialQuote+=1;
                        partialQuote = true;
                        //continue;
                    }
                    // For a partial quote, there will be no payload, so don't worry about it
                    // If payload present then it is not a partial quote and then calculated tcpquotesize would be larger than indicated and response would not be classified as partial quote
                    uint16_t tcpQuotesize = replySize - (sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr));
                    uint16_t indicatedTcpQuoteSize = (tcp_op->tcp.th_off << 2);
                    if(replySize < fullQuoteSize && (tcp_op->tcp.th_off != 12 && indicatedTcpQuoteSize > tcpQuotesize)) {
                        trace->stats->v6PartialQuote+=1;
                        debug(DEVELOP, "        Partial Quote case 3");
                        partialQuote = true;
                        //continue;
                    }
                }  
                ICMP *icmp = new ICMP6(ip, ippayload, elapsed, trace->config->coarse, partialQuote, trace);
                
                if(icmp->echoReply){
                   trace->stats->v6EchoReply+=1;
                }
                if (icmp->getSport() == 0 && !icmp->echoReply && trace->config->midbox_detection){ 
                    trace->stats->badResp+=1;    
                    delete icmp;
                    continue;
                }
                
                if (icmp->is_yarrp) { 
                    debug(DEVELOP, "        Listener.cpp: is_yarrp: " << icmp->is_yarrp << endl);
                    
                    if (verbosity > LOW)
                        icmp->print();
                    
                    if (icmp->getSport() == 0) {
                         trace->stats->badResp+=1; 
                         //trace->stats->baddst+=1;
                    } 
                      
                    /* Fill mode logic. */
                    if (trace->config->fillmode) {
                        if ( (icmp->getTTL() >= trace->config->maxttl) and
                          (icmp->getTTL() < trace->config->fillmode) ) {
                         trace->stats->fills+=1;
                         trace->probe(icmp->quoteDst6(), icmp->getTTL() + 1); 
                        }
                    }
                    icmp->write(&(trace->config->out), trace->stats->count, NULL, quoteSize, NULL);
                    /* TTL tree histogram */
                    if (trace->ttlhisto.size() > icmp->quoteTTL()) {
                     ttlhisto = trace->ttlhisto[icmp->quoteTTL()];
                     ttlhisto->add(icmp->getSrc6(), elapsed);
                    }
                    if (verbosity > DEBUG)
                     trace->dumpHisto();
                }
                delete icmp;
            }
        } 
#ifndef _LINUX
	p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
	if (p < bpfbuf + len) goto reloop;
#endif

    free(buf);
    }
    return NULL;
}
