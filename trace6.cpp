/****************************************************************************
   Program:     $Id: trace.cpp 39 2015-12-30 20:28:36Z rbeverly $
   Date:        $Date: 2015-12-30 12:28:36 -0800 (Wed, 30 Dec 2015) $
   Description: traceroute class
****************************************************************************/
#include "yarrp.h"
#include "options.h"
#include "xxhash32.h"

uint16_t mssSet = 0;

Traceroute6::Traceroute6(YarrpConfig *_config, Stats *_stats) : Traceroute(_config, _stats) {
    memset(&source6, 0, sizeof(struct sockaddr_in6));
    if (config->probesrc) {
        source6.sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, config->probesrc, &source6.sin6_addr) != 1) // probesrc is a char array
          fatal("** Bad source address."); 
    } else {
        infer_my_ip6(&source6); // should already give ip as sockaddr_in6 
    }
    inet_ntop(AF_INET6, &source6.sin6_addr, addrstr, INET6_ADDRSTRLEN);
    config->set("SourceIP", addrstr, true);
#ifdef _LINUX
    sndsock = raw_sock6(&source6);
#else
    /* Init BPF socket */
    sndsock = bpfget();
    if (sndsock < 0) fatal("bpf open error\n");
    struct ifreq bound_if;
    strcpy(bound_if.ifr_name, config->int_name);
    if (ioctl(sndsock, BIOCSETIF, &bound_if) > 0) fatal("ioctl err\n");
#endif
    pcount = 0;

    assert(config);
    assert(config->srcmac);

    /* Set Ethernet header */
    frame = (uint8_t *)calloc(1, PKTSIZE); 
    memcpy (frame, config->dstmac, 6 * sizeof (uint8_t)); // Macs are 6 bytes
    memcpy (frame + 6, config->srcmac, 6 * sizeof (uint8_t)); 
    frame[12] = 0x86; /* IPv6 Ethertype */
    frame[13] = 0xdd; //ethertype is 2 byte and for ipv6 should be 0x86dd

    /* Set static IP6 header fields */
    outip = (struct ip6_hdr *) (frame + ETH_HDRLEN);
    //fl
    flow = config->flowLabel;
    outip->ip6_flow = htonl(0x6<<28|tc<<20|flow); 
    outip->ip6_src = source6.sin6_addr;

    /* Init yarrp payload struct */
    payload = (struct ypayload *)malloc(sizeof(struct ypayload));
    payload->id = htonl(0x79727036);
    payload->instance = config->instance;

    mssSet = config->mssData;
    
    if (config->probe and config->receive) {
        pthread_create(&recv_thread, NULL, listener6, this);
        /* give listener thread time to startup */
        sleep(1);
    }
}

Traceroute6::~Traceroute6() {
    free(frame);
}

void Traceroute6::probePrint(struct in6_addr addr, int ttl) {
    uint32_t diff = elapsed();
    inet_ntop(AF_INET6, &source6.sin6_addr, addrstr, INET6_ADDRSTRLEN);
    if (config->probesrc)
        cout << addrstr << " -> ";
    //inet_ntop(AF_INET6, &(outip->ip6_dst), addrstr, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &addr, addrstr, INET6_ADDRSTRLEN);
    cout << addrstr << " ttl: " << ttl << " t=" << diff;
    (config->coarse) ? cout << "ms" << endl : cout << "us" << endl;
}

void
Traceroute6::probe(struct in6_addr addr, int ttl) {
#ifdef _LINUX 
    struct sockaddr_ll target;
    memset(&target, 0, sizeof(target));
    target.sll_ifindex = if_nametoindex(config->int_name);
    target.sll_family = AF_PACKET;
    memcpy(target.sll_addr, config->srcmac, 6 * sizeof(uint8_t));
    target.sll_halen = 6;
    probe(&target, addr, ttl);
#else
    probe(NULL, addr, ttl);
#endif
}

void
Traceroute6::probe(void *target, struct in6_addr addr, int ttl) {
    outip->ip6_hlim = ttl; 
    outip->ip6_dst = addr;

    uint16_t ext_hdr_len = 0;
    uint16_t transport_hdr_len = 0;
    switch(config->type) {
      case TR_ICMP6:
        outip->ip6_nxt = IPPROTO_ICMPV6;
        transport_hdr_len = sizeof(struct icmp6_hdr);
        break;
      case TR_UDP6:
        outip->ip6_nxt = IPPROTO_UDP;
        transport_hdr_len = sizeof(struct udphdr);
        break;
      case TR_TCP6_SYN:
      case TR_TCP6_ACK:
        outip->ip6_nxt = IPPROTO_TCP;
        if(!config->midbox_detection) {
             transport_hdr_len = sizeof(struct tcphdr);
        } else {
            transport_hdr_len = sizeof(struct tcphdr_options);
        }   
        break;
      default:
        cerr << "** bad trace type" << endl;
        assert(false);
    } 

    /* Shim in an extension header? */
    if (config->v6_eh != 255) {
        uint8_t srh_hdr_lenFld = 0;
        if (config->v6_eh == 44) {
            make_frag_eh(outip->ip6_nxt);
        } else if(config->v6_eh == 43){
            srh_hdr_lenFld = make_srh_eh(outip->ip6_nxt, config->segment, config->ipv6Adds); 
        } else {
            make_hbh_eh(outip->ip6_nxt);
        }
        outip->ip6_nxt = config->v6_eh; 
        ext_hdr_len = 8;
        if (config->v6_eh == 43){
           ext_hdr_len = 8 + srh_hdr_lenFld * 8; 
        }
    }

    /* Populate a yarrp payload */
    payload->ttl = ttl;
    payload->fudge = 0;
    payload->target = addr;
    uint32_t diff = elapsed();
    payload->diff = diff; 
    payload->spHash = 0;
    payload->pHash = 0;
 
    if(config->midbox_detection) {
        uint16_t sum = in_cksum((unsigned short *)&(outip->ip6_dst), 16);
        string spHashInput = to_string(htons(sum)); 
        unsigned char *spHashBegin = (unsigned char *) spHashInput.c_str();
        payload->spHash = XXHash32::hash(spHashBegin, spHashInput.size(),0); 
    }

    // Calculate the hash over payload (excluding fudge)
    if(config->midbox_detection) {
       char dst[INET6_ADDRSTRLEN];
       inet_ntop(AF_INET6, &(outip->ip6_dst), dst, INET6_ADDRSTRLEN);
       string dstIP(dst);
       
       string pHashInput = to_string(payload->id) + dstIP + to_string(payload->instance) + to_string(payload->ttl)
                         + to_string(payload->diff) + to_string(payload->spHash); 
       unsigned char *pHashBegin = (unsigned char *) pHashInput.c_str();
       payload->pHash = XXHash32::hash(pHashBegin, pHashInput.size(),0); 
    }

    
    u_char *data = (u_char *)(frame + ETH_HDRLEN + sizeof(ip6_hdr) 
                              + ext_hdr_len + transport_hdr_len);
    memcpy(data, payload, sizeof(struct ypayload));

    /* Populate transport header */
    packlen = transport_hdr_len + sizeof(struct ypayload);
    make_transport(ext_hdr_len);
    /* Copy yarrp payload again, after changing fudge for cksum */
    memcpy(data, payload, sizeof(struct ypayload));
    outip->ip6_plen = htons(packlen + ext_hdr_len);
    config->ipv6PayloadLengthSet = packlen + ext_hdr_len;

    /* xmit frame */
    if (verbosity > HIGH) {
      cout << ">> " << Tr_Type_String[config->type] << " probe: ";
      probePrint(addr, ttl);
    }
    uint16_t framelen = ETH_HDRLEN + sizeof(ip6_hdr) + ext_hdr_len + packlen;
#ifdef _LINUX
    if (sendto(sndsock, frame, framelen, 0, (struct sockaddr *)target,
        sizeof(struct sockaddr_ll)) < 0)
    {
        fatal("%s: error: %s", __func__, strerror(errno));
    }
#else
    /* use the BPF to send */
    write(sndsock, frame, framelen);
#endif
    pcount++;
}

void
Traceroute6::make_frag_eh(uint8_t nxt) {
    void *transport = frame + ETH_HDRLEN + sizeof(ip6_hdr);
    struct ip6_frag *eh = (struct ip6_frag *) transport;
    eh->ip6f_nxt = nxt;  
    eh->ip6f_reserved = 0;
    eh->ip6f_offlg = 0;
    eh->ip6f_ident = 0x8008;
}

void
Traceroute6::make_hbh_eh(uint8_t nxt) {
    uint8_t *transport = frame + ETH_HDRLEN + sizeof(ip6_hdr);
    struct ip6_ext *eh = (struct ip6_ext *) transport;
    eh->ip6e_nxt = nxt;  
    eh->ip6e_len = 0;
    transport+=2;
    struct ip6_opt *opt = (struct ip6_opt *) transport;
    opt->ip6o_type = IP6OPT_PADN;
    opt->ip6o_len = 4;
    transport+=2;
    memset(transport, 0, 4);
}

uint8_t
Traceroute6::make_srh_eh(uint8_t nxt, const char *segment, std::vector<std::string> &ipv6Adds) {
    void *transport = frame + ETH_HDRLEN + sizeof(ip6_hdr);
    struct ip6_srhdr *eh = (struct ip6_srhdr *) transport;
    eh->ip6sr_nxt = nxt;
    eh->ip6sr_len = (sizeof(eh->ip6sr_seglist))/8;
    eh->ip6sr_type = 4;
    eh->ip6sr_segleft = 0;
    //eh->ip6sr_lastentry = 0; //0;
    eh->ip6sr_lastentry = ipv6Adds.size() - 1; //1//0;  
    eh->ip6sr_tag = 0;
    eh->ip6sr_flags = 0;

    /*if (inet_pton (AF_INET6, segment, &(eh->ip6sr_seglist[0])) != 1)
       fatal("**Bad IPv6 address/segment list element");*/

    struct in6_addr* tmp = (struct in6_addr*) malloc(sizeof(struct in6_addr) * ipv6Adds.size());
    eh->ip6sr_len = (sizeof(struct in6_addr) * ipv6Adds.size())/8;
    int i = 0;
    while(i<ipv6Adds.size()){
        if (inet_pton (AF_INET6, ipv6Adds[i].c_str(), (tmp)) != 1){
           fatal("**Bad IPv6 address/segment list element");
        }
        i++;
        if (i == ipv6Adds.size()){
           break;   
        }
        tmp++;
        //eh->ip6sr_seglist++;  
    }
    //tmp = tmp - 1;
    tmp  = tmp - (ipv6Adds.size() - 1);
    u_char* tmpr = (u_char*) eh;
    eh->ip6sr_seglist = tmpr + 8;
    memcpy(eh->ip6sr_seglist, tmp, sizeof(struct in6_addr) * ipv6Adds.size());   

    return eh->ip6sr_len;
}

void 
Traceroute6::make_transport(int ext_hdr_len) {
    void *transport = frame + ETH_HDRLEN + sizeof(ip6_hdr) + ext_hdr_len;
    uint16_t sum = in_cksum((unsigned short *)&(outip->ip6_dst), 16);
    if (config->type == TR_ICMP6) {
        struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)transport;
        icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
        //icmp6->icmp6_code = 0;
        icmp6->icmp6_code = ICMP6_CODE_SET;
        icmp6->icmp6_cksum = 0;
        icmp6->icmp6_id = htons(sum);
        if(!config->midbox_detection) {
           icmp6->icmp6_seq = htons(pcount); 
        } else {
           icmp6->icmp6_seq = htons(ICMP6_SEQUENCE_NUMBER_SET); 
           //icmp6->icmp6_seq = htons(1);   
        }
        icmp6->icmp6_cksum = p_cksum(outip, (u_short *) icmp6, packlen);
        
    } else if (config->type == TR_UDP6) {
        struct udphdr *udp = (struct udphdr *)transport;
        udp->uh_sport = htons(sum);
        udp->uh_dport = htons(dstport);
        udp->uh_ulen = htons(packlen);
        udp->uh_sum = 0;
        udp->uh_sum = p_cksum(outip, (u_short *) udp, packlen);
        /* set checksum for paris goodness */
        uint16_t crafted_cksum = htons(0xbeef);
        payload->fudge = compute_data(udp->uh_sum, crafted_cksum);
        udp->uh_sum = crafted_cksum;
    } else if (config->type == TR_TCP6_SYN || config->type == TR_TCP6_ACK) {
        if(!config->midbox_detection) {
            struct tcphdr *tcp = (struct tcphdr *)transport;
            tcp->th_sport = htons(sum);
            tcp->th_dport = htons(dstport);
            tcp->th_seq = htonl(1);
            tcp->th_off = 5;
            tcp->th_win = htons(65535);
            tcp->th_sum = 0;
            tcp->th_x2 = 0;
            tcp->th_flags = 0;
            tcp->th_urp = htons(0);
            if (config->type == TR_TCP6_SYN) {
               tcp->th_flags |= TH_SYN; 
            } else {
               tcp->th_flags |= TH_ACK; 
            }
           tcp->th_sum = p_cksum(outip, (u_short *) tcp, packlen);
           /* set checksum for paris goodness */
           uint16_t crafted_cksum = htons(0xbeef);
           payload->fudge = compute_data(tcp->th_sum, crafted_cksum);
           tcp->th_sum = crafted_cksum;
        } else {
            struct tcphdr_options *tcp_o = (struct tcphdr_options *)transport;
            tcp_o->tcp.th_sport = htons(sum);
            tcp_o->tcp.th_dport = htons(dstport);
            tcp_o->tcp.th_seq = htonl(TCP6_SEQUENCE_NUMBER_SET);
            tcp_o->tcp.th_off = 12;
            tcp_o->tcp.th_win = htons(TCP6_RCV_WINDOW_SET);
            tcp_o->tcp.th_sum = 0;
            tcp_o->tcp.th_x2 = TCP_RESERVED_SET;
            tcp_o->tcp.th_flags = 0;
            tcp_o->tcp.th_urp = htons(TCP6_URGENT_PTR_SET);
            if (config->type == TR_TCP6_SYN) {
               tcp_o->tcp.th_flags |= TH_SYN; 
            } else {
               tcp_o->tcp.th_flags |= TH_ACK;
            }
            
            tcp_o->th_mss.kind = TCPOPT_MSS; 
            tcp_o->th_mss.len  = TCPOLEN_MSS; 
            tcp_o->th_mss.data = htons(mssSet); 

            tcp_o->th_sackp.kind = TCPOPT_SACK_PERM; 
            tcp_o->th_sackp.len  = TCPOLEN_SACK_PERM; 

            tcp_o->th_mpc.kind = TCPOPT_MPTCP;
            tcp_o->th_mpc.len  = 12;
            tcp_o->th_mpc.flag = 0x01;
            tcp_o->th_mpc.sender_key = __bswap_64(MPCAPABLE_SENDER_KEY_SET);

            tcp_o->th_tmsp.kind = TCPOPT_TIMESTAMP; 
            tcp_o->th_tmsp.len  = TCPOLEN_TIMESTAMP; 
            tcp_o->th_tmsp.TSval = htonl(TCP6_TMSP_TSVAL_SET);
               
            tcp_o->tcp.th_sum = p_cksum(outip, (u_short *) tcp_o, packlen);
            uint16_t crafted_cksum = htons(0xbeef);
            payload->fudge = compute_data(tcp_o->tcp.th_sum, crafted_cksum);
            tcp_o->tcp.th_sum = crafted_cksum;
        }
    }
}

