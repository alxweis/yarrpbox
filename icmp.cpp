/****************************************************************************
   Program:     $Id: listener.cpp 40 2016-01-02 18:54:39Z rbeverly $
   Date:        $Date: 2016-01-02 10:54:39 -0800 (Sat, 02 Jan 2016) $
   Description: yarrp listener thread
****************************************************************************/
#include "yarrp.h"
#include "options.h"
#include "xxhash32.h"

ICMP::ICMP() : 
   rtt(0), ttl(0), type(0), code(0), length(0), quote_p(0), sport(0), dport(0), ipid(0),
   probesize(0), replysize(0), replyttl(0), replytos(0), q_tos(0), q_seq(0), detection(false), ipHashComp(0), ipHashExtr(0), tcpHashComp(0),
   tcpHashExtr(0), completeHashComp(0), completeHashExtr(0), ipMatch(true), tcpMatch(true), completeMatch(true), badSeqNo(false), TosModif(false), 
   pSizeModif(false), mssPresent(false), wsNotAdded(true), wsNotRemoved(true), tmspPresent(false), mpCapablePresent(false), sackpPresent(false), 
   eolNotPresent(true), nopNotPresent(true), mssData(0), mpCapableData(0), tmspTsval(0), wScaleObserved (0), goodMpCableData(true),
   goodMssData(true), goodTmspTsval(true), optOrderModif(false), firstOption(0), secondOption(0), thirdOption(0),fourthOption(0), pQ(false), wScale(0),
   fixSequenceNo(false), v6TcModif(false), v6FlowModif(false), v6PlenModif(false), v6DestModif(false), spModif(false), dpModif(false), UdpCksmModif(false),
   UdpLenModif(false), v6probeType(255), v4probeType(255), ipv6(false), icmpTypeModif(false), icmpCodeModif(false), icmpIdModif(false), icmpSeqModif(false),
   echoReply(false), mssSet(0), dPortSet(0), tcpChksmModif(false), tcpDpModif(false), tcpFlagsModif(false), tcpOffsetModif(false), tcpSpModif(false), 
   tcpUrgModif(false), tcpWindModif(false), tcpX2Modif(false), tcpSeqModif(false), tcpAckModif(false), qTosSet(0), qTosObserved(0), qTotalLengthSet(0), 
   qTotalLengthObserved(0), qDportSet(0), qDportObserved(0), qSeqSet(0), qSeqObserved(0), qAckSet(0), qAckObserved(0), qX2Set(0), qX2Observed(0), 
   qDoffSet(0), qDoffObserved(0), qflowLabelSet(0), qflowLabelObserved(0), qTrafficClassSet(0), qTrafficClassObserved(0), qRcvWindowSet(65535), 
   qRcvWindowObserved(0), qUrgPtrSet(0), qUrgPtrObserved(0), qCksmSet(0xbeef), qCksmObserved(0), qMpKeySet(MPCAPABLE_SENDER_KEY_SET), qMpKeyObserved(0), qUDPCksmSet(0), qUDPCksmObserved(0),
   qUDPLenSet(0), qUDPLenObserved(0),  qICMPTypeSet(0),  qICMPTypeObserved(0),  qICMPCodeSet(0),  qICMPCodeObserved(0), qICMPSeqSet(0), qICMPSeqObs(0),
   srhPresent(false)  
   
{
    gettimeofday(&tv, NULL); 
    mpls_stack = NULL;
}

void ICMP::checkTcpOptModif(const unsigned char *pt, uint16_t length, bool v6) {
    vector <int> extractedOptionOrder;
    bool partiallyPresent = 0;
    int partialOption = 0;
    const unsigned char *ptr = pt;
    bool flag = false;
    uint8_t nopCount = 0;
    // window scale not set by us
    if(wScale == 0) {
       // if window scale was not set by us, makes no sense to see if it was removed
       wsNotRemoved = true;
       wsNotAdded = true; 
    } else {
        wsNotRemoved = false;
        wsNotAdded = true;
    }

    while (length > 0) {
		int opcode = *pt++;
		int opsize;
        
        if(!eolNotPresent) {
            break;
        }

        if(partiallyPresent) {
                break;
        } 
        
        // To stop before mpls extensions
        // Leverage 0 padding after options to detect mpls
        // [TODO]: Something more elegant
        if(*(pt - 2) == 0 && *(pt - 1) == 0 && *pt == 0 && *(pt + 1) == 0 && *(pt + 2) == 0 && *(pt + 3) == 0 && *(pt + 4) == 0 &&
         *(pt + 4) == 0 && *(pt + 5) == 0 && *(pt+6) == 0 && *(pt + 7) == 0 && *(pt + 8) == 0 && *(pt + 9) == 0) { 
            debug(DEVELOP, "       MPLS or end of quote");
            flag = true;
            break;
        }
		switch (opcode) {
		case TCPOPT_EOL:
            eolNotPresent = false;
            extractedOptionOrder.push_back(TCPOPT_EOL);
            length--;
            continue;
			//return;
		case TCPOPT_NOP:	
			nopNotPresent = false;
            extractedOptionOrder.push_back(TCPOPT_NOP);
            nopCount++;
            length--;
			continue;    
		default:
			opsize = *pt++;
			if (opsize < 2) { /* "silly options" */
				// if opsize not quoted 
                if(opsize == 0) {
                    partiallyPresent = true;
                    partialOption = opcode;
                    debug(DEVELOP, "       Opsize = 0, opsize not quoted");
                    break;
                }  else {
                    sport = dport = 0; // Count as bad response and do not write to .yrp file
                    return;
                }
            } 
			if (opsize > length) { // if option partially quoted after size field
                    partiallyPresent = true;
                    partialOption = opcode;                    
                    debug(DEVELOP, "        Opsize > Length, Opsize: " << opsize << " Total options length left: " << length);
                    //return;
                    break;
            }	/* don't parse partial options */
			switch (opcode) {
			case TCPOPT_MSS:
				if (opsize == TCPOLEN_MSS) {
                    uint16_t *tmp = (uint16_t *) pt;
					mssData = ntohs(*tmp);
                    mssPresent = true;
                    extractedOptionOrder.push_back(TCPOPT_MSS);
				}
				break;
			case TCPOPT_WINDOW:
				if (opsize == TCPOLEN_WINDOW) {
                    uint8_t *tmp = (uint8_t *) pt;
					wScaleObserved = *tmp;
                    if (ipv6)
                       wsNotAdded = false;
                    else {
                        if(wScale == 0){
                           wsNotAdded = false;
                        } else {
                           wsNotRemoved = true;
                        }
                    }
                    extractedOptionOrder.push_back(TCPOPT_WINDOW);
				}
				break;
			case TCPOPT_TIMESTAMP:
				if (opsize == TCPOLEN_TIMESTAMP) {
					uint32_t *tmp = (uint32_t *) pt;
                    tmspTsval = ntohl(*tmp);
                    tmspPresent = true;
                    extractedOptionOrder.push_back(TCPOPT_TIMESTAMP);
				}
				break;
			case TCPOPT_SACK_PERM:
				if (opsize == TCPOLEN_SACK_PERM) {
					sackpPresent = true;
                    extractedOptionOrder.push_back(TCPOPT_SACK_PERM);
				}
				break;
			case TCPOPT_MPTCP:
				if (opsize == 12) {
                    mpCapablePresent = true;
                    uint64_t * tmp = (uint64_t *)(pt + 2);
                    mpCapableData = *tmp;
                    qMpKeyObserved = mpCapableData;
                    extractedOptionOrder.push_back(TCPOPT_MPTCP);
                }
				break;
			}
			pt += opsize-2;
			length -= opsize;
		}
	}
    
    if(wScale != 0 && (nopCount == sizeof(struct window_scale)))
        wsNotRemoved = false;
    if (wScale != 0 && (nopCount == sizeof(struct window_scale) + 1)) {   
        if (mssPresent)
          wsNotRemoved = false;   
    }

    if(mssPresent && mssData != mssSet) // Compare extracted and set mss (user provided or default)
        goodMssData = false;
    if (mpCapablePresent && mpCapableData != MPCAPABLE_SENDER_KEY_SET)
        goodMpCableData = false;
    if (v6 && tmspPresent && tmspTsval != TCP6_TMSP_TSVAL_SET)
       goodTmspTsval = false;    
     
    bool mssPresentInFirstFour = false;
    bool sackPresentInFirstFour = false;
    bool mpcPresentInFirstFour = false;
    bool tmspPresentInFirstFour = false;
   
     // Detect option ordering only when all 4 options present and present as the first 4 options in response     
    if (mssPresent && sackpPresent && mpCapablePresent && tmspPresent) {
        for (unsigned int i = 0; i < 4; i++) {
            if(extractedOptionOrder[i] == TCPOPT_MSS)
              mssPresentInFirstFour = true;
            else if(extractedOptionOrder[i] == TCPOPT_SACK_PERM)
              sackPresentInFirstFour = true;
            else if(extractedOptionOrder[i] == TCPOPT_MPTCP) 
              mpcPresentInFirstFour = true; 
            else if(extractedOptionOrder[i] == TCPOPT_TIMESTAMP)
               tmspPresentInFirstFour = true;  
        }

        if(mssPresentInFirstFour && sackPresentInFirstFour && mpcPresentInFirstFour && tmspPresentInFirstFour) {
            if(!(extractedOptionOrder[0] == TCPOPT_MSS && extractedOptionOrder[1] == TCPOPT_SACK_PERM 
               && extractedOptionOrder[2] == TCPOPT_MPTCP && extractedOptionOrder[3] == TCPOPT_TIMESTAMP)) {
                   optOrderModif = true;
               }
        }
        firstOption = extractedOptionOrder[0];
        secondOption = extractedOptionOrder[1];
        thirdOption = extractedOptionOrder[2];
        fourthOption = extractedOptionOrder[3]; 
    }
    
    if(!v6 && pQ) {
        debug(DEBUG, "        Partially quoted option opcode: " << partialOption);
        if(partiallyPresent) {
            if(partialOption == TCPOPT_MSS) {
               goodMssData = true;
               mssPresent = true;
               debug(DEBUG, "       Corrected MSS");

            } else if(partialOption == TCPOPT_MPTCP) {
               goodMpCableData = true;
               mpCapablePresent = true;  
               debug(DEBUG, "        Corrected MPCAPABLE"); 
            } else if(partialOption == TCPOPT_WINDOW) {
                if(ipv6)
                  wsNotAdded = false;
                else {
                   if(wScale == 0) {
                      wsNotAdded = false;
                    } else {
                      wsNotRemoved = true;
                    }
                }   
            } else if(partialOption == TCPOPT_TIMESTAMP) { 
               tmspPresent = true;
               debug(DEBUG, "        Corrected Timestamp");
            } else if(partialOption == TCPOPT_SACK_PERM)  
                sackpPresent = true;      
        }
        
        // Pointer to start of TCP header
        struct tcphdr_options *tcp_op = (struct tcphdr_options *) (ptr - sizeof(struct tcphdr));
        
        uint16_t icmpPayloadSize = replysize - (sizeof(struct ip) + 8);
        uint16_t tcpQuotesize = icmpPayloadSize - (sizeof(struct ip));
        uint16_t indicatedTcpQuoteSize = (tcp_op->tcp.th_off << 2);
    
         // Response simply partialy quoted/truncated without any option removals, so everything present
        if(tcp_op->tcp.th_off == expectedOffset || (tcp_op->tcp.th_off != expectedOffset && indicatedTcpQuoteSize > tcpQuotesize)) {    
            mssPresent = true;
            sackpPresent = true;
            mpCapablePresent = true;
            tmspPresent = true;
            if(!ipv6){
                if(wScale != 0)
                   wsNotRemoved = true;        
            }
            //debug(DEBUG, "        Set all options as present");
        }
        
        if(tcp_op->tcp.th_off != expectedOffset && indicatedTcpQuoteSize > tcpQuotesize)  
           debug(DEBUG, "        Partial quote with TCP offset modified ");
        
        if(nopCount == sizeof(struct sack_p))
           sackpPresent = false;
        else if(nopCount == sizeof(struct mss) && wScale == 0) 
           mssPresent = false;   
        else if(nopCount == sizeof(struct mp_capable))
           mpCapablePresent = false;
        else if (nopCount == sizeof(struct timestamp_op))
           tmspPresent = false;
        else if (nopCount == (sizeof(struct mp_capable) + sizeof(struct timestamp_op))) {
            mpCapablePresent = false;
            tmspPresent = false;
        }   
        else if(nopCount == (sizeof(struct mp_capable) + sizeof(struct timestamp_op) + sizeof(struct window_scale))) {
           mpCapablePresent = false;
           tmspPresent = false;
           wsNotRemoved = false;
        }
        else if(nopCount == (sizeof(struct mp_capable) + sizeof(struct timestamp_op) + sizeof(struct mss))) {
            mpCapablePresent = false;
            tmspPresent = false;
            if(wScale == 0){ 
                mssPresent = false;
            }
        }
        else if(nopCount == (sizeof(struct sack_p) + sizeof(struct mp_capable) + sizeof(struct timestamp_op) + sizeof(struct window_scale))) {
            sackpPresent = false;
            mpCapablePresent = false;
            tmspPresent = false;
            wsNotRemoved = false;
        } 
        else if(nopCount == (sizeof(struct sack_p) + sizeof(struct mp_capable) + sizeof(struct timestamp_op) + sizeof(struct mss))) {
          sackpPresent = false;
          mpCapablePresent = false;
          tmspPresent = false;  
          if(wScale == 0)
            mssPresent = false;
        }
    }
}

ICMP4::ICMP4(struct ip *ip, struct icmp *icmp, uint32_t elapsed, bool _coarse, bool partialQt, Traceroute *trace): ICMP() {
    coarse = _coarse;
    detection = trace->config->midbox_detection;
    memset(&ip_src, 0, sizeof(struct in_addr));
    type = (uint8_t) icmp->icmp_type;
    code = (uint8_t) icmp->icmp_code;
    
    v4probeType = trace->config->type;
    mssSet = trace->config->mssData;
    dPortSet = trace->config->dstport;
    pQ = partialQt;
    wScale = trace->config->wScale;
    if(wScale == 0) {
        expectedOffset = 12;
        expectedProbeSize = 68;
    } else {
        expectedOffset = 13;
        expectedProbeSize = 72;
    }
    fixSequenceNo = trace->config->fixSequenceNo;        
    qTotalLengthSet = expectedProbeSize;
    qDportSet = dPortSet;
    if(fixSequenceNo)
       qSeqSet = 1;
    qDoffSet = expectedOffset;
   
    ip_src = ip->ip_src;
#if defined(_BSD) && !defined(_NEW_FBSD)
    replysize = ip->ip_len;
#else
    replysize = ntohs(ip->ip_len);
#endif
    ipid = ntohs(ip->ip_id);
    replytos = ip->ip_tos;
    replyttl = ip->ip_ttl;
    unsigned char *ptr = NULL;

    quote = NULL;
    if (((type == ICMP_TIMXCEED) and (code == ICMP_TIMXCEED_INTRANS)) or
        (type == ICMP_UNREACH)) {
        ptr = (unsigned char *) icmp;
        quote = (struct ip *) (ptr + 8);
        quote_p = quote->ip_p;
#if defined(_BSD) && !defined(_NEW_FBSD)
        probesize = quote->ip_len;
#else
        probesize = ntohs(quote->ip_len);
        qTotalLengthObserved = probesize;
#endif
        ttl = (ntohs(quote->ip_id)) & 0xFF;
        instance = (ntohs(quote->ip_id) >> 8) & 0xFF;

        /* Original probe was TCP */
        if (quote->ip_p == IPPROTO_TCP) {
             if(!detection) {
                struct tcphdr *tcp = (struct tcphdr *) (ptr + 8 + (quote->ip_hl << 2));
                rtt = elapsed - ntohl(tcp->th_seq);
                if (elapsed < ntohl(tcp->th_seq))
                   cerr << "** RTT decode, elapsed: " << elapsed << " encoded: " << ntohl(tcp->th_seq) << endl;
                sport = ntohs(tcp->th_sport);
                dport = ntohs(tcp->th_dport);
            } else if(detection && partialQt) {
                struct tcphdr_options *tcp_op = (struct tcphdr_options *) (ptr + 8 + (quote->ip_hl << 2));
                if(fixSequenceNo) {
                    if(ntohl(tcp_op->tcp.th_seq) != 1){
                       badSeqNo = true;
                    }
                } else {
                    rtt = elapsed - ntohl(tcp_op->tcp.th_seq);
                    if (elapsed < ntohl(tcp_op->tcp.th_seq)) {
                       cerr << "** RTT decode, elapsed: " << elapsed << " encoded: " << ntohl(tcp_op->tcp.th_seq) << endl;
                       badSeqNo = true;
                    }
                }
                
                sport = ntohs(tcp_op->tcp.th_sport);
                dport = ntohs(tcp_op->tcp.th_dport);
                qDportObserved = dport;

                q_seq = ntohl(tcp_op->tcp.th_seq);
                qSeqObserved = q_seq;

                if(dport != dPortSet)
                   tcpDpModif = true;

                q_tos = quote->ip_tos;
                qTosObserved = q_tos;
                qTosSet = 0;
                if(q_tos != 0) {
                   TosModif = true;
                } 
                
                if(probesize != expectedProbeSize) {    
                   pSizeModif = true;
                }  
                uint16_t quoteSize = replysize - ((ip->ip_hl<<2) + 8);
                
                if(quoteSize <= 40) { // Options unquoted so simply set everything to present
                    mssPresent = true;
                    sackpPresent = true;
                    mpCapablePresent = true;
                    tmspPresent = true;
                    goodMssData = true;
                    goodMpCableData = true;
        
                    // If partial quote then neither added nor removed
                    wsNotRemoved = true;
                    wsNotAdded = true;
                }
                // Partial quote of 28 bytes followed by mpls
                if(quoteSize > 28 && tcp_op->tcp.th_off == 0) {
                    mssPresent = true;
                    sackpPresent = true;
                    mpCapablePresent = true;
                    tmspPresent = true;
                    goodMssData = true;
                    goodMpCableData = true;  
                    wsNotRemoved = true;
                    wsNotAdded = true;
                    return;
                }
                if(quoteSize >= 34) {
                    qAckObserved = ntohl(tcp_op->tcp.th_ack);
                    if(ntohl(tcp_op->tcp.th_ack) != 0)
                      tcpAckModif = true;

                    qDoffObserved = tcp_op->tcp.th_off;   
                    if(tcp_op->tcp.th_off != expectedOffset)
                      tcpOffsetModif = true;
                   
                    qX2Observed = tcp_op->tcp.th_x2;
                    if(tcp_op->tcp.th_x2 != TCP_RESERVED_SET)
                      tcpX2Modif = true;

                    if(v4probeType == TR_TCP_SYN) {   
                      if(tcp_op->tcp.th_flags != 0x02)
                        tcpFlagsModif = true;
                    } else if(v4probeType == TR_TCP_ACK) {
                      if(tcp_op->tcp.th_flags != 0x10)
                        tcpFlagsModif = true;
                    }
                // If options present, perform option parsing on the partial quote    
                   if(quoteSize > 40){
                       const unsigned char *pt;
	                   uint16_t optLength = replysize - (sizeof(struct ip) + 8 + sizeof(struct ip) + sizeof(struct tcphdr));
                       debug(DEBUG, "        Options length: " << optLength);
    	               pt = (const unsigned char *)tcp_op + sizeof(struct tcphdr);
                       checkTcpOptModif(pt, optLength, ipv6);
                       debug(DEBUG, "        Quote size > 40 ");
                   }
                }                  
            } else {
                struct tcphdr_options *tcp_op = (struct tcphdr_options *) (ptr + 8 + (quote->ip_hl << 2));
                if(fixSequenceNo){
                    if(ntohl(tcp_op->tcp.th_seq) != 1){
                       badSeqNo = true;
                    }
                } else {
                    rtt = elapsed - ntohl(tcp_op->tcp.th_seq);
                    if (elapsed < ntohl(tcp_op->tcp.th_seq)) {
                       cerr << "** RTT decode, elapsed: " << elapsed << " encoded: " << ntohl(tcp_op->tcp.th_seq) << endl;
                       badSeqNo = true;
                    }
                }
                
                sport = ntohs(tcp_op->tcp.th_sport);
                dport = ntohs(tcp_op->tcp.th_dport);
                qDportObserved = dport;

                q_seq = ntohl(tcp_op->tcp.th_seq);
                qSeqObserved = q_seq;


                q_tos = quote->ip_tos;
                qTosObserved = q_tos;
                qTosSet = 0;
                
                if(probesize != expectedProbeSize) {    
                   pSizeModif = true;
                }
                if(q_tos != 0) {
                   TosModif = true;
                }
                
                qAckObserved = ntohl(tcp_op->tcp.th_ack);
                if(ntohl(tcp_op->tcp.th_ack) != 0)
                   tcpAckModif = true;
                
                //if((tcp_op->tcp.th_x2) != 0)
                qX2Observed = tcp_op->tcp.th_x2;
                if((tcp_op->tcp.th_x2) != TCP_RESERVED_SET) {
                   tcpX2Modif = true;   
                }

                if(dport != dPortSet)
                   tcpDpModif = true;
                
                qDoffObserved = tcp_op->tcp.th_off;
                if((tcp_op->tcp.th_off) != expectedOffset)
                   tcpOffsetModif = true; 

                if(v4probeType == TR_TCP_SYN) {   
                    if(tcp_op->tcp.th_flags != 0x02)
                       tcpFlagsModif = true;
                } else if(v4probeType == TR_TCP_ACK) {
                    if(tcp_op->tcp.th_flags != 0x10)
                       tcpFlagsModif = true;
                }  

                qUrgPtrObserved = ntohs(tcp_op->tcp.th_urp);
                qRcvWindowObserved = ntohs(tcp_op->tcp.th_win);

                unsigned char *p = (unsigned char *)tcp_op + 20; // Start of TCP options
                uint16_t optionSizeAlt = replysize - 20 - 8 - 20 - 20; // Either gives total length of options or length of options + mpls extension 
                unsigned char *end = p + optionSizeAlt;

                bool saw_tmsp = false; 
                uint32_t ipHashExtracted = 0;
                uint32_t tcpHashExtracted = 0;
                string opts;
                opts.clear();

                while( p < end) {
                    if(*p == 8 && *(p + 1) == 10){
                        p = p + 2;
                        uint32_t *q = (uint32_t *) p; 
                        ipHashExtracted = ntohl(*q);
                        q++;
                        tcpHashExtracted = ntohl(*q);
                        p = p + 8;
                        saw_tmsp = true;
                    } else{
                        // For mpls extension, original IP datagram has to be atleast 128 octets if not, 
                        // then 0 padded 
                        // 0 padding always present before extension and after TCP header or TCP header + options
                        if(*p == 0 && *(p + 1) == 0 && *(p + 2) == 0 && *(p + 3) == 0 && *(p + 4) == 0 && *(p + 5) == 0 && *(p + 6) == 0 && *(p + 7) == 0 && *(p + 8) == 0)
                          break;
                        else {
                          opts = opts + to_string(*p);
                          ++p;
                        }   
                    }
                }

                uint32_t ipHashComputed;
                uint32_t tcpHashComputed;
                string ipHashComputedInput;
                string tcpHashComputedInput;

                char targ[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(quote->ip_dst), targ, INET_ADDRSTRLEN);
                string targIP(targ); 

                // Compute IP hash over fields of quote  
                ipHashComputedInput = to_string(q_tos) + targIP + to_string((quote->ip_id)) + to_string((quote->ip_len));
                unsigned char *ipHashComputedInputBegin = (unsigned char*) ipHashComputedInput.c_str();
                ipHashComputed = XXHash32::hash(ipHashComputedInputBegin, ipHashComputedInput.size(), 0); 

                // Compute TCP hash over fields of quote 
                tcpHashComputedInput = to_string(tcp_op->tcp.th_seq) + opts;
                unsigned char *tcpHashComputedInputBegin = (unsigned char*) tcpHashComputedInput.c_str();
                tcpHashComputed = XXHash32::hash(tcpHashComputedInputBegin, tcpHashComputedInput.size(), 0); 

                // Compute Complete hash over fields of quote    
                uint32_t completeHashComputed;
                string completeHashInput;
                completeHashInput = to_string(q_tos) + targIP + to_string((quote->ip_id)) + to_string((quote->ip_len)) + to_string((tcp_op->tcp.th_seq)) + opts;
                unsigned char *completeHashInputBegin = (unsigned char *) completeHashInput.c_str(); 
                completeHashComputed = XXHash32::hash(completeHashInputBegin, completeHashInput.size(), 0);
                
                ipHashExtr = ipHashExtracted;
                ipHashComp = ipHashComputed;

                tcpHashExtr = tcpHashExtracted;
                tcpHashComp = tcpHashComputed;

                completeHashComp = completeHashComputed;
                completeHashExtr = uint32_t((ntohl( tcp_op->tcp.th_urp << 16) + ntohl((tcp_op->tcp.th_win ))));

                if(ipHashComp == ipHashExtr)
                  ipMatch = 1;
                else
                  ipMatch = 0;

                if(tcpHashComp == tcpHashExtr)
                  tcpMatch = 1;
                else
                  tcpMatch = 0;

                if(completeHashComp == completeHashExtr)
                  completeMatch = 1;
                else
                  completeMatch = 0;
               
               const unsigned char *pt;
	           uint16_t length = optionSizeAlt;
               vector <int> extractedOptionOrder;
	           pt = (const unsigned char *)tcp_op + 20;
               checkTcpOptModif(pt, length, ipv6);  
            }
        } else if (quote->ip_p == IPPROTO_UDP) {  /* Original probe was UDP */
            struct udphdr *udp = (struct udphdr *) (ptr + 8 + (quote->ip_hl << 2));
            /* recover timestamp from UDP.check and UDP.payloadlen */
            int payloadlen = ntohs(udp->uh_ulen) - sizeof(struct icmp);
            int timestamp = udp->uh_sum;
            sport = ntohs(udp->uh_sport);
            dport = ntohs(udp->uh_dport);
            if (payloadlen > 2)
                timestamp += (payloadlen-2) << 16;
            if (elapsed >= timestamp) {
                rtt = elapsed - timestamp;
            /* checksum was 0x0000 and because of RFC, 0xFFFF was transmitted
             * causing us to see packet as being 65 (2^{16}/1000) seconds in future */
            } else if (udp->uh_sum == 0xffff) {
                timestamp = (payloadlen-2) << 16;
                rtt = elapsed - timestamp;
            }
            if (elapsed < timestamp) {
                cerr << "** RTT decode, elapsed: " << elapsed << " encoded: " << timestamp << endl;
                sport = dport = 0;
            }
        } else if (quote->ip_p == IPPROTO_ICMP) { /* Original probe was ICMP */
            struct icmp *icmp = (struct icmp *) (ptr + 8 + (quote->ip_hl << 2));
            uint32_t timestamp = ntohs(icmp->icmp_id);
            timestamp += ntohs(icmp->icmp_seq) << 16;
            rtt = elapsed - timestamp;
            sport = icmp->icmp_cksum;
        }

        /* According to Malone PAM 2007, 2% of replies have bad IP dst. */
        uint16_t sum = in_cksum((unsigned short *)&(quote->ip_dst), 4);
        
        if (sport != sum) {
            cerr << "** IP dst in ICMP reply quote invalid!" << endl;
            sport = dport = 0;
            if (detection)
               trace->stats->badDestIP+=1;
        }

        /* Finally, does this ICMP packet have an extension (RFC4884)? */
        length = (ntohl(icmp->icmp_void) & 0x00FF0000) >> 16;
        length *= 4;
        if ( (length > 0) and (replysize > length+8) ) {
            ptr = (unsigned char *) icmp;
            ptr += length+8;
            if (length < 128) 
                ptr += (128-length);
            // ptr at start of ICMP extension
            ptr += 4;
            // ptr at start of MPLS stack header
            ptr += 2;
            // is this a class/type 1/1 (MPLS)?
            if ( (*ptr == 0x01) and (*(ptr+1) == 0x01) ) {
                ptr += 2;
                uint32_t *tmp;
                mpls_label_t *lse = (mpls_label_t *) calloc(1, sizeof(mpls_label_t) );
                mpls_stack = lse;
                for (int labels = 0; labels < MAX_MPLS_STACK_HEIGHT; labels++) {
                    tmp = (uint32_t *) ptr;
                    if (labels > 0) {
                        mpls_label_t *nextlse = (mpls_label_t *) calloc(1, sizeof(mpls_label_t) );
                        lse->next = nextlse;
                        lse = nextlse;
                    }
                    lse->label = (htonl(*tmp) & 0xFFFFF000) >> 12;
                    lse->exp   = (htonl(*tmp) & 0x00000F00) >> 8;
                    lse->ttl   = (htonl(*tmp) & 0x000000FF);
                    // bottom of stack?
                    if (lse->exp & 0x01) 
                        break;
                    ptr+=4;
                }
            }
        }
    }
}



// IPv6 response parsing 
void ICMP6::checkTcpFldModif(struct tcphdr_options * tcp_op, int probeType) {
    qDportObserved = ntohs(tcp_op->tcp.th_dport);
    if(ntohs(tcp_op->tcp.th_dport) != dPortSet) {
       tcpDpModif = true;
    }
    
    qSeqObserved = ntohl(tcp_op->tcp.th_seq);
    qSeqSet = TCP6_SEQUENCE_NUMBER_SET;
    if(ntohl(tcp_op->tcp.th_seq) != TCP6_SEQUENCE_NUMBER_SET)
       tcpSeqModif = true;  

    qAckObserved = ntohl(tcp_op->tcp.th_ack);
    qAckSet = 0;
    if(ntohl(tcp_op->tcp.th_ack) != 0)
       tcpAckModif = true;

    qDoffObserved = tcp_op->tcp.th_off;   
    qDoffSet = 12;
    if(tcp_op->tcp.th_off != 12) 
       tcpOffsetModif = true;

    qRcvWindowObserved = ntohs(tcp_op->tcp.th_win);
    if(ntohs(tcp_op->tcp.th_win) != TCP6_RCV_WINDOW_SET)
       tcpWindModif = true;

    qCksmObserved = ntohs(tcp_op->tcp.th_sum);
    qCksmSet = 0xbeef;   
    if(ntohs(tcp_op->tcp.th_sum) != 0xbeef)
        tcpChksmModif = true;
    
    qX2Observed = tcp_op->tcp.th_x2;
    qX2Set = TCP_RESERVED_SET;
    if(tcp_op->tcp.th_x2 != TCP_RESERVED_SET) 
       tcpX2Modif = true;  
       
    qUrgPtrSet = TCP6_URGENT_PTR_SET;
    qUrgPtrObserved = ntohs(tcp_op->tcp.th_urp);
    if(ntohs(tcp_op->tcp.th_urp) != TCP6_URGENT_PTR_SET)
       tcpUrgModif = true;
    if(probeType == TR_TCP6_SYN) {   
        if(tcp_op->tcp.th_flags != 0x02)
          tcpFlagsModif = true;
    } else if(probeType == TR_TCP6_ACK) {
        if(tcp_op->tcp.th_flags != 0x10)
          tcpFlagsModif = true;
    }               
}




void ICMP6::checkSpModif(uint16_t srcPort, uint32_t srcPortHash, Traceroute6 *trace) {
    string spHashInput = to_string(srcPort); 
    unsigned char *spHashBegin = (unsigned char *) spHashInput.c_str();
    uint32_t tmp = XXHash32::hash(spHashBegin, spHashInput.size(),0); 

    if(tmp != srcPortHash) // Stored cksm was changed not the dest IP
       spModif = true;
    // Check dest IP modification 
    else { // If source port is unmodified, verify dest IP
       uint16_t sum = in_cksum((unsigned short *)&(quote->ip6_dst), 16);
       if(sum != ntohs(srcPort)) {
          v6DestModif = true;
          cerr << "** IP6 dst in ICMP6 reply quote invalid!" << endl;
          sport = dport = 0;
          trace->stats->badDestIP+=1;
        }   
    }
}


/**
 * Create ICMP6 object on received response.
 *
 * @param ip   Received IPv6 hdr
 * @param icmp Received ICMP6 hdr
 * @param elapsed Total running time
 */

ICMP6::ICMP6(struct ip6_hdr *ip, struct icmp6_hdr *icmp, uint32_t elapsed, bool _coarse, bool partialQt, Traceroute6 *trace) : ICMP()
{
    is_yarrp = false;
    coarse = _coarse;
    detection = trace->config->midbox_detection;
    v6probeType = trace->config->type;
    mssSet = trace->config->mssData;
    dPortSet = trace->config->dstport;
    uint32_t flowLabelSet = trace->config->flowLabel;
    ipv6 = true;

    memset(&ip_src, 0, sizeof(struct in6_addr));
    type = (uint8_t) icmp->icmp6_type;
    code = (uint8_t) icmp->icmp6_code;
    ip_src = ip->ip6_src;
    replysize = ntohs(ip->ip6_plen); 
    replyttl = ip->ip6_hlim;

    qDportSet = dPortSet;
    qflowLabelSet = flowLabelSet;
    qTotalLengthSet = trace->config->ipv6PayloadLengthSet;

    /* Ethernet
     * IPv6 hdr
     * ICMP6 hdr                struct icmp6_hdr *icmp;         <- ptr
     *  IPv6 hdr                struct ip6_hdr *icmpip;
     *  Ext hdr                 struct ip6_ext *eh; (if present)
     *  Probe transport hdr     struct tcphdr,udphdr,icmp6_hdr; 
     *  Yarrp payload           struct ypayload *qpayload;
     */

    unsigned char *ptr = (unsigned char *) icmp; 
    quote = (struct ip6_hdr *) (ptr + sizeof(struct icmp6_hdr));            /* Quoted IPv6 hdr */
    struct ip6_ext *eh = NULL;                /* Pointer to any extension header */
    struct ip6_rthdr *reh = NULL; /* Pointer to any routing header */
    struct ip6_srhdr *srh = NULL; /* Pointer to segment routing header (type 4) */ 
    struct ypayload *qpayload = NULL;     /* Quoted ICMPv6 yrp payload */ 
    uint16_t ext_hdr_len = 0;
    quote_p = quote->ip6_nxt;
    
    int offset = 0;

    if (icmp->icmp6_type == ICMP6_ECHO_REPLY) {
        qpayload = (struct ypayload *) (ptr + sizeof(struct icmp6_hdr));
        if(detection){
           echoReply = true;
           return;
        }
    } else {
        // handle hop-by-hop (0), dest (60), frag (44) and SRH routing (43) extension headers
        if ( (quote_p == 0) or (quote_p == 44) or (quote_p == 60) or (quote_p == 43)) {
            if(quote_p == 43) {
               reh =  (struct ip6_rthdr *) (ptr + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) );
               if (reh->ip6r_type == 4){
                   srhPresent = true;
                   srh = (struct ip6_srhdr *) reh;
               }                     
               ext_hdr_len = reh->ip6r_len * 8 + 8;
               quote_p = reh->ip6r_nxt;
            } else {
                eh = (struct ip6_ext *) (ptr + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) );
                ext_hdr_len = 8;
                quote_p = eh->ip6e_nxt;
            }
        } 
        offset = sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + ext_hdr_len;
        if (quote_p == IPPROTO_TCP) {
            if(!detection)
               qpayload = (struct ypayload *) (ptr + offset + sizeof(struct tcphdr)); 
            else 
               qpayload = (struct ypayload *) (ptr + offset + sizeof(struct tcphdr_options));  
        } else if (quote_p == IPPROTO_UDP) {
            qpayload = (struct ypayload *) (ptr + offset + sizeof(struct udphdr));
        } else if (quote_p == IPPROTO_ICMPV6) {
            qpayload = (struct ypayload *) (ptr + offset + sizeof(struct icmp6_hdr));
        } else {
            warn("unknown quote\n");
            return;
        }
    }

    if(!detection) {
        if (ntohl(qpayload->id) == 0x79727036) 
           is_yarrp = true;
        ttl = qpayload->ttl;
        instance = qpayload->instance;
        yarrp_target = &(qpayload->target);
        uint32_t diff = qpayload->diff;
        if (elapsed >= diff)
           rtt = elapsed - diff;
        else
           cerr << "** RTT decode, elapsed: " << elapsed << " encoded: " << diff << endl;

    /* ICMP6 echo replies only quote the yarrp payload, not the full packet! */
        if (((type == ICMP6_TIME_EXCEEDED) and (code == ICMP6_TIME_EXCEED_TRANSIT)) or
           (type == ICMP6_DST_UNREACH)) {
           probesize = ntohs(quote->ip6_plen);
           if (quote_p == IPPROTO_TCP) {
               struct tcphdr *tcp = (struct tcphdr *) (ptr + offset);
               sport = ntohs(tcp->th_sport);
               dport = ntohs(tcp->th_dport);
           } else if (quote_p == IPPROTO_UDP) {
               struct udphdr *udp = (struct udphdr *) (ptr + offset);
               sport = ntohs(udp->uh_sport);
               dport = ntohs(udp->uh_dport);
           } else if (quote_p == IPPROTO_ICMPV6) {
               struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) (ptr + offset);
               sport = ntohs(icmp6->icmp6_id);
               dport = ntohs(icmp6->icmp6_seq);
           }
           uint16_t sum = in_cksum((unsigned short *)&(quote->ip6_dst), 16); 
           if (sport != sum) {
            cerr << "** IP6 dst in ICMP6 reply quote invalid!" << endl;
            sport = dport = 0;
           }
        }
    } else if(detection) {
        if(quote_p == IPPROTO_ICMPV6 || quote_p == IPPROTO_UDP){ 
            char dst[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(quote->ip6_dst), dst, INET6_ADDRSTRLEN);
            string dstIP(dst);
            string pHashInput = to_string((qpayload->id)) + dstIP + to_string(qpayload->instance) + to_string(qpayload->ttl)
                              + to_string(qpayload->diff) + to_string(qpayload->spHash);
            unsigned char *pHashBegin = (unsigned char *) pHashInput.c_str();
            uint32_t pHashExt = XXHash32::hash(pHashBegin, pHashInput.size(),0); 
           
            debug(DEVELOP, "        IPv6 Payload Hash Computed: " << pHashExt);
            debug(DEVELOP, "        IPv6 Payload Hash Stored: " << qpayload->pHash);

            if(pHashExt == qpayload->pHash) {
                if (ntohl(qpayload->id) == 0x79727036) 
                   is_yarrp = true;
                ttl = qpayload->ttl;
                instance = qpayload->instance;
                yarrp_target = &(qpayload->target);
                uint32_t diff = qpayload->diff;
                if (elapsed >= diff)
                   rtt = elapsed - diff;
                else
                   cerr << "** RTT decode, elapsed: " << elapsed << " encoded: " << diff << endl;
              
              // Check IPv6 header fields here
                uint32_t fLabel = 0; 
                uint32_t temp = 0;
                uint8_t tClass = 0; 
                fLabel = (ntohl(quote->ip6_flow)) & 0x000FFFFF; // Extract last 20 bits (flow label) from the 32 bit field
                temp = (ntohl(quote->ip6_flow)) >> 20;
                tClass = temp & 0xFF;
              
                qflowLabelObserved = fLabel;
                if(fLabel != flowLabelSet)
                   v6FlowModif = true;

                qTrafficClassObserved = tClass;   
                if(tClass != 0)
                   v6TcModif = true;   

            /* ICMP6 echo replies only quote the yarrp payload, not the full packet! */
                if (((type == ICMP6_TIME_EXCEEDED) and (code == ICMP6_TIME_EXCEED_TRANSIT)) or (type == ICMP6_DST_UNREACH)) {
                    probesize = ntohs(quote->ip6_plen);
                    if (quote_p == IPPROTO_UDP) {
                        struct udphdr *udp = (struct udphdr *) (ptr + offset);
                        sport = ntohs(udp->uh_sport);
                        dport = ntohs(udp->uh_dport);
    
                       qTotalLengthObserved = ntohs(quote->ip6_plen);
                       if(ntohs(quote->ip6_plen) != qTotalLengthSet)
                          v6PlenModif = true;

                       qDportObserved = ntohs(udp->uh_dport);        
                       if(ntohs(udp->uh_dport) != dPortSet) 
                          dpModif = true;

                       qUDPCksmSet = 0xbeef;
                       qUDPCksmObserved = ntohs(udp->uh_sum);   
                       if(ntohs(udp->uh_sum) != 0xbeef) 
                          UdpCksmModif = true;
                      
                       qUDPLenSet = qTotalLengthSet;
                       qUDPLenObserved = ntohs(udp->uh_ulen);    
                       if(ntohs(udp->uh_ulen) != qTotalLengthSet)
                          UdpLenModif = true;
                       checkSpModif(udp->uh_sport, qpayload->spHash, trace); 
                       v6probeType = TR_UDP6;
                    } else if (quote_p == IPPROTO_ICMPV6) {
                        struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) (ptr + offset);
                        sport = ntohs(icmp6->icmp6_id);
                        dport = ntohs(icmp6->icmp6_seq);
                     
                        qTotalLengthObserved = ntohs(quote->ip6_plen);
                        if(ntohs(quote->ip6_plen) != qTotalLengthSet)
                           v6PlenModif = true;

                        qICMPTypeSet = ICMP6_ECHO_REQUEST;
                        qICMPTypeObserved = icmp6->icmp6_type ;
                        if(icmp6->icmp6_type != ICMP6_ECHO_REQUEST)
                           icmpTypeModif = true;

                        qICMPCodeSet = ICMP6_CODE_SET;
                        qICMPCodeObserved = icmp6->icmp6_code;
                        if(icmp6->icmp6_code != ICMP6_CODE_SET)
                           icmpCodeModif = true;

                        qICMPSeqSet =  ICMP6_SEQUENCE_NUMBER_SET;
                        qICMPSeqObs = ntohs(icmp6->icmp6_seq);
                        if (ntohs(icmp6->icmp6_seq) != ICMP6_SEQUENCE_NUMBER_SET)
                           icmpSeqModif =true;

                        checkSpModif(icmp6->icmp6_id, qpayload->spHash, trace); 
                        v6probeType = TR_ICMP6;
                    }
                }
            } else {
              cerr << "** icmp: Bad response, no integrity match\n" << endl;
              sport = dport = 0;
              trace->stats->v6BadIntegrity+=1;    
            }
        } else if(quote_p == IPPROTO_TCP && partialQt) { // For all ipv6 partial quotes, write defualt value to .yrp, so ttl for all is 0
            pQ = true;
            is_yarrp = true;
            debug(DEBUG, "        Partial Quote");
            if(((type == ICMP6_TIME_EXCEEDED) and (code == ICMP6_TIME_EXCEED_TRANSIT)) or (type == ICMP6_DST_UNREACH)) {
                probesize = ntohs(quote->ip6_plen);
                struct tcphdr_options *tcp_op = (struct tcphdr_options *) (ptr + offset);
                sport = ntohs(tcp_op->tcp.th_sport);
                dport = ntohs(tcp_op->tcp.th_dport);
            }
        } else if(quote_p == IPPROTO_TCP && !partialQt) {
            unsigned char *mov = (unsigned char *) qpayload;
            unsigned char * lptr = NULL;
            unsigned char * rptr = NULL;
            uint32_t yId = 0;
            uint8_t count = 0;
            bool left = false;
            bool idNotFound = false;

            if(ntohl(qpayload->id) ==  0x79727036) {                
                debug(DEVELOP, endl << "        TCP6, no option removal case ");
                char dst[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &(quote->ip6_dst), dst, INET6_ADDRSTRLEN);
                string dstIP(dst);
                debug(DEVELOP, "        Target IP: " << dstIP);
                string pHashInput = to_string((qpayload->id)) + dstIP + to_string(qpayload->instance) + to_string(qpayload->ttl)
                                  + to_string(qpayload->diff) + to_string(qpayload->spHash);// + to_string(qpayload->mss); 
                unsigned char *pHashBegin = (unsigned char *) pHashInput.c_str();
                uint32_t pHashExt = XXHash32::hash(pHashBegin, pHashInput.size(),0); 
        
                debug(DEVELOP, "        IPv6 Payload Hash Computed: " << pHashExt);
                debug(DEVELOP, "        IPv6 Payload Hash Stored: " << qpayload->pHash);

                if(pHashExt == qpayload->pHash) {
                    is_yarrp = true;
                    ttl = qpayload->ttl;
                    instance = qpayload->instance;
                    yarrp_target = &(qpayload->target);
                    uint32_t diff = qpayload->diff;
                    if (elapsed >= diff)
                        rtt = elapsed - diff;
                    else
                        cerr << "** RTT decode, elapsed: " << elapsed << " encoded: " << diff << endl;
                       
                    uint32_t fLabel = 0; 
                    uint32_t temp = 0;
                    uint8_t tClass = 0; 
                    fLabel = (ntohl(quote->ip6_flow)) & 0x000FFFFF; //extract last 20 bits (flow label) from the 32 bit field
                    temp = (ntohl(quote->ip6_flow)) >> 20;
                    tClass = temp & 0xFF;                  

                    debug(DEVELOP, "        Flow Label Extracted: " << fLabel << " Flow Label Set: " << flowLabelSet);
                     
                    qflowLabelObserved = fLabel;
                    if(fLabel != flowLabelSet)
                        v6FlowModif = true;
                    qTrafficClassObserved = tClass;   
                    if(tClass != 0)
                        v6TcModif = true;   

            /* ICMP6 echo replies only quote the yarrp payload, not the full packet! */
                    if (((type == ICMP6_TIME_EXCEEDED) and (code == ICMP6_TIME_EXCEED_TRANSIT)) or (type == ICMP6_DST_UNREACH)) {                        
                        probesize = ntohs(quote->ip6_plen);
                        qTotalLengthObserved = probesize;
                        if(probesize != qTotalLengthSet)   
                           v6PlenModif = true;

                        struct tcphdr_options *tcp_op = (struct tcphdr_options *) (ptr + offset);
                        sport = ntohs(tcp_op->tcp.th_sport);
                        dport = ntohs(tcp_op->tcp.th_dport);
                        checkTcpFldModif(tcp_op, v6probeType);
                      
                        debug(DEVELOP, "        Reply size/external IP payload length field:  " << replysize);
                        uint16_t length = replysize - (sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + ext_hdr_len + sizeof(struct tcphdr) + sizeof(struct ypayload));
                        const unsigned char * optStart = (const unsigned char *) tcp_op + sizeof(struct tcphdr);
                        debug(DEVELOP, "        Options length:  " << length);
                        checkTcpOptModif(optStart, length, ipv6);
                        checkSpModif(tcp_op->tcp.th_sport, qpayload->spHash, trace);
                    }
                } else {
                    cerr << "** icmp.cpp: Bad response, no integrity match!" << endl;
                    sport = dport = 0;
                    trace->stats->v6BadIntegrity+=1;
                }
            } // End of normal option processing, i.e, when no option added or removed (yarrp id at expected position)
            else {
                debug(DEVELOP, endl << "        Option Removal case ");
                char dst[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &(quote->ip6_dst), dst, INET6_ADDRSTRLEN);
                string dstIP(dst);
                debug(DEVELOP, "        Target IP " << dstIP);
                debug(DEVELOP, "        Reply size/external IP payload length field:  " << replysize);
                // Cumulative size of pre-set options = 28 bytes
                while((ntohl(yId) != 0x79727036)) {
                    uint32_t *tmp = (uint32_t *) mov; 
                    yId = ntohl(*tmp);
                    if(count == 28)
                       break;
                    count++;
                    mov--; // Move left/back for max 28 bytes in search of yID, when option removals done
                }
                debug(DEVELOP, "        Leftward movement complete");
                if(ntohl(yId) == 0x79727036){
                    debug(DEVELOP, "        Yarrp ID found to the left of expected position");
                    left = true;
                    mov++;
                    lptr = mov;
                    is_yarrp = true;
                } else{
                    mov = (unsigned char *) qpayload; // Start again from expected position of yarrp id and then move right
                    yId = 0;
                    count = 0;
                    while((ntohl(yId) != 0x79727036)) { // Move right/forward, when option addition  
                       uint32_t *tmp = (uint32_t *) mov; 
                       yId = ntohl(*tmp);
                       if(count == 28)
                          break;
                       count++;
                       mov++;
                    }
                    debug(DEVELOP, "        Rightward movement complete");
                    if(ntohl(yId) == 0x79727036) {
                       left = false;
                       mov--;
                       rptr = mov;
                       is_yarrp = true;
                       debug(DEVELOP, "        Yarrp ID found to the right of expected position");

                    } else {
                        cerr << "** Bad packet, yarrp ID could not be located!" << endl;
                        idNotFound = true;
                       sport = dport = 0;
                    }
                }
                if(!idNotFound) {
                    if(left)
                        qpayload = (struct ypayload *) lptr;
                    else
                        qpayload = (struct ypayload *) rptr;    

                    char dst[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &(quote->ip6_dst), dst, INET6_ADDRSTRLEN);
                    string dstIP(dst);
                    string pHashInput = to_string((qpayload->id)) + dstIP + to_string(qpayload->instance) + to_string(qpayload->ttl)
                                      + to_string(qpayload->diff) + to_string(qpayload->spHash);
                    unsigned char *pHashBegin = (unsigned char *) pHashInput.c_str();
                    uint32_t pHashExt = XXHash32::hash(pHashBegin, pHashInput.size(),0); 

                    debug(DEVELOP, "        IPv6 Payload Hash Computed: " << pHashExt);
                    debug(DEVELOP, "        IPv6 Payload Hash Stored: " << qpayload->pHash);

                    if(pHashExt == qpayload->pHash) {
                        ttl = qpayload->ttl;
                        instance = qpayload->instance;
                        yarrp_target = &(qpayload->target);
                        uint32_t diff = qpayload->diff;
                        if (elapsed >= diff)
                           rtt = elapsed - diff;
                        else
                           cerr << "** RTT decode, elapsed: " << elapsed << " encoded: " << diff << endl;
                    
                        uint32_t fLabel = 0; 
                        uint32_t temp = 0;
                        uint8_t tClass = 0; 
                        fLabel = (ntohl(quote->ip6_flow)) & 0x000FFFFF; 
                        temp = (ntohl(quote->ip6_flow)) >> 20;
                        tClass = temp & 0xFF;

                        qflowLabelObserved = fLabel;
                        if(fLabel != 0)
                           v6FlowModif = true;

                        qTrafficClassObserved = tClass;   
                        if(tClass != 0)
                           v6TcModif = true;   

            /* ICMP6 echo replies only quote the yarrp payload, not the full packet! */
                        if (((type == ICMP6_TIME_EXCEEDED) and (code == ICMP6_TIME_EXCEED_TRANSIT)) or (type == ICMP6_DST_UNREACH)) {
                            probesize = ntohs(quote->ip6_plen);
                            qTotalLengthObserved = probesize;
                            if(probesize != qTotalLengthSet)
                               v6PlenModif = true;

                            struct tcphdr_options *tcp_op = (struct tcphdr_options *) (ptr + offset);
                            sport = ntohs(tcp_op->tcp.th_sport);
                            dport = ntohs(tcp_op->tcp.th_dport);
                            checkTcpFldModif(tcp_op, v6probeType);
                      
                            // Length of options
                            uint16_t length = replysize - sizeof(struct icmp6_hdr) - sizeof(struct ip6_hdr) - sizeof(struct tcphdr) - sizeof(struct ypayload);
                        
                            debug(DEVELOP, "        Options length:  " << length);
                        
                            const unsigned char * optStart = (const unsigned char *) tcp_op + sizeof(struct tcphdr);
                            checkTcpOptModif(optStart, length, ipv6);                        
                            checkSpModif(tcp_op->tcp.th_sport, qpayload->spHash, trace);
                        }
                    } else { 
                        printf("** icmp: Bad response, no integrity match!\n");
                        sport = dport = 0;
                        trace->stats->v6BadIntegrity+=1;
                    }  
                }           
            }
        } // TCP processing ends here
        else {
            cout << "** Unknown quote" << endl;
            sport = dport = 0;
        }
    } // IPv6 middlebox detection ends here
}



uint32_t ICMP4::quoteDst() {
    if ((type == ICMP_TIMXCEED) and (code == ICMP_TIMXCEED_INTRANS)) {
        return quote->ip_dst.s_addr;
    }
    return 0;
}

void ICMP::printterse(char *src) {
    float r = 0.0;
    coarse ? r = rtt/1.0 : r = rtt/1000.0;
    printf(">> ICMP response: %s Type: %d Code: %d TTL: %d RTT: %2.3fms",
      src, type, code, ttl, r);
    if (instance)
      printf(" Inst: %u", instance);
    printf("\n");
}

void ICMP::print(char *src, char *dst, int sum) {
    printf("\ttype: %d code: %d from: %s\n", type, code, src);
    printf("\tYarrp instance: %u\n", instance);
    printf("\tTS: %lu.%ld\n", tv.tv_sec, (long) tv.tv_usec);
    if (coarse)
      printf("\tRTT: %u ms\n", rtt);
    else
      printf("\tRTT: %u us\n", rtt);
    printf("\tProbe dst: %s\n", dst);
    printf("\tProbe TTL: %d\n", ttl);
    if (detection && ipv6){
        printf("\tTraffic Class modified: %d\n", v6TcModif); 
        printf("\tFlow Label modified: %d\n", v6FlowModif); 
        printf("\tIP Payload Length modified: %d\n", v6PlenModif);
    }
    if (detection && !ipv6){
        printf("\tToS modified: %d\n", TosModif); 
        printf("\tIP Total Length modified: %d\n", pSizeModif); 
        printf("\tIP Hash match: %d\n", ipMatch);
        printf("\tTCP Hash match: %d\n", tcpMatch); 
        printf("\tComplete Hash match: %d\n", completeMatch);  
    }
    if (detection && (quote_p == IPPROTO_TCP)){
        printf("\tMSS observed: %d\n", mssData);
        printf("\tPartial Quote: %d\n", pQ);
        printf("\tTCP Data Offset modified: %d\n", tcpOffsetModif);
        printf("\tNop not added (0 if added) %d\n", nopNotPresent);
    }
    if (ipid) printf("\tReply IPID: %d\n", ipid);
    if (quote_p) printf("\tQuoted Protocol: %d\n", quote_p);
    if ( (quote_p == IPPROTO_TCP) || (quote_p == IPPROTO_UDP) ) 
      printf("\tProbe TCP/UDP src/dst port: %d/%d\n", sport, dport);
    if ( (quote_p == IPPROTO_ICMP) || (quote_p == IPPROTO_ICMPV6) )
      printf("\tQuoted ICMP checksum: %d\n", sport);
    if (sum) printf("\tCksum of probe dst: %d\n", sum);
}


char *
ICMP::getMPLS() {
    static char *mpls_label_string = (char *) calloc(1, PKTSIZE);
    static char *label = (char *) calloc(1, PKTSIZE);
    memset(mpls_label_string, 0, PKTSIZE);
    memset(label, 0, PKTSIZE);
    mpls_label_t *head = mpls_stack;
    if (not head)
        snprintf(mpls_label_string, PKTSIZE, "0");
    while (head) {
        //printf("**** LABEL: %d TTL: %d\n", head->label, head->ttl);
        if (head->next)
            snprintf(label, PKTSIZE, "%d:%d,", head->label, head->ttl);
        else
            snprintf(label, PKTSIZE, "%d:%d", head->label, head->ttl);
        strcat(mpls_label_string, label);
        head = head->next;
    }
    return mpls_label_string;
}

void 
ICMP4::print() {
    char src[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_src, src, INET_ADDRSTRLEN);
    char dst[INET_ADDRSTRLEN] = "no-quote";
    uint16_t sum = 0;
    if (quote) {
        inet_ntop(AF_INET, &(quote->ip_dst), dst, INET_ADDRSTRLEN);
        sum = in_cksum((unsigned short *)&(quote->ip_dst), 4);
    }
    if (verbosity > HIGH) {
        printf(">> ICMP response:\n");
        ICMP::print(src, dst, sum);
        if (mpls_stack)
            printf("\t MPLS: [%s]\n", getMPLS());
    } else if (verbosity > LOW) {
        ICMP::printterse(src);
    }
}

void
ICMP6::print() {
    char src[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip_src, src, INET6_ADDRSTRLEN);
    char dst[INET6_ADDRSTRLEN] = "no-quote";
    uint16_t sum = 0;
    if (quote != NULL) {
        inet_ntop(AF_INET6, &(quote->ip6_dst), dst, INET6_ADDRSTRLEN);
        sum = in_cksum((unsigned short *)&(quote->ip6_dst), 16);
    }
    if (verbosity > HIGH) {
        printf(">> ICMP6 response:\n");
        ICMP::print(src, dst, sum);
    } else if (verbosity > LOW) {
        ICMP::printterse(src);
    }
}

/* trgt, sec, usec, type, code, ttl, hop, rtt, ipid, psize, rsize, rttl, rtos */
void ICMP::write(FILE ** out, uint32_t count, char *src, char *target) {
    if (*out == NULL)
        return;
    if(!detection)    
    {
        fprintf(*out, "%s %lu %ld %d %d ",
        target, tv.tv_sec, (long) tv.tv_usec, type, code);
        fprintf(*out, "%d %s %d %u ",
        ttl, src, rtt, ipid);
        fprintf(*out, "%d %d %d %d ",
        probesize, replysize, replyttl, replytos);
        fprintf(*out, "%s ", getMPLS());
        fprintf(*out, "%d\n", count);
    } else {
        if(ipv6 & v6probeType == TR_UDP6) {
            fprintf(*out, "%s %d %s %lu %ld %d %d %d %d %d %d ", target, ttl, src, tv.tv_sec, (long) tv.tv_usec, rtt, type, code, probesize, replysize, replyttl);
            fprintf(*out, "%d %d %d ", v6TcModif, v6FlowModif, v6PlenModif); 
            fprintf(*out, "%d %d %d %d %d ", spModif, dpModif, UdpCksmModif, UdpLenModif, srhPresent);
            fprintf(*out, "%d %d %d %d %d %d %d %d %d %d %d %d ", qflowLabelSet, qflowLabelObserved, qTrafficClassSet, qTrafficClassObserved, qTotalLengthSet, qTotalLengthObserved, qDportSet, qDportObserved, qUDPLenSet, qUDPLenObserved, qUDPCksmSet, qUDPCksmObserved);
        } else if(ipv6 & v6probeType == TR_ICMP6) {
            fprintf(*out, "%s %d %s %lu %ld %d %d %d %d %d %d ", target, ttl, src, tv.tv_sec, (long) tv.tv_usec, rtt, type, code, probesize, replysize, replyttl);
            fprintf(*out, "%d %d %d ", v6TcModif, v6FlowModif, v6PlenModif);
            fprintf(*out, "%d %d %d %d %d ", icmpTypeModif, icmpCodeModif, icmpIdModif, icmpSeqModif, srhPresent);
            fprintf(*out, "%d %d %d %d %d %d ", qflowLabelSet, qflowLabelObserved, qTrafficClassSet, qTrafficClassObserved, qTotalLengthSet, qTotalLengthObserved);
            fprintf(*out, "%d %d %d %d %d %d ", qICMPTypeSet, qICMPTypeObserved, qICMPCodeSet, qICMPCodeObserved, qICMPSeqSet, qICMPSeqObs);
        } else if(ipv6 & (v6probeType == TR_TCP6_SYN || v6probeType == TR_TCP6_ACK)) {
            fprintf(*out, "%s %d %s %lu %ld %d %d %d %d %d %d ", target, ttl, src, tv.tv_sec, (long) tv.tv_usec, rtt, type, code, probesize, replysize, replyttl);
            fprintf(*out, "%d %d %d %d %d ", mssData, mssSet, v6TcModif, v6FlowModif, v6PlenModif);
            fprintf(*out, "%d %d %d %d %d %d %d %d %d %d %d ", tcpSpModif, tcpDpModif, tcpSeqModif, tcpAckModif, tcpOffsetModif, tcpWindModif, tcpChksmModif, tcpUrgModif, tcpFlagsModif, tcpX2Modif, srhPresent);
            fprintf(*out, "%d %d %d %d %d %d %d %d %d %d %d ", mssPresent, sackpPresent, mpCapablePresent, tmspPresent, goodMssData, goodMpCableData, goodTmspTsval, nopNotPresent, wsNotAdded, wsNotRemoved, pQ);
            fprintf(*out, "%d %d %d %d %d %d %d %d %d %d %d %d ", qflowLabelSet, qflowLabelObserved, qTrafficClassSet, qTrafficClassObserved, qTotalLengthSet, qTotalLengthObserved, qDportSet, qDportObserved, qSeqSet, qSeqObserved, qAckSet, qAckObserved);
            fprintf(*out, "%d %d %d %d %d %d %d %d %d %d %lu %lu ", qDoffSet, qDoffObserved, qX2Set, qX2Observed, qRcvWindowSet, qRcvWindowObserved, qUrgPtrSet, qUrgPtrObserved, qCksmSet, qCksmObserved, (long) qMpKeySet, (long) qMpKeyObserved);
            if(!optOrderModif) {
                fprintf(*out, "%d X X X X ", optOrderModif);
            } else {
                fprintf(*out, "%d %d %d %d %d ", optOrderModif, firstOption, secondOption, thirdOption, fourthOption);

            }
        } else {// IPv4 TCP
            fprintf(*out, "%s %d %s %lu %ld %d %u %d %d %d %d %d %d %d ", target, ttl, src, tv.tv_sec, (long) tv.tv_usec, rtt, ipid, type, code, probesize, replysize, replyttl, q_tos, q_seq);
            fprintf(*out, "%d %d %d %d %u %u %u %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d ", mssData, mssSet, wScale, wScaleObserved, ipHashExtr, tcpHashExtr, completeHashExtr, ipMatch, tcpMatch, completeMatch, badSeqNo, TosModif, pSizeModif, dpModif, tcpOffsetModif, tcpFlagsModif, tcpX2Modif, mssPresent, sackpPresent, mpCapablePresent, tmspPresent, goodMssData, goodMpCableData, nopNotPresent, wsNotAdded, wsNotRemoved, pQ);
            fprintf(*out, "%d %d %d %d %d %d %d %d ", qTosSet, qTotalLengthSet, qTotalLengthObserved, qDportSet, qDportObserved, qSeqSet, qAckSet, qAckObserved);
            fprintf(*out, "%d %d %d %d %d %d %u %lu %lu ", qDoffSet, qDoffObserved, qX2Set, qX2Observed, qUrgPtrObserved, qRcvWindowObserved, tmspTsval, (long) qMpKeySet, (long) qMpKeyObserved);
            if(!optOrderModif) {
              fprintf(*out, "%d X X X X ", optOrderModif);
            } else {
              fprintf(*out, "%d %d %d %d %d ", optOrderModif, firstOption, secondOption, thirdOption, fourthOption);
            }
        }    
    }

}

void ICMP4::write(FILE ** out, uint32_t count, struct ip *quote, uint16_t quoteSize, FILE **outDump) {
    if ((sport == 0) and (dport == 0))
        return;
   
    char src[INET_ADDRSTRLEN];
    char target[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_src, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(quote->ip_dst), target, INET_ADDRSTRLEN);
    ICMP::write(out, count, src, target);
    if (detection)
       quoteDump(out, quote, quoteSize);
}

void ICMP6::write(FILE ** out, uint32_t count, struct ip *quotation, uint16_t quoteSize, FILE **outDump) {
    if ((sport == 0) and (dport == 0))
        return;
    char src[INET6_ADDRSTRLEN];
    char target[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip_src, src, INET6_ADDRSTRLEN);
    if (((type == ICMP6_TIME_EXCEEDED) and (code == ICMP6_TIME_EXCEED_TRANSIT)) or
    (type == ICMP6_DST_UNREACH)) { 
        inet_ntop(AF_INET6, &(quote->ip6_dst.s6_addr), target, INET6_ADDRSTRLEN);
    } 
    /* In the case of an ECHO REPLY, the quote does not contain the invoking
     * packet, so we rely on the target as encoded in the yarrp payload */
    else if (type == ICMP6_ECHO_REPLY) {
        inet_ntop(AF_INET6, yarrp_target, target, INET6_ADDRSTRLEN);
    } 
    /* If we don't know what else to do, assume that source of the packet
     * was the target */
    else {
        inet_ntop(AF_INET6, &ip_src, target, INET6_ADDRSTRLEN);
    }
    ICMP::write(out, count, src, target);
    if (detection)
       quoteDump(out, quote, quoteSize);
}

struct in6_addr ICMP6::quoteDst6() {
    if ((type == ICMP6_TIME_EXCEEDED) and (code == ICMP6_TIME_EXCEED_TRANSIT)) {
        return quote->ip6_dst;
    }
    struct in6_addr a;
    memset(&a, 0, sizeof(struct in6_addr));
    return a;
}

template<typename T>
void ICMP::quoteDump(FILE ** outDump, T quote, uint16_t quoteSize) {
    unsigned char *ptr = (unsigned char *) quote;
    uint16_t i;
    for (i = 0; i < quoteSize; i++){
    fprintf(*outDump, "%02x", *ptr);
        ++ptr;
    }
    fprintf(*outDump, "\n");
}