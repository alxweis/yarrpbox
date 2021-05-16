/****************************************************************************
   Program:     $Id: $
   Date:        $Date: $
   Description: yarrp runtime configuration parsing
****************************************************************************/
#include "yarrp.h"
#include "options.h"
int verbosity;
bool mssSupplied = false;
bool flowLabelSupplied = false;
bool srhSegmentSupplied = false;

static struct option long_options[] = {
    {"srcaddr", required_argument, NULL, 'a'},
    {"bgp", required_argument, NULL, 'b'},
    {"blocklist", required_argument, NULL, 'B'},
    {"coarse", required_argument, NULL, 'C'},
    {"count", required_argument, NULL, 'c'},
    {"middlebox", no_argument, NULL, 'd'},
    {"mss", required_argument, NULL, 'D'},
    {"segment", required_argument, NULL, 'e'},
    {"sequence", no_argument, NULL, 'N'},
    {"flowlabel", required_argument, NULL, 'f'},
    {"fillmode", required_argument, NULL, 'F'},
    {"poisson", required_argument, NULL, 'Z'},
    {"srcmac", required_argument, NULL, 'M'},
    {"help", no_argument, NULL, 'h'},
    {"input", required_argument, NULL, 'i'},
    {"interface", required_argument, NULL, 'I'},
    {"minttl", required_argument, NULL, 'l'},
    {"maxttl", required_argument, NULL, 'm'},
    {"dstmac", required_argument, NULL, 'G'},
    {"neighborhood", required_argument, NULL, 'n'},
    {"output", required_argument, NULL, 'o'},
    {"port", required_argument, NULL, 'p'}, 
    {"probeonly", required_argument, NULL, 'P'}, 
    {"entire", no_argument, NULL, 'Q'},
    {"rate", required_argument, NULL, 'r'},
    {"receiveonly", required_argument, NULL, 'R'},
    {"sequential", no_argument, NULL, 's'},
    {"seed", required_argument, NULL, 'S'},
    {"type", required_argument, NULL, 't'},
    {"verbose", no_argument, NULL, 'v'},
    {"wscale", required_argument, NULL, 'w'},
    {"testing", no_argument, NULL, 'T'},
    {"instance", required_argument, NULL, 'E'}, 
    {"v6eh", required_argument, NULL, 'X'}, 
    {"version", no_argument, NULL, 'V'}, 
    {NULL, 0, NULL, 0},
};

uint8_t *read_mac(char *str) {
    uint8_t *mac = (uint8_t *) malloc (6 * sizeof(uint8_t));
    mac[0] = (uint8_t) strtoul(strtok(str, ":"), NULL, 16);
    for (int i=1; i < 6; i++) 
        mac[i] = (uint8_t) strtoul(strtok(NULL, ":"), NULL, 16);
    return mac;
}

void
YarrpConfig::parse_opts(int argc, char **argv) {
    int c, opt_index;
    char *endptr;

    if (argc <= 1)
        usage(argv[0]);
    type = TR_TCP_ACK;
    seed = time(NULL);
#ifdef GITREV
    params["Program"] = val_t("Yarrp v" + string(VERSION) + " (" + GITREV + ")", true);
#else
    params["Program"] = val_t("Yarrp v" + string(VERSION), true);
#endif
    params["RTT_Granularity"] = val_t("us", true);
    params["Targets"] = val_t("entire", true);
    
    while (-1 != (c = getopt_long(argc, argv, "a:b:B:c:CE:e:dD:f:F:G:hi:I:l:m:M:n:No:p:PQr:RsS:t:vVw:TX:Z:", long_options, &opt_index))) {
        switch (c) {
        case 'b':
            bgpfile = optarg;
            params["BGP_table"] = val_t(bgpfile, true);
            break;
        case 'B':
            blocklist = optarg;
            params["Blocklist"] = val_t(blocklist, true);
            break;
        case 'Z':
            poisson = strtol(optarg, &endptr, 10);
            params["Poisson"] = val_t(to_string(poisson), true);
            break;
        case 'C':
            coarse = true;
            params["RTT_Granularity"] = val_t("ms", true);
            break;
        case 'c':
            count = strtol(optarg, &endptr, 10);
            params["Count"] = val_t(to_string(count), true);
            break;
        case 'd':
            midbox_detection = true;
            break;     
        case 'D':
            uint64_t temp;
            temp = strtol(optarg, &endptr, 10);
            if(temp <= 0xFFFF) {
                mssSupplied = true;
                mssData = temp;
            } else {
                cerr << "MSS must be less than 0xFFFF" << endl;
                usage(argv[0]);
            }
            break;
        case 'e':
            srhSegmentSupplied = true;
            segment = optarg;  
            ipv6Adds.push_back(segment);
            break;
        case 'N':
            fixSequenceNo = true;
            break;        
        case 'w': 
            uint8_t tmp;
            tmp = strtol(optarg, &endptr, 10);
            if(tmp > 0 && tmp < 15) {
                wScaleProvided = true;
                wScale = tmp;
            } else {
                cerr << "Window Scale factor must be non 0 and less than 15" << endl;
                usage(argv[0]);
            }
            break;
        case 'f':
            uint32_t fL;
            fL =  strtol(optarg, &endptr, 10);
            if (fL <= 0x000FFFFF){
               flowLabel = fL;
               flowLabelSupplied = true;
            } else {
                cerr << "Flow label must be smaller than 0x000FFFFF" << endl;
                usage(argv[0]);
            }
            break;      
        case 'F':
            fillmode = strtol(optarg, &endptr, 10);
            break;
        case 'i':
            inlist = optarg;
            params["Targets"] = val_t(inlist, true);
            break;
        case 's':
            random_scan = false;
            params["Sequential"] = val_t("true", true);
            break;
        case 'S':
            seed = strtol(optarg, &endptr, 10);
            break;
        case 'T':
            testing = true;
            break;
        case 'Q':
            maxttl = 32;
            entire = true;
            break;
        case 'n':
            ttl_neighborhood = strtol(optarg, &endptr, 10);
            break;
        case 'v':
            verbosity++;
            break;
        case 'o':
            output = optarg;
            params["Output"] = val_t(output, true);
            break;
        case 'p':
            dstport = strtol(optarg, &endptr, 10);
            break;
        case 'E':
            instance = strtol(optarg, &endptr, 10);
            params["Instance"] = val_t(to_string(instance), true);
            break;
        case 'P':
            receive = false;
            break;
        case 'R':
            probe = false;
            break;
        case 'l':
            minttl = strtol(optarg, &endptr, 10);
            break;
        case 'm':
            maxttl = strtol(optarg, &endptr, 10);
            break;
        case 'r':
            rate = strtol(optarg, &endptr, 10);
            break;
        case 'I':
            int_name = optarg;
            break;
        case 'G':
            dstmac = read_mac(optarg);
            break;
        case 'M':
            srcmac = read_mac(optarg);
            break;
        case 'a':
            probesrc = optarg;
            break;
        case 't':
            if (strcmp(optarg, "ICMP6") == 0) {
                ipv6 = true;
                type = TR_ICMP6;
            } else if(strcmp(optarg, "UDP6") == 0) {
                ipv6 = true;
                type = TR_UDP6;
            } else if(strcmp(optarg, "TCP6_SYN") == 0) {
                ipv6 = true;
                type = TR_TCP6_SYN;
            } else if(strcmp(optarg, "TCP6_ACK") == 0) {
                ipv6 = true;
                type = TR_TCP6_ACK;
            } else if(strcmp(optarg, "ICMP") == 0) {
                type = TR_ICMP;
            } else if(strcmp(optarg, "ICMP_REPLY") == 0) {
                type = TR_ICMP_REPLY;
            } else if(strcmp(optarg, "UDP") == 0) {
                type = TR_UDP;
            } else if(strcmp(optarg, "TCP_SYN") == 0) {
                type = TR_TCP_SYN;
            } else if(strcmp(optarg, "TCP_ACK") == 0) {
                type = TR_TCP_ACK;
            } else {
                usage(argv[0]);
            }
            break;
        case 'V':
            debug(OFF, ">> yarrp v" << VERSION);
            debug(OFF, ">> https://www.cmand.org/yarrp/");
            exit(0);
        case 'X':
            v6_eh = strtol(optarg, &endptr, 10);
            break;
        case 'h':
        default:
            usage(argv[0]);
        }
    }
    if (testing)
        receive = false;
    if (not testing) {
        /* set default output file, if not set */
        if (not output) {
            output = (char *) malloc(UINT8_MAX);
            snprintf(output, UINT8_MAX, "output.yrp");
        }
        debug(DEBUG, ">> Output: " << output);
        /* set output file */
        if ( (output)[0] == '-')
            out = stdout;
        else
            out = fopen(output, "a");
        if (out == NULL)
            fatal("%s: cannot open %s: %s", __func__, output, strerror(errno));
    }

    /* set default destination port based on tracetype, if not set */
    if (not dstport) {
        dstport = 80;
        if ( (type == TR_UDP) || (type == TR_UDP6) )
            dstport = 53;
    }

    if(midbox_detection) {
        random_scan = true;
        if(!mssSupplied) {
            if(ipv6)
               mssData = 1220; // MSS corresponding to min IPv6 MTU
            else 
               mssData = 536; // MSS corresponding to min IPv4 MTU 
        }
        probe = true;
        receive = true;
        if (testing)
           receive = false;
    }
    if(!midbox_detection) {
        if(mssSupplied) {
           fatal("Can set MSS data only in middlebox detection mode");
        } if(wScaleProvided) {
           fatal("Can set Window Scale only in middlebox detection mode");  
        } if(flowLabelSupplied) {
           fatal("Can set Flow Label only in middlebox detection mode"); 
        } if (fixSequenceNo){
            fatal("Can set Sequence Number only in middlebox detection mode");    
        }
    }
    if(midbox_detection) {
        if(mssSupplied and (type == TR_UDP or type == TR_ICMP or type == TR_UDP6 or type == TR_ICMP6)){
           fatal("Can set MSS data only for TCP probes");
        } if(wScaleProvided and (type == TR_UDP or type == TR_ICMP or type == TR_UDP6 or type == TR_ICMP6 or type == TR_TCP6_SYN or type == TR_TCP6_ACK)){
           fatal("Can set WScale only for TCP probes"); 
        } if (flowLabelSupplied and !ipv6) {
           fatal("Can set Flow Label only for IPv6 probes");
        } if (fixSequenceNo and ipv6){
           fatal("Can set Sequence Number only for IPv4 probes");      
        }
    }
    if (v6_eh != 43) {
        if (srhSegmentSupplied){
           fatal("Can set segment list only for segment routing header (Protocol Number 43)");
        } 
    }

    debug(LOW, ">> yarrp v" << VERSION);

    params["Seed"] = val_t(to_string(seed), true);
    params["Random"] = val_t(to_string(random_scan), true);
    params["Rate"] = val_t(to_string(rate), true);
    params["Trace_Type"] = val_t(Tr_Type_String[type], true);
    if (ipv6) {
        params["v6_EH"] = val_t(to_string(v6_eh), true);
    }
    params["Start"] = val_t("unknown", true);
    params["Fill_Mode"] = val_t(to_string(fillmode), true);
    params["Min_TTL"] = val_t(to_string(minttl), true);
    params["Max_TTL"] = val_t(to_string(maxttl), true);
    params["TTL_Nbrhd"] = val_t(to_string(ttl_neighborhood), true);
    params["Dst_Port"] = val_t(to_string(dstport), true);
    if(!midbox_detection) {
       params["Output_Fields"] = val_t("target sec usec type code ttl hop rtt ipid psize rsize rttl rtos mpls count", true);
    } else if (midbox_detection && type == TR_UDP6) {
        params["Output_Fields"] = val_t("target ttl hop sec usec rtt type code psize rsize rttl tClassModif fLabelModif pLenModif srcPtModif dstPtModif cksmModif lenModif srhPresent flowLabelSet flowLabelObserved trafficClassSet trafficClassObserved IpPLengthSet IpPLengthObserved DportSet DportObserved UDPLenSet UDPLenObserved UDPCksmSet UDPCksmObserved quoteDump", true);
        params["Middlebox_Detection"] = val_t("1", true);
        params["IPv6"] = val_t("1", true);
    } else if (midbox_detection && type == TR_ICMP6) {
        params["Output_Fields"] = val_t("target ttl hop sec usec rtt type code psize rsize rttl tClassModif fLabelModif pLenModif typeModif codeModif idModif seqModif flowLabelSet srhPresent flowLabelObserved trafficClassSet trafficClassObserved IpPLengthSet IpPLengthObserved ICMPTypeSet ICMPTypeObserved ICMPCodeSet ICMPCodeObserved ICMPSeqSet ICMPSeqObserved quoteDump", true);
        params["Middlebox_Detection"] = val_t("1", true);
        params["IPv6"] = val_t("1", true);
    } else if(midbox_detection && (type == TR_TCP6_SYN || type == TR_TCP6_ACK)) {
        params["Output_Fields"] = val_t("target ttl hop sec usec rtt type code psize rsize rttl mssDataExt mssDataSet tClassModif fLabelModif pLenModif srcPtModif dstPortModif seqNoModif AckModif dOffsetModif wndwModif ChksmModif UrgModif flagsModif rsvdModif srhPresent mssPresent sackpPersent mpCapablePresent tmspPresent goodMssData goodMpCableData goodTmspTsval nopNotPresent wSNotAdded wSNotRemoved partialQuote flowLabelSet flowLabelObserved trafficClassSet trafficClassObserved IpPLengthSet IpPLengthObserved dportSet dportObserved seqSet seqObserved ackSet ackObserved doffSet doffObserved rsrvd2Set rsrvdObserved rcvWindowSet rcvWindowObserved urgPtrSet urgPtrObserved tcpCksmSet tcpCksmObserved mpcKeySet mpcKeyObserved optionOrderModified firstOpt secondOpt thirdOpt fourthOpt quoteDump", true);
        params["Middlebox_Detection"] = val_t("1", true);
        params["IPv6"] = val_t("1", true);
    } else if (midbox_detection){
    params["Output_Fields"] = val_t("target ttl hop tv.tv_sec, (long) tv.tv_usec rtt ipid type code probesize replysize replyttl dscp sequenceNumber mssDataExt mssDataSet wScaleSet wScaleObserved extractedIpHash extractedTcpHash extractedCompleteHash ipMatch tcpMatch completeMatch badSeqNo TosModif pSizeModif dpModif tcpOffsetModif tcpFlagsModif tcpX2Modif mssPresent sackpPresent mpCapablePresent tmspPresent goodMssData goodMpCapableData nopNotAdded wSNotAdded wSNotRemoved partialQuote tosSet totalLengthSet totalLengthObserved dportSet dportObserved seqSet ackSet ackObserved doffSet doffObserved rsrvdSet rsrvdObserved qUrgPtrObserved qRcvWindowObserved tmspTsvalObserved mpcKeySet mpcKeyObserved optionOrderModified firstOpt secondOpt thirdOpt fourthOpt quoteDump", true);
    params["Middlebox_Detection"] = val_t("1", true);
    }
}


void YarrpConfig::set(string key, string val, bool isset) {
    params[key] = val_t(val, isset);
}

void
YarrpConfig::dump(FILE *fd) {
    for (params_t::iterator i = params.begin(); i != params.end(); i++ ) {
        string key = i->first;
        val_t val = i->second;
        if (val.second)
            fprintf(fd, "# %s: %s\n", key.c_str(), val.first.c_str());   
    }
    fflush(fd);
}


void
YarrpConfig::usage(char *prog) {
    cout << "Usage: " << prog << " [OPTIONS] [targets]" << endl

    << "General options:" << endl
    << "  -o, --output            Output file (default: output.yrp)" << endl
    << "  -t, --type              Probe type: ICMP, ICMP_REPLY, TCP_SYN, TCP_ACK, UDP," << endl
    << "                                      ICMP6, UDP6, TCP6_SYN, TCP6_ACK" << endl 
    << "                                      (default: TCP_ACK)" << endl
    << "  -r, --rate              Scan rate in pps (default: 10)" << endl
    << "  -c, --count             Probes to issue (default: unlimited)" << endl
    << "  -v, --verbose           verbose (default: off)" << endl
    << "  -S, --seed              Seed (default: random)" << endl
    << "  -a, --srcaddr           Source address of probes (default: auto)" << endl
    << "  -p, --port              Transport dst port (default: 80)" << endl
    << "  -T, --test              Don't send probes (default: off)" << endl
    << "  -E, --instance          Prober instance (default: 0)" << endl

    << "Target options:" << endl
    << "  -i, --input             Input target file" << endl
    << "  -b, --bgp               BGP table (default: none)" << endl
    << "  -B, --blocklist         Prefix blocklist (default: none)" << endl
    << "  -Q, --entire            Entire IPv4/IPv6 Internet (default: off)" << endl

    << "TTL options:" << endl
    << "  -l, --minttl            Minimum TTL (default: 1)" << endl
    << "  -m, --maxttl            Maximum TTL (default: 16)" << endl
    << "  -F, --fillmode          Fill mode maxttl (default: 32)" << endl
    << "  -s, --sequential        Scan sequentially (default: random)" << endl
    << "  -n, --neighborhood      Neighborhood TTL (default: 0)" << endl
    << "  -Z, --poisson           Poisson TTLs (default: uniform)" << endl

    << "IPv6 options:" << endl
    << "  -I, --interface         Network interface (required for IPv6)" << endl
    << "  -G, --dstmac            MAC of gateway router (default: auto)" << endl
    << "  -M, --srcmac            MAC of probing host (default: auto)" << endl
    << "  -X, --v6eh              Ext Header number to add (default: none)" << endl

    << "Middlebox detection options:" << endl
    << "  -d  --middlebox         Run in middlebox detection mode (default:false)" << endl
    << "  -D  --mss               MSS data for TCP probes (default IPv6: 1220, default IPv4: 536)" << endl   
    << "  -f  --flowlabel         Flow Label for IPv6 probes (default: 0)" << endl
    << "  -N  --sequence          Set sequence number to 1 (default: elapsed time)" << endl
    << "  -w  --wscale            Add window scale option and set to provided value " << endl

/* Undocumented options */
//    << "  -C, --coarse            Coarse ms timestamps (default: us)" << endl
//    << "  -P, --probeonly         Probe only, don't receive" << endl
//    << "  -R, --receiveonly       Receive only, don't probe" << endl
    << endl;
    exit(-1);
}
