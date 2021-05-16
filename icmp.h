typedef struct mpls_label {
    uint32_t label:20;
    uint8_t exp:4;
    uint8_t ttl;
    struct mpls_label *next;
} mpls_label_t;
#define MAX_MPLS_STACK_HEIGHT 4

class ICMP {
    public:
    ICMP();
    virtual void print() {};
    virtual void write(FILE **, uint32_t, struct ip *, uint16_t, FILE **){};
    virtual uint32_t getSrc() { return 0; };
    virtual struct in6_addr *getSrc6() { return NULL; };
    virtual uint32_t quoteDst() { return 0; };
    virtual struct in6_addr quoteDst6() { struct in6_addr a; return a; };
    void printterse(char *);
    uint8_t quoteTTL() { return ttl; }
    uint32_t getRTT() { return rtt; }
    uint32_t getTTL() { return ttl; }
    uint16_t getSport() { return sport; }
    uint16_t getDport() { return dport; }
    uint8_t  getInstance() { return instance; }

    void checkTcpOptModif(const unsigned char *pt, uint16_t length, bool v6);
    void print(char *, char *, int);
    void write(FILE **, uint32_t, char *, char *);
    template<typename T>
    void quoteDump(FILE **, T, uint16_t);
    char *getMPLS();
    bool is_yarrp;
    bool echoReply;

    protected:
    uint32_t rtt;
    uint8_t ttl;
    uint8_t instance;
    uint8_t type;
    uint8_t code;
    uint8_t length;
    uint8_t quote_p;
    uint16_t sport;
    uint16_t dport;
    uint16_t ipid;
    uint16_t probesize; 
    uint16_t replysize;
    uint8_t replyttl;
    uint8_t replytos;
    uint8_t q_tos; 
    uint32_t q_seq; 
    struct timeval tv;
    bool coarse;
    bool detection; 
    uint32_t ipHashComp;
    uint32_t ipHashExtr;
    uint32_t tcpHashComp;
    uint32_t tcpHashExtr;
    uint32_t completeHashComp;
    uint32_t completeHashExtr;
    bool ipMatch; 
    bool tcpMatch;
    bool completeMatch;
    bool badSeqNo;
    bool pSizeModif;
    bool TosModif;
    bool mssPresent;
    bool wsNotAdded;
    bool wsNotRemoved;
    bool tmspPresent;
    bool mpCapablePresent;
    bool sackpPresent;
    bool eolNotPresent;
    bool nopNotPresent;
    uint16_t mssData;
    uint64_t mpCapableData;
    uint32_t tmspTsval;
    bool goodMssData;
    bool goodMpCableData;
    bool goodTmspTsval; 

    bool optOrderModif;
    uint16_t firstOption;
    uint16_t secondOption;
    uint16_t thirdOption;
    uint16_t fourthOption;
    bool pQ; 
    uint8_t wScale;
    uint8_t expectedOffset;
    uint16_t expectedProbeSize;
    uint8_t wScaleObserved;
    bool fixSequenceNo;

    // Transport protocol for ipv6 probing
    uint8_t v6probeType;
    int v4probeType;
    // If ipv6 probing
    bool ipv6;
    uint16_t mssSet;
    uint16_t dPortSet;

    bool v6TcModif; 
    bool v6FlowModif;
    bool v6PlenModif;
    bool v6DestModif;

    //udp6 field modification flags
    bool spModif;
    bool dpModif;
    bool UdpCksmModif;
    bool UdpLenModif;

    //ICMPv6 field modification flags
    bool icmpTypeModif;
    bool icmpCodeModif;
    bool icmpIdModif;
    bool icmpSeqModif;

    //TCP6 field modification flags
    bool tcpSpModif;
    bool tcpDpModif;
    bool tcpSeqModif;
    bool tcpAckModif;
    bool tcpOffsetModif;
    bool tcpWindModif;
    bool tcpChksmModif;
    bool tcpUrgModif;
    bool tcpFlagsModif;
    bool tcpX2Modif;

    uint8_t qTosSet;
    uint8_t qTosObserved;
    uint16_t qTotalLengthSet;
    uint16_t qTotalLengthObserved;
    uint16_t qDportSet;
    uint16_t qDportObserved;
    uint32_t qSeqSet;
    uint32_t qSeqObserved;
    uint32_t qAckSet;
    uint32_t qAckObserved;
    uint8_t qDoffSet;
    uint8_t qDoffObserved;
    uint8_t qX2Set;
    uint8_t qX2Observed;
    uint64_t qMpKeySet;
    uint64_t qMpKeyObserved;
    //v6 only
    uint32_t qflowLabelSet;
    uint32_t qflowLabelObserved;
    uint8_t qTrafficClassSet;
    uint8_t qTrafficClassObserved;
    uint16_t qRcvWindowSet;
    uint16_t qRcvWindowObserved;
    uint16_t qUrgPtrSet;
    uint16_t qUrgPtrObserved;
    uint16_t qCksmSet;
    uint16_t qCksmObserved;

    uint16_t qUDPCksmSet;
    uint16_t qUDPCksmObserved;
    uint16_t qUDPLenSet;
    uint16_t qUDPLenObserved;

    uint8_t qICMPTypeSet;
    uint8_t qICMPTypeObserved;
    uint8_t qICMPCodeSet;
    uint8_t qICMPCodeObserved;
    uint16_t qICMPSeqSet;
    uint16_t qICMPSeqObs;

    bool srhPresent;

    mpls_label_t *mpls_stack;
};

class ICMP4 : public ICMP {
    public: 
    ICMP4(struct ip *, struct icmp *, uint32_t elapsed, bool _coarse, bool partialQt, Traceroute *trace);
    uint32_t quoteDst();
    uint32_t getSrc() { return ip_src.s_addr; }
    void print();
    void write(FILE **, uint32_t, struct ip *, uint16_t, FILE **);

    private:
    struct ip *quote;
    struct in_addr ip_src;
}; 

class ICMP6 : public ICMP {
    public:
    ICMP6(struct ip6_hdr *, struct icmp6_hdr *, uint32_t elapsed, bool _coarse, bool partialQt, Traceroute6 *trace);
    struct in6_addr *getSrc6() { return &ip_src; }
    struct in6_addr quoteDst6();
    void print();
    void write(FILE **, uint32_t, struct ip *, uint16_t, FILE **);
    void checkTcpFldModif(struct tcphdr_options * tcp_op, int probeType);
    void checkSpModif(uint16_t srcPort, uint32_t srcPortHash, Traceroute6 *trace);

    private:
    struct ip6_hdr *quote;
    struct in6_addr ip_src;
    struct in6_addr *yarrp_target;
};

