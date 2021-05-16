#pragma once
#include "yarrp.h"

struct mss {
    uint8_t kind;
    uint8_t len;
    uint16_t data; 
}__attribute__((packed));

struct mp_capable {
    uint8_t kind;
    uint8_t len;
    //add subtype, version, 8 bit field
    unsigned int subtype:4;
    unsigned int version:4;
    uint8_t flag;
    uint64_t sender_key; 
}__attribute__((packed));

struct sack_p {
    uint8_t kind;
    uint8_t len;
}__attribute__((packed));

struct timestamp_op {
    uint8_t kind;
    uint8_t len;
    uint32_t TSval;
    uint32_t TSecr; 
}__attribute__((packed));

/*struct eol{
    uint8_t kind;
};*/

struct window_scale {
    uint8_t kind;
    uint8_t len;
    uint8_t shift; 
}__attribute__((packed));

struct tcphdr_options {
    struct tcphdr tcp;
    struct mss th_mss;
    struct sack_p th_sackp;
    struct mp_capable th_mpc;
    struct timestamp_op th_tmsp;
    //struct eol th_eol;
};


/* Type 4 (Segment Routing) Routing header */
struct ip6_srhdr {
    uint8_t  ip6sr_nxt;		/* next header */
    uint8_t  ip6sr_len;		/* length in units of 8 octets */
    uint8_t  ip6sr_type;		/* routing type */
    uint8_t  ip6sr_segleft;	/* segments left */
    uint8_t  ip6sr_lastentry; /*last entry */
    uint8_t  ip6sr_flags;  /* flags */
    uint16_t ip6sr_tag;   /* tag */
    //struct in6_addr ip6sr_seglist[1]; /* segment list */
    //struct in6_addr *ip6sr_seglist;
    
    // use
    u_char* ip6sr_seglist;
    
    //std::vector<struct in6_addr> ip6sr_seglist;
  };