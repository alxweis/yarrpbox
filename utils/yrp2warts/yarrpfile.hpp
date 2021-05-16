/****************************************************************************
 * Copyright (c) 2016-2019 Justin P. Rohrer <jprohrer@tancad.org> 
 * All rights reserved.  
 *
 * Program:     $Id: yarrpfile.hpp $
 * Description: Process Yarrp output
 *
 * Attribution: R. Beverly, "Yarrp'ing the Internet: Randomized High-Speed 
 *              Active Topology Discovery", Proceedings of the ACM SIGCOMM 
 *              Internet Measurement Conference, November, 2016
 ***************************************************************************/

#ifndef YARRPFILE_INCLUDED
#define YARRPFILE_INCLUDED

//#include <arpa/inet.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include "ipaddress.hpp"

using namespace std;
using namespace ip;

// from scamper/trace/scamper_trace.h
typedef enum {ICMP6 = 0x04, ICMP = 0x04, UDP6 = 0x05, UDP = 0x05, TCP6_SYN = 0x03, TCP_SYN = 0x03, TCP6_ACK = 0x06, TCP_ACK = 0x06} traceroute_t;

// from yarrp/src/trace.h
static vector<traceroute_t> traceroute_type = {ICMP6, ICMP, UDP6, UDP, TCP6_SYN, TCP_SYN, TCP6_ACK, TCP_ACK};

static unordered_map<string,traceroute_t> tracetype_names = { {"ICMP", ICMP}, {"ICMP6", ICMP6}, {"UDP", UDP}, {"UDP6", UDP6}, {"TCP_SYN", TCP_SYN}, {"TCP6_SYN", TCP6_SYN}, {"TCP_ACK", TCP_ACK}, {"TCP6_ACK", TCP6_ACK} };

struct yarrpRecord {
	ipaddress target;
	uint32_t sec;
	uint32_t usec;
	uint8_t typ;
	uint8_t code;
	uint8_t ttl;
	ipaddress hop;
	uint32_t rtt;
	uint16_t ipid;
	uint16_t psize;
	uint16_t rsize;
	uint8_t rttl;
	uint8_t rtos;
	uint64_t count;
	
	uint8_t q_tos;
    uint32_t q_seq; 
    uint32_t ipHashExtr;
    uint32_t tcpHashExtr;
    uint32_t completeHashExtr;
    bool ipMatch; 
    bool tcpMatch;
    bool completeMatch;
	bool mid_detection;
	bool badSeqNo;
	bool TosModif;
	bool pSizeModif;    
	uint16_t mssSet;
	uint16_t mssSeen;
	bool mssPresent;
	bool wsNotAdded;
	bool wsNotRemoved;
	uint8_t wsSet;
	uint8_t wsObserved;
    bool tmspPresent;
    bool mpCapablePresent;
    bool sackpPresent;
    bool eolNotPresent;
    bool nopNotPresent;
    bool goodMssData;
    bool goodMpCableData;
	bool goodTmspTsval;
	uint32_t qtmspTsvalObserved;
	bool optOrderModif;
	uint16_t firstOption;
    uint16_t secondOption;
    uint16_t thirdOption;
    uint16_t fourthOption; 
	bool partialQuote;
	bool v6TcModif;
	bool v6FlowModif; 
	bool v6PlenModif; 
	bool spModif; 
	bool dpModif;
	bool UdpCksmModif; 
	bool UdpLenModif;
	bool icmpTypeModif;
    bool icmpCodeModif;
    bool icmpIdModif;
    bool icmpSeqModif;
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
    uint32_t qflowLabelSet;
    uint32_t qflowLabelObserved;
    uint8_t qTrafficClassSet;
    uint8_t qTrafficClassObserved;
    uint16_t qRcvWindowSet;
    uint16_t qRcvWindowObserved;
    uint16_t qUrgPtrSet;
    uint16_t qUrgPtrObserved;
    uint16_t qTCPCksmSet;
    uint16_t qTCPCksmObserved;

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
};

bool detection = false;

bool ipv6 = false;
string traceType;

ostream& operator<< (ostream& os, const yarrpRecord& r)
{
    return os << r.target << ", " << r.sec << ", " << r.usec << ", " << uint16_t(r.typ) << ", " << uint16_t(r.code) << ", " << uint16_t(r.ttl) << ", " << r.hop << ", " << r.rtt << ", " << r.ipid << ", " << r.psize << ", " << r.rsize << ", " << uint16_t(r.rttl) << ", " << uint16_t(r.rtos) << ", " << r.count;
}
istream& operator>> (istream &in, yarrpRecord& r)
{
	if(!detection) {
	  uint16_t typ, code, ttl, rttl, rtos;
	  in >> r.target >> r.sec >> r.usec >> typ >> code >> ttl >> r.hop >> r.rtt >> r.ipid >> r.psize >> r.rsize >> rttl >> rtos >> r.count;
	
	  r.typ = typ;
	  r.code = code;
	  r.ttl = ttl;
	  r.rttl = rttl;
	  r.rtos = rtos;
	  return in;
	} else if(detection && traceType == "UDP6") {
		uint16_t typ, code, ttl, rttl, trafficClassSet, trafficClassObserved;
		in >> r.target >> ttl >> r.hop >> r.sec >> r.usec >> r.rtt >> typ >> code >> r.psize >> r.rsize >> rttl >> r.v6TcModif >> r.v6FlowModif 
		>> r.v6PlenModif >> r.spModif >> r.dpModif >> r.UdpCksmModif >> r.UdpLenModif >> r.srhPresent >> r.qflowLabelSet >> r.qflowLabelObserved 
		>> trafficClassSet >> trafficClassObserved >> r.qTotalLengthSet >> r.qTotalLengthObserved >> r.qDportSet >> r.qDportObserved >> r.qUDPLenSet 
		>> r.qUDPLenObserved >> r.qUDPCksmSet >> r.qUDPCksmObserved;

		r.typ = typ;
		r.code = code;
		r.ttl = ttl; 
		r.rttl = rttl;
		r.qTrafficClassSet = trafficClassSet;
		r.qTrafficClassObserved = trafficClassObserved;
		return in;
	} else if(detection && traceType == "ICMP6") {
		uint16_t typ, code, ttl, rttl, trafficClassSet, trafficClassObserved, qTypeSet, qTypeObserved, qCodeSet, qCodeObserved;
		in >> r.target >> ttl >> r.hop >> r.sec >> r.usec >> r.rtt >> typ >> code >> r.psize >> r.rsize >> rttl >> r.v6TcModif >> r.v6FlowModif 
		>> r.v6PlenModif >> r.icmpTypeModif >> r.icmpCodeModif >> r.icmpIdModif >> r.icmpSeqModif >> r.srhPresent >> r.qflowLabelSet 
		>> r.qflowLabelObserved >> trafficClassSet >> trafficClassObserved >> r.qTotalLengthSet >> r.qTotalLengthObserved >>  qTypeSet
		>> qTypeObserved >> qCodeSet >> qCodeObserved>> r.qICMPSeqSet >> r.qICMPSeqObs;

		r.typ = typ;
		r.code = code;
		r.ttl = ttl; 
		r.rttl = rttl;
		r.qTrafficClassSet = trafficClassSet;
		r.qTrafficClassObserved = trafficClassObserved;
		r.qICMPTypeSet = qTypeSet;
		r.qICMPTypeObserved = qTypeObserved;
		r.qICMPCodeSet = qCodeSet;
		r.qICMPCodeObserved = qCodeObserved;
		return in;
	} else if(detection && (traceType == "TCP6_SYN" || traceType == "TCP6_ACK")) {
		uint16_t typ, code, ttl, rttl, doffSet, doffObserved, x2Set, x2Observed, trafficClassSet, trafficClassObserved;
		in >> r.target >> ttl >> r.hop >> r.sec >> r.usec >> r.rtt >> typ >> code >> r.psize >> r.rsize >> rttl >> r.mssSeen 
		>> r.mssSet >> r.v6TcModif >> r.v6FlowModif >> r.v6PlenModif >> r.tcpSpModif>> r.tcpDpModif >> r.tcpSeqModif >> r.tcpAckModif 
		>> r.tcpOffsetModif >> r.tcpWindModif >> r.tcpChksmModif >> r.tcpUrgModif >> r.tcpFlagsModif >> r.tcpX2Modif >> r.srhPresent 
		>> r.mssPresent >> r.sackpPresent >> r.mpCapablePresent >> r.tmspPresent >> r.goodMssData >> r.goodMpCableData >> r.goodTmspTsval >> /*r.eolNotPresent 
		>>*/r.nopNotPresent >> r.wsNotAdded >> r.wsNotRemoved >>  r.partialQuote >> r.qflowLabelSet >> r.qflowLabelObserved >> trafficClassSet 
		>> trafficClassObserved >> r.qTotalLengthSet >> r.qTotalLengthObserved >> r.qDportSet >>  r.qDportObserved >> r.qSeqSet 
		>> r.qSeqObserved >> r.qAckSet >> r.qAckObserved >> doffSet >> doffObserved >> x2Set >> x2Observed >> r.qRcvWindowSet >> r.qRcvWindowObserved 
		>> r.qUrgPtrSet >> r.qUrgPtrObserved >> r.qTCPCksmSet >> r.qTCPCksmObserved >> r.qMpKeySet >> r.qMpKeyObserved 
		>> r.optOrderModif >> r.firstOption >> r.secondOption >> r.thirdOption >> r.fourthOption;

		r.typ = typ;
		r.code = code;
		r.ttl = ttl; 
		r.rttl = rttl;
	    r.qDoffSet = doffSet;
	    r.qDoffObserved = doffObserved;
	    r.qX2Set = x2Set;
	    r.qX2Observed = x2Observed;
		r.qTrafficClassSet = trafficClassSet;
		r.qTrafficClassObserved = trafficClassObserved;
		return in;
	} else {
	  uint16_t typ, code, ttl, rttl, wsSet, wsObserved, dscp, tosSet, doffSet, doffObserved, x2Set, x2Observed;
      in >> r.target >> ttl >> r.hop >> r.sec >> r.usec >> r.rtt >> r.ipid >> typ >> code >> r.psize >> r.rsize >> rttl >> dscp >> r.q_seq >> r.mssSeen 
	  >> r.mssSet >> wsSet >> wsObserved >> r.ipHashExtr >> r.tcpHashExtr >> r.completeHashExtr >> r.ipMatch >> r.tcpMatch >> r.completeMatch 
	  >> r.badSeqNo >> r.TosModif >> r.pSizeModif >> r.tcpDpModif >> r.tcpOffsetModif >> r.tcpFlagsModif >> r.tcpX2Modif >> r.mssPresent 
	  >> r.sackpPresent >> r.mpCapablePresent >> r.tmspPresent >> r.goodMssData >> r.goodMpCableData >>  r.nopNotPresent >> r.wsNotAdded 
	  >> r.wsNotRemoved >> r.partialQuote >> tosSet >> r.qTotalLengthSet >> r.qTotalLengthObserved >> r.qDportSet >>  r.qDportObserved >> r.qSeqSet 
	  >> r.qAckSet >> r.qAckObserved >> doffSet >> doffObserved >> x2Set >> x2Observed >> r.qUrgPtrObserved >> r.qRcvWindowObserved >> r.qtmspTsvalObserved >> r.qMpKeySet >> r.qMpKeyObserved
	  >> r.optOrderModif >> r.firstOption >> r.secondOption >> r.thirdOption >> r.fourthOption;  

	  r.typ = typ;
	  r.code = code;
	  r.ttl = ttl;
	  r.rttl = rttl;
	  r.q_tos = dscp;
	  r.qTosObserved = r.q_tos;
	  r.mid_detection = detection;
	  r.wsSet = wsSet;
	  r.wsObserved = wsObserved;
	  r.qTosSet = tosSet;
	  r.qDoffSet = doffSet;
	  r.qDoffObserved = doffObserved;
	  r.qX2Set = x2Set;
	  r.qX2Observed = x2Observed;
	  r.qSeqObserved = r.q_seq;
	  
	  return in;
	}
}

class yarrpFile
{
private:
	ifstream m_fh;
	istream *m_fhs;
	bool read_file;
	ipaddress m_source;
	bool m_usGranularity;
	uint8_t m_traceType;
	uint16_t m_maxTtl;
	uint16_t m_fillTtl;
	uint64_t m_fills;
	uint64_t m_pkts;
	string m_startTime;
	string m_endTime;
	uint8_t m_columns;
	bool readHeader();
	bool readTrailer();

public:
	yarrpFile() : m_usGranularity(false), m_columns(0) {};
	bool open(string fn);
	bool open(istream& input_stream);
	void close();
	bool nextRecord(yarrpRecord &r);
	ipaddress getSource() const;
	uint8_t getType() const;
	uint16_t getMaxTtl() const;
};

bool yarrpFile::open(string fn)
{
	cout << "Opening Yarrp file: " << fn << endl;
	m_fh.open(fn, ifstream::in);
	m_fhs = &m_fh;
	read_file = true;
	return readHeader();
}

bool yarrpFile::open(istream& input_stream)
{
	cout << "Opening input stream" << endl;
	ios_base::sync_with_stdio(false);
	m_fhs = &input_stream;
	read_file = false;
	return readHeader();
}

void yarrpFile::close()
{
	if (m_fh.is_open()) {
		m_fh.close();
	}
}

bool yarrpFile::readHeader()
{
	if (!m_fhs->good()) {
		cerr << "Input not good" << endl;
		return false;
	}
	string line;
	string hash;
	string param;
	int headerlines = 0;
	while (m_fhs->peek() == '#') {
		getline(*m_fhs, line);
		replace(line.begin(), line.end(), ',', ' ');
		istringstream iss(line);
		iss >> hash >> param;
		if (param == "yarrp") {
			string ver;
			iss >> ver;
			if (ver == "v0.5") {
				cerr << "yrp2warts only works with version 0.6 or newer .yrp files!" << endl;
				return false;
			}
		}
		if (param == "Start:") {
			string dow, dom, month, year, tod, tz;
			iss >> dow >> dom >> month >> year >> tod >> tz;
			m_startTime = dow + " " + dom + " " + month + " " + year + " " + tod + " " + tz;
		}
		if (param == "SourceIP:") {
			iss >> m_source;
		}
		if (param == "IPv6:")
		{
			ipv6 = true;
		}
		if (param == "Trace_Type:") {
			string type_name;
			iss >> type_name;

			traceType.clear();
			traceType = type_name;
			cout << "yarrpfile: Trace type: " << traceType << endl;
			
			m_traceType = tracetype_names[type_name];
		}
		if (param == "Max_TTL:") {
			iss >> m_maxTtl;
		}
		if (param == "Fill_Mode:") {
			iss >> m_fillTtl;
		}
		
		if (param == "RTT_Granularity:") {
			string trash, units;
			iss >> trash >> units;
			if (units == "us") {
				m_usGranularity = true;
			}
		}
		if (param == "Middlebox_Detection:"){
			detection = true;
		}
		if (param == "Output_Fields:") {
			string trash;
			m_columns = 0;
			while (iss >> trash) {
				m_columns++;
			}
		}
		headerlines++;
	}
	if (headerlines > 0) {
		return true;
	}
	return false;
}

bool yarrpFile::readTrailer()
{
	if (!m_fh.good()) {
		return false;
	}
	string line;
	string hash;
	string param;
	int trailerlines = 0;
	while (m_fhs->peek() == '#') {
		getline(*m_fhs, line);
		istringstream iss(line);
		iss >> hash >> param;
		if (param == "End:") {
			string dow, dom, month, year, tod, tz;
			iss >> dow >> dom >> month >> year >> tod >> tz;
			m_endTime = dow + " " + dom + " " + month + " " + year + " " + tod + " " + tz;
		}
		if (param == "Fills:") {
			iss >> m_fills;
		}
		if (param == "Pkts:") {
			iss >> m_pkts;
		}
		trailerlines++;
	}
	if (trailerlines > 0) {
		return true;
	}
	return false;
}

bool yarrpFile::nextRecord(yarrpRecord &r)
{
	string line;
	if (read_file) {
		if (!m_fh.good()) {
			return false;
		}
		if (m_fh.peek() == '#') {
			readTrailer();
			return false;
		}
		getline(m_fh, line);
	}
	else {
		if (!m_fhs->good()) {
			return false;
		}
		if (m_fhs->peek() == '#') {
			readTrailer();
			return false;
		}
		getline(*m_fhs, line);
	}
	//replace(line.begin(), line.end(), ',', ' ');
	istringstream iss(line);
	iss >> r;
	return true;
}

ipaddress yarrpFile::getSource() const
{
	return m_source;
}

uint8_t yarrpFile::getType() const
{
	return m_traceType;
}

uint16_t yarrpFile::getMaxTtl() const
{
	return m_maxTtl;
}

#endif