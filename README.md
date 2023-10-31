Yarrpbox
=========

There are existing tools aimed at middlebox detection. However, those tools fall short either due to the speed at which detection can be performed or the inability to lend themselves to a middlebox census at Internet-scale. To address these issues, we propose Yarrpbox. With Yarrpbox, we create a tool that allows for rapid scanning, detects as many modifications as possible, while also avoiding the triggering of ICMP rate limiting. These goals are fulfilled through a stateless design, the use of hashes encoded in the packet, and a randomized approach to probing, respectively.

Yarrpbox is built on top of Yarrp [1], benefiting from many of its features. Yarrpbox is stateless, allowing for high-speed probing, and randomizes the order of targeted destination addresses, reducing the risk of ICMP rate limiting like Yarrp. Like Yarrp, it also follows Paris traceroute techniques [2]. Yarrpbox can send different probe types: TCP SYN and TCP ACK for IPv4; TCP SYN, TCP ACK, UDP, and ICMPv6 for IPv6. Similar to Yarrp, Yarrpbox uses offline post-processing of scan output files to perform the middlebox detection.

Yarrpbox is written in C++, runs on Linux and BSD systems, and is open-sourced with a BSD license.

[1] Robert Beverly. 2016. Yarrp’ing the Internet: Randomized High-Speed Active Topology Discovery. In Proceedings of the
2016 Internet Measurement Conference. 413–420.

[2] Brice Augustin, Xavier Cuvellier, Benjamin Orgogozo, Fabien Viger, Timur Friedman, Matthieu Latapy, Clémence
Magnien, and Renata Teixeira. 2006. Avoiding traceroute anomalies with Paris traceroute. In Proceedings of the 6th
ACM SIGCOMM conference on Internet measurement. 153–158


## Build

```shell
./bootstrap
./configure
make
```

The following packages are required for successfully building the tool: `autoconf`, `zlib1g-dev`, `libscamperfile0`, `libscamperfile0-dev`. On debian systems they can be installed by running:
```
sudo apt-get install autoconf
sudo apt-get install zlib1g-dev
sudo apt-get install libscamperfile0
sudo apt-get install libscamperfile0-dev
```
The `yrp2warts` utility that performs an offline reconstruction on the probing results collected in the `yrp` format file and writes the result to a `txt` or `JSON` file format, is also included. In order to build the utility, please follow these steps:

```
cd utils
cd yrp2warts
make
```

## Options

In addition to the features and options that Yarrp provides (see: www.cmand.org/yarrp/yarrp.1.pdf), Yarrpbox incorporates new options:

Yarrpbox introduces the following additional options:

- `-d` or `--middlebox` Run in middlebox detection mode (default: false)
- `-D` or `--mss` MSS data for TCP probes (default IPv6: 1220, default IPv4: 536)
- `-f` or `--flowlabel` Flow Label for IPv6 probes (default: 0)
- `-N` or `--sequence` Set sequence number to 1 (default: elapsed time)
- `-w` or `--wscale` Add window scale option and set to the provided value


## Output

Yarrpbox writes probe responses (middlebox detection relevant fields + hex dump) to the specified output file in a delimited ASCII format in the order of reception, one response per line. Similar to Yarrp, Yarrpbox randomizes its probing. As a result, responses  will also be similarly randomized. To determine all of the responses for a single target destination, it is necessary to filter and collate responses. This is done through the "yrp2warts.cpp" tool. For standard Yarrp measurements (-d option not used), it generates output in the warts binary output. However, for Yarrpbox it produces either text or JSON output based on the user specification.


## Examples

### Middlebox Detection Mode

The command:

```
yarrp -i targets.txt -o test-detection.yrp -r 100 -d
```
runs Yarrpbox in middlebox detection mode. It sends TCP SYN probes in a randomly-permuted order to the IPv4 targets specified in the `targets.txt` file at a rate of 100 probes per second. Each line in the `targets.txt` file contains an IP address to be probed. The results are written to the `test-detection.yrp` file. 

### Offline Reconstruction - JSON Output

The command:

```
yrp2warts -i test-detection.yrp -o test-detection.json -j
```
performs an offline reconstruction of the Yarrpbox probe responses stored in the `test-detection.yrp` file. It produces JSON traces containing information relevant for middlebox detection and writes the result to the `test-detection.json` file.

### Offline Reconstruction - Text Output

The command:

```
yrp2warts -i test-detection.yrp -o test-detection.txt
```
performs an offline reconstruction of the Yarrpbox probe responses stored in `test-detection.yrp` file. It produces text traces containing information relevant for middlebox detection and writes the result to the `test-detection.txt` file.


## Probing Guidelines

The following suggestions are offered as guidelines for good Internet citizenship while using Yarrpbox for conducting rapid Internet-scale scans.

1. Before conducting Yarrpbox measurements, proposals by Partridge and Allman [1] and Kenneally and Dittrich [2] should be incorporated.
2. Best measurement practices [3] including limiting the probing rate, should be followed. We found 20kpps (IPv4) and 5kpps (IPv6) to be suitable based on several metrics such as the number of ICMP/ICMPv6 replies we receive, missing replies in our traces, and the number of detected middlebox IPs we have the highest confidence in. The entire IPv4 address space was scanned in under 3 hours with the over 15M IPv6 addresses probed in under 10 hours. Suitable scanning could also depend on the used network and vantage point. Therefore, we ask users of Yarrpbox to consult with their network operator to find apt scanning rates.
3. A well-established block-list should be used.
4. Dedicated servers or AWS instances should be used as measurement vantage points.
5. The benign nature of the scans should be signalled in web pages and rDNS entries of the source addresses used for probing.
6. The purpose and scope of the scans should be clearly expressed in all communications.
7. A straightforward way to opt out should be made available, and requests should be promptly respected.
8. Scans should not be larger or more frequent than necessary for research objectives to be achieved.

[1] Craig Partridge and Mark Allman. 2016. Ethical considerations in
network measurement papers. Commun. ACM 59, 10 (2016), 58–64.

[2]  Erin Kenneally and David Dittrich. 2012. The Menlo Report: Ethi-
cal Principles Guiding Information and Communication Technology
Research. Available at SSRN 2445102 (2012).

[3] Zakir Durumeric, Eric Wustrow, and J Alex Halderman. 2013. ZMap:
Fast Internet-wide Scanning and Its Security Applications. In 22nd
USENIX Security Symposium (USENIX Security 13). 605–620.


## Reproducibility

To reproduce the results from our paper, please refer to our [data and analysis.](https://doi.org/10.17617/3.EVDWIT)
