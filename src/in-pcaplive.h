/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __PCAPLIVE_H
#define __PCAPLIVE_H
#ifdef __cplusplus
extern "C" {
#endif

#ifdef STATICPCAP
/* Normal, we "dynamically" link to the libpcap library. However, on
 * some platforms, we might want to statically link to it instead. */
#include <pcap.h>
#else
struct pcap_if {
	struct pcap_if *next;
	char *name;		/* name to hand to "pcap_open_live()" */
	char *description;	/* textual description of interface, or NULL */
	void  *addresses;
	unsigned flags;	/* PCAP_IF_ interface flags */
};
typedef struct pcap_if pcap_if_t;
struct pcap_pkthdr {
	struct pcap_timeval {
		unsigned tv_sec;
		unsigned tv_usec;
	} ts;	/* time stamp */
	unsigned caplen;	/* length of portion present */
	unsigned len;	/* length this packet (off wire) */
};
#endif


#ifndef PCAP_ERRBUF_SIZE 
#define PCAP_ERRBUF_SIZE 256
#endif

typedef void (*PCAP_HANDLE_PACKET)(unsigned char *v_seap, 
    const struct pcap_pkthdr *framehdr, const unsigned char *buf);

typedef void (*PCAP_CLOSE)(void *hPcap);
typedef unsigned (*PCAP_DATALINK)(void *hPcap);
typedef unsigned (*PCAP_DISPATCH)(void *hPcap, unsigned how_many_packets, PCAP_HANDLE_PACKET handler, void *handle_data);
typedef int (*PCAP_FINDALLDEVS)(pcap_if_t **alldevs, char *errbuf);
typedef const char *(*PCAP_LIB_VERSION)(void);
typedef char *(*PCAP_LOOKUPDEV)(char *errbuf);
typedef int (*PCAP_MAJOR_VERSION)(void *p);
typedef int (*PCAP_MINOR_VERSION)(void *p);
typedef void * (*PCAP_OPEN_LIVE)(const char *devicename, unsigned snap_length, unsigned is_promiscuous, unsigned read_timeout, char *errbuf);
typedef void (*PCAP_FREEALLDEVS)(pcap_if_t *alldevs);
typedef void * (*PCAP_GET_AIRPCAP_HANDLE)(void *p);
typedef unsigned (*AIRPCAP_SET_DEVICE_CHANNEL)(void *p, unsigned channel);
typedef unsigned (*CAN_TRANSMIT)(const char *devicename);

struct PCAPLIVE
{
	unsigned func_err:1;
	unsigned is_available:1;
	unsigned is_printing_debug:1;
	unsigned status;
	unsigned errcode;

	PCAP_CLOSE			close;
	PCAP_DATALINK		datalink;
	PCAP_DISPATCH		dispatch;
	PCAP_FINDALLDEVS	findalldevs;
	PCAP_FREEALLDEVS	freealldevs;
	PCAP_LOOKUPDEV		lookupdev;
	PCAP_LIB_VERSION	lib_version;
	PCAP_MAJOR_VERSION	major_version;
	PCAP_MINOR_VERSION	minor_version;
	PCAP_OPEN_LIVE		open_live;
	PCAP_GET_AIRPCAP_HANDLE get_airpcap_handle;
	AIRPCAP_SET_DEVICE_CHANNEL airpcap_set_device_channel;
	//AIRPCAP_SET_FCS_PRESENCE airpcap_set_fcs_presence;
	//BOOL AirpcapSetFcsPresence(PAirpcapHandle AdapterHandle, BOOL IsFcsPresent);

	CAN_TRANSMIT		can_transmit;
};

/**
 * Initialize the pcap subsystem by loading the DLL or shared objects.
 */
void pcaplive_init(struct PCAPLIVE *pl);

void pcaplive_shutdown(struct PCAPLIVE *pl);


#ifdef __cplusplus
}
#endif
#endif /*__PCAPLIVE_H*/
