/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __TCP_H
#define __TCP_H
#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include "util-housekeeping.h"
#include "util-mystring.h"

struct PARSE {
	unsigned state;
	size_t remaining;
};

struct HTTPREQUEST;
typedef void (*HTTPVALUEPARSE)(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length, void *req);

struct HTTPREQUEST {
	unsigned char method[16];
	unsigned method_length;
	unsigned char url[512];
	unsigned url_length;
	unsigned char tmp[1024];
	unsigned tmp_length;

	struct StringT *name;
	struct StringT *host;
	struct StringT *user_agent;
	struct StringT *cookie[8];
	unsigned cookie_count;
	struct StringT *parm_name;
	struct StringT *login;
	struct StringT *password;
	struct StringT *youtube_video_id;

	unsigned content_length;

	unsigned value_state;


	HTTPVALUEPARSE value_parser;
};


struct HTTPRESPONSE {
	unsigned char version[16];
	unsigned version_length;
	unsigned return_code;
	unsigned content_length;
	time_t last_modified;
	time_t date;
	

	struct StringT *connection;
	struct StringT *content_type;
	struct StringT *server;


	unsigned char tmp[512];
	unsigned tmp_length;
	unsigned value_state;
	HTTPVALUEPARSE value_parser;

	char snarf_filename[64];
};

struct SMTPREQUEST
{
	unsigned char from[128];
	unsigned char to[128];
	unsigned char subject[128];
	unsigned is_data:1;
	unsigned is_body:1;
};
struct YMSG
{
	unsigned version;
	unsigned service;
	unsigned status;
	unsigned session_id;
	unsigned pwhash_algorithm;
	unsigned char username[64];
};

struct AIMPARSER {
	unsigned flap_state;
	unsigned snac_state;
	unsigned tlv_tag;
	unsigned tlv_len;
	unsigned remaining;

	struct {
		unsigned channel;
		unsigned seqno;
		unsigned length;
		unsigned family;
		unsigned subtype;
		unsigned flags;
		unsigned request_id;
	} pdu;

	unsigned char challenge[16];
	unsigned challenge_length;

	unsigned ssi_obj_count;
	unsigned ssi_state;
	unsigned ssi_len;
	unsigned ssi_buddy_type;
	struct StringT *ssi_group;

	unsigned skip_len;
};

struct POP3REQUEST {
	unsigned state;

	struct StringT *username;
};
struct POP3RESPONSE{
	unsigned state;
	unsigned cmd_id;
};

struct MSNREQUEST {
	unsigned char username[64];
	unsigned char toname[64];
};


/**
 * This function forces a malloc() to store the string. The TCP engine
 * calls this AFTER the application layer parses the packet for
 * any string that must be remembered after the current packet 
 * is discarded. A common bug in TCP parsers is to forget to 
 * call strfrag_finish() after using a string, which will cause
 * backing-stores to be needlessly created for them, hurting
 * performance. */
void strfrag_force_backing_store(struct StringReassembler *strfrag);

/**
 * Appends a string onto our virtual string. If the current virtual
 * string is a reference to the packet, and the appended string is adjacent
 * in the packet, then we just widen the reference in the packet. Otherwise
 * we malloc() a backing-store and copy the strings into it.
 */
void strfrag_append(struct StringReassembler *strfrag, const unsigned char *px, unsigned length);
void strfrag_finish(struct StringReassembler *strfrag);
void strfrag_init(struct StringReassembler *strfrag);
void strfrag_xfer(struct StringReassembler *dst, struct StringReassembler *src);
#define strfrag_clear strfrag_init




/**
 * This is a record for a half-duplex TCP stream. It contains a pointer
 * (potentially invalid) to the other half of the TCP stream.
 */
struct TCPRECORD {
	unsigned layer7_proto;
	unsigned ip_ver;
	unsigned char ip_src[16];
	unsigned char ip_dst[16];
	unsigned short tcp_src;
	unsigned short tcp_dst;

	/** The "next expected sequence number" along this TCP connection. */
	unsigned seqno;

	time_t last_activity;

	struct TCP_segment *segments;

	struct TCPRECORD *next;
	struct TCPRECORD *prev;
	
	/** The function that will parse incoming data segments on this
	 * TCP stream. These parsers assume that data can possibly arrive
	 * one byte at a time. Therefore, no underlying TCP reassembly needs
	 * to be done, although segments will be re-ordered by the system.
	 */
	FERRET_PARSER parser;

	/** The TCP connection going in the reverse direction, if there is
	 * any. In some cases, we won't see the reverse connection, such
	 * as on networks where the reverse direction goes out a different
	 * network path to the Internet. */
	struct TCPRECORD *reverse;
	struct PARSE parse;
	struct FerretEngine *eng;

	/** This is a 'string reassembler' for doing occasional reassembly
	 * of buffers in TCP protocols that cross protocol boundaries. We
	 * have 2 such strings so we can accomodate <name=value> pairs. If
	 * protocol needs a third string, it will have to allocate memory */
	struct StringReassembler str[2];

	union {
		struct SMTPREQUEST smtpreq;
		struct HTTPREQUEST httpreq;
		struct HTTPRESPONSE httprsp;
		struct AIMPARSER aim;
		struct POP3REQUEST pop3req;
		struct POP3RESPONSE pop3rsp;
		struct MSNREQUEST msnreq;
		struct YMSG ymsg;
	} layer7;

	/**
	 * A single state variable for holding private state information
	 * for the layer 7 protocol.
	 */
	unsigned layer7_state;
	unsigned layer7_length_remaining;

	/**
	 * This points into the housekeeping list
	 */
	struct HousekeepingEntry housekeeping_entry;

	unsigned a3;
};

void strfrag_copy(struct StringReassembler *dst, struct StringReassembler *src);


/**
 * We send this value into the system as the 'px' parameter to tell the 
 * system that it should close the TCP connection, move to the "closed"
 * state in the state-machines, and to release any allocated resources.
 */
#define TCP_CLOSE NULL

#ifdef __cplusplus
}
#endif
#endif /*__TCP_H*/
