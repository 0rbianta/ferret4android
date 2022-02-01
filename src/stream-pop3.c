/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "ferret.h"
#include "stack-parser.h"
#include "stack-netframe.h"
#include "stack-extract.h"
#include "util-mystring.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

enum {
	POP3_NONE=0,
	POP3_APOP = 'A'<<24 | 'P'<<16 | 'O'<<8 | 'P',	/* APOP authentication */
	POP3_DELE = 'D'<<24 | 'E'<<16 | 'L'<<8 | 'E',	/* DELE delete a message */
	POP3_LIST = 'L'<<24 | 'I'<<16 | 'S'<<8 | 'T',	/* LIST list available messages */
	POP3_NOOP = 'N'<<24 | 'O'<<16 | 'O'<<8 | 'P',	/* PASS password */
	POP3_PASS = 'P'<<24 | 'A'<<16 | 'S'<<8 | 'S',	/* PASS password */
	POP3_QUIT = 'Q'<<24 | 'U'<<16 | 'I'<<8 | 'T',	/* QUIT logoff */
	POP3_RETR = 'R'<<24 | 'E'<<16 | 'T'<<8 | 'R',	/* RETR retrieve a message */
	POP3_RSET = 'R'<<24 | 'S'<<16 | 'E'<<8 | 'T',	/* RSET reset the state*/
	POP3_STAT = 'S'<<24 | 'T'<<16 | 'A'<<8 | 'T',	/* STAT status of a message*/
	POP3_TOP  = 'T'<<24 | 'O'<<16 | 'P'<<8 | ' ',	/* TOP  retrieve headers of message */
	POP3_USER = 'U'<<24 | 'S'<<16 | 'E'<<8 | 'R',	/* USER username */
	POP3_UIDL = 'U'<<24 | 'I'<<16 | 'D'<<8 | 'L',	/* UIDL list unique identifiers for messages */
};

/*
S: <wait for connection on TCP port 110>
C: <open connection>
S:    +OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>
C:    APOP mrose c4c9334bac560ecc979e58001b3e22fb
S:    +OK mrose's maildrop has 2 messages (320 octets)
C:    STAT
S:    +OK 2 320
C:    LIST
S:    +OK 2 messages (320 octets)
S:    1 120
S:    2 200
S:    .
C:    RETR 1
S:    +OK 120 octets
S:    <the POP3 server sends message 1>
S:    .
C:    DELE 1
S:    +OK message 1 deleted
C:    RETR 2
S:    +OK 200 octets
S:    <the POP3 server sends message 2>
S:    .
C:    DELE 2
S:    +OK message 2 deleted
C:    QUIT
S:    +OK dewey POP3 server signing off (maildrop empty)
C:  <close connection>
S:  <wait for next connection>

*/

static void parse_message(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	UNUSEDPARM(sess);UNUSEDPARM(frame);UNUSEDPARM(px);UNUSEDPARM(length);
}

void parse_pop3_response(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct POP3RESPONSE *rsp = &sess->layer7.pop3rsp;
	unsigned offset = 0;
	unsigned state = rsp->state;
	unsigned sublen;
	enum {
	S_START,
	S_RESPONSE,
	S_PLUS,
	S_O,
	S_OK,
	S_OK_SPACE,
	S_MINUS,
	S_E,
	S_ER,
	S_ERR,
	S_ERR_SPACE,
	S_UNTIL_EOL,
	S_LOOKING_FOR_APOP_CHALLENGE,
	S_APOP_CHALLENGE,
	S_UNTIL_END_OF_MSG,
	S_EOM_NL,
	S_EOM_DOT,
	S_EOM_CR,
	};

	frame->layer7_protocol = LAYER7_POP3;

	while (offset<length)
	switch (state) {
	case S_START:
		state++;
		break;
	case S_RESPONSE:
		if (px[offset] == '+')
			state = S_PLUS;
		else if (px[offset] == '-')
			state = S_MINUS;
		else
			state = S_UNTIL_END_OF_MSG;
		break;
	case S_PLUS:
		if (px[offset] == '+') {
			offset++;
			state++;
		} else
			state = S_UNTIL_EOL;
		break;
	case S_O:
		if (toupper(px[offset]) == 'O') {
			offset++;
			state++;
		} else
			state = S_UNTIL_EOL;
		break;
	case S_OK:
		if (toupper(px[offset]) == 'K') {
			offset++;
			state++;
		} else
			state = S_UNTIL_EOL;
		break;
	case S_OK_SPACE:
		while (offset<length && isspace(px[offset]) && px[offset] != '\n')
			offset++;
		if (offset<length) {
			if (rsp->cmd_id == 0)
				state = S_LOOKING_FOR_APOP_CHALLENGE;
			else
				state = S_UNTIL_EOL;
		}			
		break;
	case S_MINUS:
		if (px[offset] == '-') {
			offset++;
			state++;
		} else
			state = S_UNTIL_EOL;
		break;
	case S_E:
		if (toupper(px[offset]) == 'E') {
			offset++;
			state++;
		} else
			state = S_UNTIL_EOL;
		break;
	case S_ER:
		if (toupper(px[offset]) == 'E') {
			offset++;
			state++;
		} else
			state = S_UNTIL_EOL;
		break;
	case S_ERR:
		if (toupper(px[offset]) == 'R') {
			offset++;
			state++;
		} else
			state = S_UNTIL_EOL;
		break;
	case S_ERR_SPACE:
		while (offset<length && isspace(px[offset]) && px[offset] != '\n')
			offset++;
		if (offset<length) {
			state = S_UNTIL_EOL;
		}			
		break;
	case S_UNTIL_EOL:
		while (offset<length && px[offset] != '\n')
			offset++;
		if (offset<length) {
			offset++;
			state = S_RESPONSE;
		}
		break;
	case S_LOOKING_FOR_APOP_CHALLENGE:
		while (offset<length && px[offset] != '\n' && px[offset] != '<')
			offset++;
		if (offset<length) {
			if (px[offset] == '<')
				state = S_APOP_CHALLENGE;
			else
				state = S_UNTIL_EOL;
		}
		break;
	case S_APOP_CHALLENGE:
		sublen = 0;
		while (offset+sublen<length && px[offset+sublen] != '\n' && px[offset] != '>')
			offset++;
		strfrag_append(sess->str, px+offset, sublen);
		offset+=sublen;
		if (offset<length) {
			if (px[offset] == '>') {
				strfrag_append(sess->str, px+offset, 1);
				offset++;
			}

			/* Prevent us from reparsing it again */
			rsp->cmd_id++;
			
			/* We have finished grabbing the challenge. We'll keep
			 * it in the strfrag buffer until we use it later */
			state = S_UNTIL_EOL;
		}
		break;
	case S_UNTIL_END_OF_MSG:
		if (px[offset] == '.') {
			offset++;
			state = S_EOM_DOT;
		} else {
			sublen = 0;
			while (offset+sublen<length && px[offset+sublen] != '\n')
				sublen++;
			
			parse_message(sess, frame, px+offset, sublen);
			offset += sublen;

			if (offset<length) {
				state = S_EOM_NL;
				parse_message(sess, frame, px+offset, 1);
				offset++;
			}
		}
		break;
	case S_EOM_NL:
		if (px[offset] == '.') {
			offset++;
			state = S_EOM_DOT;
		} else
			state = S_UNTIL_END_OF_MSG;
		break;
	case S_EOM_DOT:
		if (px[offset] == '\r') {
			state = S_EOM_CR;
			offset++;
		} else if (px[offset] == '\n') {
			/* Do a CLOSE on the message */
			parse_message(sess, frame, 0, 0);
			offset++;
			state = S_RESPONSE;
		} else
			state = S_UNTIL_END_OF_MSG;
		break;
	case S_EOM_CR:
		if (px[offset] == '\n') {
			offset++;
			state = S_EOM_NL;
		} else {
			state = S_UNTIL_END_OF_MSG;
		}
		break;
	}

	rsp->state = state;
}


static void
set_reverse_cmd(struct TCPRECORD *sess, unsigned cmd_id)
{
	if (sess->reverse)
		sess->reverse->layer7.pop3rsp.cmd_id = cmd_id;
}

static void 
parse_cmd_parm(struct TCPRECORD *sess, struct NetFrame *frame, struct StringReassembler *cmd, struct StringReassembler *parm)
{
	struct POP3REQUEST *req = &sess->layer7.pop3req;
	
	if (cmd->length == 0)
		return;

	set_reverse_cmd(sess, 1);

	switch (toupper(cmd->the_string[0])) {
	case 'A':
		/*
		 * Sniff the username and password
		 */
		if (MATCHES("APOP", cmd->the_string, cmd->length)) {
			const unsigned char *user;
			unsigned user_length=0;
			const unsigned char *md5;
			unsigned md5_length=0;
			const unsigned char *challenge;
			unsigned challenge_length;
			unsigned i;

			set_reverse_cmd(sess, POP3_APOP);

			if (parm->length == 0)
				break;

			/*
			 * We have the username and the MD5 hash in the string, so we
			 * need to split them out. Example:
			 *  APOP mrose c4c9334bac560ecc979e58001b3e22fb
			 */
			user = parm->the_string;
			i=0;
			while (i<parm->length && !isspace(parm->the_string[i]))
				i++;
			user_length = i;

			while (i<parm->length && isspace(parm->the_string[i]))
				i++;

			md5 = parm->the_string + i;
			while (i<parm->length && !isspace(parm->the_string[i])) {
				i++;
				md5_length++;
			}

			/* We need to extract the challenge from the reverse
			 * side of the connection if there is one */
			if (sess->reverse && sess->reverse->str->length) {
				challenge = sess->reverse->str->the_string;
				challenge_length = sess->reverse->str->length;
			} else {
				challenge = (const unsigned char*)"";
				challenge_length = 0;
			}

			/* Now log the entire record */
			JOTDOWN(sess->eng->ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("POP3-apop", user, user_length),
				JOT_PRINT("Password-Hash", md5, md5_length),
				JOT_PRINT("Password-Challenge", challenge, challenge_length),
				0);
		}
		break;
	case 'D':
		if (MATCHES("DELE", cmd->the_string, cmd->length)) {
			/*Examples:
			 *	 C: DELE 1
			 *	 S: +OK message 1 deleted
			 *		...
			 *	 C: DELE 2
			 *	 S: -ERR message 2 already deleted
			 */

			set_reverse_cmd(sess, POP3_DELE);
		}
		break;
	case 'L':
		if (MATCHES("LIST", cmd->the_string, cmd->length)) {
			/*Examples:
			 *	 C: LIST
			 *	 S: +OK 2 messages (320 octets)
			 *	 S: 1 120
			 *	 S: 2 200
			 *	 S: .
			 *	 C: LIST 2
			 *	 S: +OK 2 200
			 *	 C: LIST 3
			 *	 S: -ERR no such message, only 2 messages in maildrop
			 */
			set_reverse_cmd(sess, POP3_LIST);
		}
		break;
	case 'N':
		if (MATCHES("NOOP", cmd->the_string, cmd->length)) {
			/*Examples:
			 *	 C: NOOP
			 *	 S: +OK
			 */
			set_reverse_cmd(sess, POP3_NOOP);
		}
		break;
	case 'P':
		if (MATCHES("PASS", cmd->the_string, cmd->length)) {
			set_reverse_cmd(sess, POP3_PASS);
			if (req->username)
				JOTDOWN(sess->eng->ferret,
					JOT_SRC("ID-IP", frame),
					JOT_PRINT("POP3-user", req->username->str, req->username->length),
					JOT_PRINT("POP3-passwd", parm->the_string, parm->length),
					0);
			else
				JOTDOWN(sess->eng->ferret,
					JOT_SRC("ID-IP", frame),
					JOT_PRINT("POP3-passwd", parm->the_string, parm->length),
					0);
		}
		break;
	case 'Q':
		if (MATCHES("QUIT", cmd->the_string, cmd->length)) {
			/*Examples:
			 *	 C: QUIT
			 *	 S: +OK dewey POP3 server signing off (maildrop empty)
			 *		...
			 *	 C: QUIT
			 *	 S: +OK dewey POP3 server signing off (2 messages left)
			 */
			set_reverse_cmd(sess, POP3_QUIT);
		}
		break;
	case 'R':
		if (MATCHES("RETR", cmd->the_string, cmd->length)) {
			/* Examples:
			 *	 C: RETR 1
			 *	 S: +OK 120 octets
			 *	 S: <the POP3 server sends the entire message here>
			 *	 S: .
			 */
			set_reverse_cmd(sess, POP3_RETR);
		}
		else if (MATCHES("RSET", cmd->the_string, cmd->length)) {
			/* Examples:
			 *	 C: RSET
			 *	 S: +OK maildrop has 2 messages (320 octets)
			 */
			set_reverse_cmd(sess, POP3_RSET);
		}
		break;
	case 'S':
		if (MATCHES("STAT", cmd->the_string, cmd->length)) {
			/* Examples:
             *  C: STAT
             *  S: +OK 2 320
			 */
			set_reverse_cmd(sess, POP3_STAT);
		}
		break;
	case 'T':
		if (MATCHES("TOP", cmd->the_string, cmd->length)) {
			/*Examples:
			 *	 C: TOP 1 10
			 *	 S: +OK
			 *	 S: <the POP3 server sends the headers of the
			 *		message, a blank line, and the first 10 lines
			 *		of the body of the message>
			 *	 S: .
			 *		...
			 *	 C: TOP 100 3
			 *	 S: -ERR no such message
			 */
			set_reverse_cmd(sess, POP3_TOP);
		}
		break;
	case 'U':
		/*
		 * Sniff the username and password
		 */
		if (MATCHES("USER", cmd->the_string, cmd->length)) {
			/* Examples:
             *	C: USER frated
             *	S: -ERR sorry, no mailbox for frated here
             *   ...
             *	C: USER mrose
             *	S: +OK mrose is a real hoopy frood
			 */
			set_reverse_cmd(sess, POP3_USER);

			/* Remember the username for later activity on this connection */
			req->username = stringtab_lookup(sess->eng->stringtab, parm->the_string, parm->length);

			/* Jot the username */
			JOTDOWN(sess->eng->ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("POP3-user", parm->the_string, parm->length),
				0);
		}
		if (MATCHES("UIDL", cmd->the_string, cmd->length)) {
			    /*Examples:
				 *	  C: UIDL
				 *	  S: +OK
				 *	  S: 1 whqtswO00WBw418f9t5JxYwZ
				 *	  S: 2 QhdPYR:00WBw1Ph7x7
				 *	  S: .
				 *		 ...
				 *	  C: UIDL 2
				 *	  S: +OK 2 QhdPYR:00WBw1Ph7x7
				 *		 ...
				 *	  C: UIDL 3
				 *	  S: -ERR no such message, only 2 messages in maildrop
				 */
			set_reverse_cmd(sess, POP3_UIDL);
		}
		break;
	default:
		/* See 'read-code.txt' about the subject 'SAMPLING' */
		SAMPLE(sess->eng->ferret,"POP3", JOT_PRINT("command", cmd->the_string, cmd->length));

		/* Remember the command */
		JOTDOWN(sess->eng->ferret,
			JOT_SZ("proto", "POP3"),
			JOT_PRINT("op", cmd->the_string, cmd->length),
			JOT_PRINT("parm",	parm->the_string, parm->length),
			JOT_SRC("client", frame),
			JOT_DST("server", frame),
			0);

		break;
	}


	strfrag_finish(cmd);
	strfrag_finish(parm);
}

void parse_pop3_request(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct POP3REQUEST *req = &sess->layer7.pop3req;
	unsigned offset=0;
	unsigned state;
	unsigned sublen;
	struct StringReassembler *cmd = &sess->str[0];
	struct StringReassembler *parm = &sess->str[1];
	enum {	S_START, S_LEADING_WHITESPACE, S_COMMAND,
			S_COMMAND_SPACE, S_PARM, S_UNTIL_EOL};

	UNUSEDPARM(frame);

	/* IF CLOSING CONNECTION */
	if (px == TCP_CLOSE) {
		return;
	}

	frame->layer7_protocol = LAYER7_POP3;

	state = req->state;
	
	while (offset<length)
	switch (state) {
	case S_START:
		state++;
		strfrag_init(cmd);
		strfrag_init(parm);
		break;
	case S_LEADING_WHITESPACE:
		if (isspace(px[offset]))
			offset++;
		else
			state++;
		break;
	case S_COMMAND:
		for (sublen=0; offset+sublen<length && !isspace(px[offset+sublen]); sublen++)
			;
		strfrag_append(cmd, px+offset, sublen);
		offset += sublen;
		if (offset<length) {
			state++;
		}
		break;
	case S_COMMAND_SPACE:
		if (isspace(px[offset]) && px[offset] != '\n')
			offset++;
		else
			state++;
		break;
	case S_PARM:
		for (sublen=0; offset+sublen<length && px[offset+sublen] != '\n'; sublen++)
			;
		while (sublen && offset+sublen<length && isspace(px[offset+sublen-1]))
			sublen--;
		strfrag_append(parm, px+offset, sublen);
		offset += sublen;
		if (offset < length) {

			/* We are done parsing the commands */
			parse_cmd_parm(sess, frame, cmd, parm);

			state = S_UNTIL_EOL;
		}
		break;
	case S_UNTIL_EOL:
		while (offset<length && px[offset] != '\n')
			offset++;
		if (offset<length) {
			offset++; /*remove '\n'*/
			strfrag_init(cmd);
			strfrag_init(parm);
			state = S_COMMAND;
		}
		break;
	}

	req->state = state;
}

/*r:\regress-lincoln-pop3.pcap*/
		
