/* Shared definitions between the eBPF kernel program and the user-space daemon. */
#ifndef CREDGUARD_H
#define CREDGUARD_H

#define TASK_COMM_LEN 16
#define PAYLOAD_LEN   96

/* action field in struct event */
#define ACT_OBSERVE 0  /* monitor mode: metadata access seen (payload attached) */
#define ACT_BLOCKED 1  /* enforce mode: connection to metadata denied           */

struct event {
	__u32 pid;
	__u32 uid;
	__u32 daddr;                 /* destination IPv4, network byte order */
	__u16 dport;                 /* destination port, host byte order    */
	__u8  action;                /* ACT_OBSERVE / ACT_BLOCKED            */
	__u8  payload_len;           /* bytes captured in payload[]          */
	char  comm[TASK_COMM_LEN];   /* process name                         */
	char  payload[PAYLOAD_LEN];  /* first bytes of the HTTP request      */
};

#endif /* CREDGUARD_H */
