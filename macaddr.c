#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char *argv[]){
    char rule[256];
    int rc = 0;

	if (argc >= 2) {
		if (strcmp(argv[1], "--help") == 0) {
			printf("usage: %s (on|off) mac_address [expiry_time]\n", argv[0]);
		} else if (argc >= 3) {
			setuid(0);
			if (strcmp(argv[1], "on") == 0) {
				if (argc >= 4) {
					sprintf(rule, "iptables -I FORWARD -m mac --mac-source %s -j ACCEPT -m time --datestop %s", argv[2], argv[3]);
				} else {
					sprintf(rule, "iptables -I FORWARD -m mac --mac-source %s -j ACCEPT", argv[2]);
				}
				printf("%s\n", rule);
				rc = system(rule);
				printf("result: %d\n", rc);
			} else if (strcmp(argv[1], "off") == 0) {
				if (argc >= 4) {
					sprintf(rule, "iptables -D FORWARD -m mac --mac-source %s -j ACCEPT -m time --datestop %s", argv[2], argv[3]);
				} else {
					sprintf(rule, "iptables -D FORWARD -m mac --mac-source %s -j ACCEPT", argv[2]);
				}
				printf("%s\n", rule);
				rc = system(rule);
				printf("result: %d\n", rc);
			}
		}
	} else {
		printf("Invalid number of arguments (%d for 2)\n", argc);
	}
	return rc;
}