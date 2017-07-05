#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

char rule[256];

void updateRejectRule(char *macAddr){
    /* delete old reject rule, if any */
    sprintf(rule, "iptables -D FORWARD -m mac --mac-source %s -j REJECT", macAddr);
    printf("%s\n", rule);
    printf("result: %d\n", system(rule));
    /* insert a new reject rule at the top */
    sprintf(rule, "iptables -I FORWARD -m mac --mac-source %s -j REJECT", macAddr);
    printf("%s\n", rule);
    printf("result: %d\n", system(rule));
}

int insertAcceptRule(char *macAddr, char *dateTime){
    /* insert new accept rule above all other rules */
    if (dateTime) {
        sprintf(rule, "iptables -I FORWARD -m mac --mac-source %s -j ACCEPT -m time --datestop %s", macAddr, dateTime);
    } else {
        sprintf(rule, "iptables -I FORWARD -m mac --mac-source %s -j ACCEPT", macAddr);
    }
    printf("%s\n", rule);
    int rc = system(rule);
    printf("result: %d\n", rc);
    return rc;
}

int deleteAcceptRule(char *macAddr, char *dateTime){
    /* remove accept rule */
    if (dateTime) {
        sprintf(rule, "iptables -D FORWARD -m mac --mac-source %s -j ACCEPT -m time --datestop %s", macAddr, dateTime);
    } else {
        sprintf(rule, "iptables -D FORWARD -m mac --mac-source %s -j ACCEPT", macAddr);
    }
    printf("%s\n", rule);
    int rc = system(rule);
    printf("result: %d\n", rc);
    return rc;
}

int main(int argc, char *argv[]){
    int rc = 0;

	if (argc >= 2) {
		if (strcmp(argv[1], "--help") == 0) {
			printf("usage: %s (on|off) mac_address [expiry_time]\n", argv[0]);
		} else if (argc >= 3) {
			setuid(0);
			updateRejectRule(argv[2]);
			if (strcmp(argv[1], "on") == 0) {
			    deleteAcceptRule(argv[2], argc >=4 ? argv[3] : NULL); /* delete old rule, just in case */
			    rc = insertAcceptRule(argv[2], argc >=4 ? argv[3] : NULL);
			} else if (strcmp(argv[1], "off") == 0) {
			    rc = deleteAcceptRule(argv[2], argc >=4 ? argv[3] : NULL);
			}
		}
	} else {
		printf("Invalid number of arguments (%d for 2)\n", argc);
	}
	return rc;
}