#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

char rule[256];

void updateRejectRule(char *username, char *macAddr){
    /* delete existing mac address reject rule, if any */
    sprintf(rule, "iptables -D FORWARD -m mac --mac-source %s -j REJECT", macAddr);
    printf("%s\n", rule);
    printf("result: %d\n", system(rule));
    /* insert a new mac address reject rule at the top */
    sprintf(rule, "iptables -I FORWARD -m mac --mac-source %s -j REJECT", macAddr);
    printf("%s\n", rule);
    printf("result: %d\n", system(rule));
    /* delete legacy localhost drop rule, if any */
    sprintf(rule, "iptables -D OUTPUT -m owner --uid-owner %s -j DROP", username);
    printf("%s\n", rule);
    printf("result: %d\n", system(rule));
    /* delete existing localhost reject rule, if any */
    sprintf(rule, "iptables -D OUTPUT -m owner --uid-owner %s -j REJECT", username);
    printf("%s\n", rule);
    printf("result: %d\n", system(rule));
    /* append a new localhost reject rule at the end */
    sprintf(rule, "iptables -A OUTPUT -m owner --uid-owner %s -j REJECT", username);
    printf("%s\n", rule);
    printf("result: %d\n", system(rule));
}

int insertAcceptRule(char *username, char *macAddr, char *dateTime){
    /* insert new mac address accept rule above all other rules */
    if (dateTime) {
        sprintf(rule, "iptables -I FORWARD -m mac --mac-source %s -j ACCEPT -m time --datestop %s", macAddr, dateTime);
    } else {
        sprintf(rule, "iptables -I FORWARD -m mac --mac-source %s -j ACCEPT", macAddr);
    }
    printf("%s\n", rule);
    int rc = system(rule);
    printf("result: %d\n", rc);
    if (rc == 0) {
        /* insert new localhost accept rule above all other rules */
        if (dateTime) {
            sprintf(rule, "iptables -I OUTPUT -m owner --uid-owner %s -j ACCEPT -m time --datestop %s", username, dateTime);
        } else {
            sprintf(rule, "iptables -I OUTPUT -m owner --uid-owner %s -j ACCEPT", username);
        }
        printf("%s\n", rule);
        rc = system(rule);
        printf("result: %d\n", rc);
    }
    return rc;
}

int deleteAcceptRule(char *username, char *macAddr, char *dateTime){
    /* remove existing mac address accept rule */
    if (dateTime) {
        sprintf(rule, "iptables -D FORWARD -m mac --mac-source %s -j ACCEPT -m time --datestop %s", macAddr, dateTime);
    } else {
        sprintf(rule, "iptables -D FORWARD -m mac --mac-source %s -j ACCEPT", macAddr);
    }
    printf("%s\n", rule);
    int rc = system(rule);
    printf("result: %d\n", rc);
    if (rc == 0) {
        /* remove existing localhost accept rule */
        if (dateTime) {
            sprintf(rule, "iptables -D OUTPUT -m owner --uid-owner %s -j ACCEPT -m time --datestop %s", username, dateTime);
        } else {
            sprintf(rule, "iptables -D OUTPUT -m owner --uid-owner %s -j ACCEPT", username);
        }
        printf("%s\n", rule);
        rc = system(rule);
        printf("result: %d\n", rc);
    }
    return rc;
}

int main(int argc, char *argv[]){
    int rc = 0;

	if (argc >= 2) {
		char *command = argv[1];
		if (strcmp(command, "--help") == 0) {
			printf("usage: %s (on|off) username mac_address [expiry_time]\n", argv[0]);
		} else if (argc >= 4) {
			setuid(0);
			char *username = argv[2];
			char *macAddr = argv[3];
			char *dateTime = argc >= 5 ? argv[4] : NULL;
			updateRejectRule(username, macAddr);
			if (strcmp(command, "on") == 0) {
			    deleteAcceptRule(username, macAddr, dateTime); /* delete old rule, just in case */
			    rc = insertAcceptRule(username, macAddr, dateTime);
			} else if (strcmp(command, "off") == 0) {
			    rc = deleteAcceptRule(username, macAddr, dateTime);
			}
		}
	} else {
		printf("Invalid number of arguments (%d for 2)\n", argc);
	}
	return rc;
}