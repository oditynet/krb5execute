//============================================================================
// Name        : krb5client.cpp
// Author      : odity
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <krb5.h>
#include <errno.h>
//#include <zephyr/zephyr.h>
#include <signal.h>
#include <curses.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <pwd.h>
using namespace std;
int sockfd, curs_start, use_curses, debug_flag;
static inline int data_eq(krb5_data d1, krb5_data d2)
{
    return (d1.length == d2.length && (d1.length == 0 ||
                                       !memcmp(d1.data, d2.data, d1.length)));
}
static krb5_boolean is_local_tgt(krb5_principal princ, krb5_data *realm)
{
    return princ->length == 2 && data_eq(princ->realm, *realm); //&&
       // data_eq_string(princ->data[0], KRB5_TGS_NAME) &&
       // data_eq(princ->data[1], *realm);
}
bool ts_after(krb5_timestamp a, krb5_timestamp b)
{
    return (uint32_t)a > (uint32_t)b;
}
int main(int argc, char **argv) {
	char *execstr = NULL;
	int ret, writebufflen;
	krb5_context context;
	krb5_ccache ccache;
	char *my_principal_string;
	krb5_address local_address, foreign_address;
	struct sockaddr_in faddr, laddr;
	size_t laddrlen;
	WINDOW *sendwin = NULL, *receivewin = NULL, *sepwin = NULL;
	fd_set fdset;
	struct sigaction sigact;
	char writebuff[1024], startupmsg[2048];
	krb5_principal my_principal;
	krb5_auth_context auth_context;
	int opt;
	extern char *optarg;
	extern int optind;
	if (argc == 1){
		cout<<argv[0]<<" -e [execstr]";
		exit(1);
	}
	if (argv[0][0] == '-') argv[0]++;
	while((opt = getopt(argc, argv, "e:")) != EOF) {
	    switch (opt) {
	    case 'e':
	      execstr = optarg;
	      break;
	    default:
	      cout<<argv[0]<<" -e [execstr]";
	      exit(0);
	    }
	  }

	putenv("KRB5_KTNAME=/dev/null");	/* kerberos V can kiss my pasty white ass */
	ret = krb5_init_context(&context);
	if (ret){
		cout<<"Error: krb5_init_context";
		exit(1);
	}
	ret = krb5_cc_default(context, &ccache);
	if (ret){
		cout<<"Error: krb5_cc_default";
		exit(1);
	}
	ret = krb5_cc_get_principal(context, ccache, &my_principal); // ticket none
	if (ret){
		cout<<"Error: krb5_cc_get_principal";
		exit(1);
	}
	krb5_cc_cursor cur = NULL;
	 krb5_creds creds;
	 krb5_timestamp now;

	 now = time(0);
	 ret=krb5_cc_start_seq_get(context, ccache, &cur);
	 while ((ret = krb5_cc_next_cred(context, ccache, &cur, &creds)) == 0) {
	         if (is_local_tgt(creds.server, &my_principal->realm)) {
	             if (ts_after(creds.times.endtime, now))
	            	 cout<<"Ticket is valid"<<endl;
	             else
	             {
	            	 cout<<"Ticket is expired";
	            	 exit(1);
	             }
	         }
	         krb5_free_cred_contents(context, &creds);
	     }
	 ret = krb5_unparse_name(context, my_principal, &my_principal_string);
	if (ret){
		cout<<"Error: krb5_unparse_name";
		exit(1);
	}
	cout<<"you are "<<my_principal_string<<endl;
	int uid=getuid();

	struct stat info;
	int err = stat(execstr, &info);  // Error check omitted
	if (err != 0){
		cout<<execstr<<" :Path is not correct"<<endl;
		exit(1);
	}
	struct passwd *pw = getpwuid(info.st_uid);
	if (pw->pw_uid == uid)
	{
			cout<<"Run "<<execstr<<endl;
			system(execstr);
	}
	else{
		cout<<"Permission denied...";
	}
	return 0;
}
