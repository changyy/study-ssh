// telnet socket usage
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libssh/libssh.h>
#define MAX_BUF 8096

// telnet parser
#include <iostream>
#include <string>

void sendCommand(std::string data);
void sendQuitCommand();

char run_begin_time[32] = {0};
char run_current_time[32] = {0};

int sockd,cli,state,cli_len,words;
ssh_channel my_ssh_channel;

int verify_knownhost(ssh_session session) {
	int state, hlen, return_value;
	unsigned char *hash = NULL;
	char *hexa;
	char buf[10];

	state = ssh_is_server_known(session);
	if ( (hlen = ssh_get_pubkey_hash(session,&hash)) < 1) {
		return -1;
	}
	return_value = 0;
	switch(state) {
		case SSH_SERVER_KNOWN_OK:
			hexa = ssh_get_hexa(hash, hlen);
			std::cerr << "SSH_SERVER_KNOWN_OK, Public key hash: " << hexa << std::endl;
			free(hexa);
			break;
		case SSH_SERVER_KNOWN_CHANGED:
			//ssh_print_hexa("Public key hash",hash,hlen);
			hexa = ssh_get_hexa(hash, hlen);
			std::cerr << "SSH_SERVER_KNOWN_CHANGED, Public key hash: " << hexa << std::endl;
			free(hexa);
			std::cerr << "For security reasons, connection will be stopped" << std::endl;
			return_value = -1;
			break;
		case SSH_SERVER_FOUND_OTHER:
			std::cerr << "SSH_SERVER_FOUND_OTHER" << std::endl;
			return_value = -1;
			break;
		case SSH_SERVER_FILE_NOT_FOUND:
		case SSH_SERVER_NOT_KNOWN:
			hexa = ssh_get_hexa(hash, hlen);
			std::cerr << "Public key hash: " << hexa << std::endl;
			free(hexa);
			if (ssh_write_knownhost(session) < 0) {
				std::cerr << "ssh_write_knownhost, Error: " << strerror(errno) << std::endl;
				return_value = -1;
			}
			break;
		case SSH_SERVER_ERROR:
			std::cerr << "SSH_SERVER_ERROR, Error: " << strerror(errno) << std::endl;
			return_value = -1;
			break;
	}
	free(hash);
	return return_value;
}

int main(int argc, char* argv[])
{
	time_t t_begin = time(NULL), t_current = time(NULL); 
	struct tm *tm_begin = localtime(&t_begin), *tm_current = localtime(&t_current);
	strftime(run_begin_time, sizeof run_begin_time, "%Y/%m/%d %H:%M:%S", tm_begin);

	struct sockaddr_in serv_name;
	char buf[MAX_BUF+1],dis[MAX_BUF+1];
	fd_set readfds;
	FILE *fp, *log;

	int rc = 0;
	int ssh_port = 22;
	my_ssh_channel = NULL;
	ssh_session my_ssh_session = ssh_new();
	if (my_ssh_session == NULL)
		exit(-1);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "ptt.cc");
	ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &ssh_port);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, "bbs");

	rc = ssh_connect(my_ssh_session);
	if (rc!=SSH_OK) {
		std::cerr << "Error connecting to localhost: " << ssh_get_error(my_ssh_session) << std::endl;
		ssh_free(my_ssh_session);
		exit(-1);
	}
	if (verify_knownhost(my_ssh_session) < 0) {
		std::cerr << "verify_knownhost failed" << std::endl;
		ssh_free(my_ssh_session);
		exit(-1);
	}

	// no use
	/*
	if (false) {
		rc = ssh_userauth_publickey_auto(my_ssh_session, "bbs", "");
		if (rc != SSH_AUTH_SUCCESS) {
			switch(rc) {
				case SSH_AUTH_ERROR:
					std::cerr << "ssh_userauth_publickey_auto failed " << ssh_get_error(my_ssh_session) << std::endl;
					ssh_free(my_ssh_session);
					exit(-1);
					break;
				case SSH_AUTH_DENIED:
					std::cerr << "ssh_userauth_publickey_auto is SSH_AUTH_DENIED: " << ssh_get_error(my_ssh_session) << std::endl;
					ssh_free(my_ssh_session);
					exit(-1);
					break;
				case SSH_AUTH_PARTIAL:
					std::cerr << "ssh_userauth_publickey_auto is SSH_AUTH_PARTIAL: " << ssh_get_error(my_ssh_session) << std::endl;
					ssh_free(my_ssh_session);
					exit(-1);
					break;
				case SSH_AUTH_AGAIN:
					std::cerr << "ssh_userauth_publickey_auto is SSH_AUTH_AGAIN: " << ssh_get_error(my_ssh_session) << std::endl;
					ssh_free(my_ssh_session);
					exit(-1);
					break;
			}
		} else {
			std::cerr << "ssh_userauth_publickey_auto is SSH_AUTH_SUCCESS" << std::endl;
		}
	}
	*/

	if ((rc = ssh_userauth_none(my_ssh_session,NULL)) != SSH_AUTH_SUCCESS) {
		std::cerr << "ssh_userauth_none is not SSH_AUTH_SUCCESS: " << ssh_get_error(my_ssh_session) << std::endl;
		ssh_free(my_ssh_session);
		exit(-1);
	}

	std::cerr << "SSH connection" << std::endl;

	if (NULL == (my_ssh_channel = ssh_channel_new(my_ssh_session))) {
		std::cerr << "ssh_channel_new is NULL: " << ssh_get_error(my_ssh_session) << std::endl;
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		exit(-1);
	}

	if (SSH_OK != (rc = ssh_channel_open_session(my_ssh_channel))) {
		std::cerr << "ssh_channel_open_session is not SSH_OK: " << ssh_get_error(my_ssh_session) << std::endl;
		ssh_channel_send_eof(my_ssh_channel);
		ssh_channel_close(my_ssh_channel);
		ssh_channel_free(my_ssh_channel);
		my_ssh_channel = NULL;
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		exit(-1);
	}
	if (SSH_OK != (rc = ssh_channel_request_pty(my_ssh_channel))) {
		std::cerr << "ssh_channel_request_pty is not SSH_OK: " << ssh_get_error(my_ssh_session) << std::endl;
		ssh_channel_send_eof(my_ssh_channel);
		ssh_channel_close(my_ssh_channel);
		ssh_channel_free(my_ssh_channel);
		my_ssh_channel = NULL;
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		exit(-1);
	}
	if (SSH_OK != (rc = ssh_channel_change_pty_size(my_ssh_channel, 80, 24))) {
		std::cerr << "ssh_channel_change_pty_size is not SSH_OK: " << ssh_get_error(my_ssh_session) << std::endl;
		ssh_channel_send_eof(my_ssh_channel);
		ssh_channel_close(my_ssh_channel);
		ssh_channel_free(my_ssh_channel);
		my_ssh_channel = NULL;
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		exit(-1);
	}
	if (SSH_OK != (rc = ssh_channel_request_shell(my_ssh_channel))) {
		std::cerr << "ssh_channel_request_shell is not SSH_OK: " << ssh_get_error(my_ssh_session) << std::endl;
		ssh_channel_send_eof(my_ssh_channel);
		ssh_channel_close(my_ssh_channel);
		ssh_channel_free(my_ssh_channel);
		my_ssh_channel = NULL;
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		exit(-1);
	}

	/*
	// https://github.com/rofl0r/libssh/blob/master/examples/sample.c#L303
	// look stdin
	FD_ZERO(&readfds);
	while(1) {
		FD_ZERO(&readfds);
		FD_SET(ssh_get_fd(my_ssh_session), &readfds);
		select(ssh_get_fd(my_ssh_session)+1,&readfds,0,0,0);
		if(FD_ISSET(ssh_get_fd(my_ssh_session), &readfds)) {
			ssh_set_fd_toread(my_ssh_session);
		}
	}
	*/

	while(my_ssh_channel && !ssh_channel_is_closed(my_ssh_channel)) {
		if (ssh_channel_poll(my_ssh_channel, 0) == 0) {
			continue;
		}
		words = ssh_channel_read(my_ssh_channel, buf, MAX_BUF, 0);
		if (words == -1) {
			std::cerr << "##__## ssh_channel_read, error: " << ssh_get_error(my_ssh_session) << std::endl;
			ssh_channel_send_eof(my_ssh_channel);
			ssh_channel_close(my_ssh_channel);
			ssh_channel_free(my_ssh_channel);
			my_ssh_channel = NULL;
			ssh_disconnect(my_ssh_session);
			ssh_free(my_ssh_session);
			exit(-1);
		} else if (words == 0) {
			std::cerr << "##__## ssh_channel_read empty, break! " << std::endl;
			break;
		}
		buf[words] = '\0';
		buf[MAX_BUF] = '\0';
		std::cerr << "##__## ssh_channel_read Receiverd: " << strlen(buf)  << std::endl;

		t_current = time(NULL); 
		tm_current = localtime(&t_current);
		strftime(run_current_time, sizeof run_current_time, "%Y/%m/%d %H:%M:%S", tm_current);
		std::cerr << "##__## Now: " << run_current_time << ", Begin: " << run_begin_time << ", Cost: " << difftime(t_current, t_begin) << std::endl;

		std::cout << buf;

		//log = fopen("/tmp/bbs.log", "ab+");
		//write(fileno(log),buf,words);
		//fclose(log);
	}

	std::cout << "##__## SSH Done" << std::endl;

	// 收尾
	if (my_ssh_channel != NULL) {
		ssh_channel_send_eof(my_ssh_channel);
		ssh_channel_close(my_ssh_channel);
		ssh_channel_free(my_ssh_channel);
		my_ssh_channel = NULL;
	}

	ssh_disconnect(my_ssh_session);
	ssh_free(my_ssh_session);
	return 0;
}

void sendCommand(std::string data) {
	static std::string prev;
	if (prev.size()) {
		if (prev == data && data == "q")
			return;
	}
	prev = data;
	if (my_ssh_channel)
		ssh_channel_write(my_ssh_channel, data.c_str(), data.size());
	else
		write(sockd, data.c_str(), data.size());
}
