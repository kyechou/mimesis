#include <unistd.h> 
#include <stdio.h> 
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#include <iostream>
#include <fcntl.h>
#include <fstream>
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bitset>
#include <map>
#include <string>
#include <LB_algo.h>
#include <RoundRobin.h>
using namespace std;
#define PORT 8088
#define STRLen 10000
#define LOCALHOST 2130706433

std::map<std::string, std::string> http_request;
std::string LB;
RoundRobin RR();

void parse_args(int argc, char **argv);

int passiveTCP()
{
	int sockfd;
	int newsockfd;
	struct sockaddr_in serv_addr;

	if((sockfd=socket(AF_INET,SOCK_STREAM,0))<0){
		perror("socket failed");
		exit(-1);
	}

	int isSetSockOk = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &isSetSockOk, sizeof(int)) == -1) {
	       perror("SetSockOpt error");
	       exit(-1);
	}

	bzero((char*)&serv_addr,sizeof(serv_addr));
	serv_addr.sin_family=AF_INET;
	serv_addr.sin_addr.s_addr=htonl(INADDR_ANY);
	serv_addr.sin_port = htons(PORT);

	if(bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0){
		perror("Server can't bind local address.");
		exit(-1);
	}

	listen(sockfd, 30);
	return sockfd;
}

int main(int argc, char *argv[])
{
    int server_fd, new_socket, cli_fd, valread;
    struct sockaddr_in cli_addr; // address of the backend servers
    int caddrlen = sizeof(cli_addr);
    char buffer[STRLen] = {0};
    struct addrs* cli_list;
    int lines = 0;
    string file_lines[20];

    parse_args(argc, argv);

    // read server list from config files
    ifstream algofile ("../configs/"+LB);
    wihle(!algofile.eof())
    {
        getline(algofile, file_lines[lines++]);
    }

    // initial load balance argorithm class 
    cli_list = new struct addrs[lines];
    for(int i; i<lines; i++){
        cli_list[i].ip = file_lines[i].substr(0, file_lines[i].find(":"));
	cli_list[i].port = stoi(file_lines[i].substr(1, file_lines[i].find(":")));
    }
    if(LB == "roundrobin"){
        RR.set_cli_addrs(cli_list);
    }

    // get load balancer fd
    server_fd = passiveTCP();
    if(server_fd == -1){
    	exit(EXIT_FAILURE);
    }

    printf("Load Balancer is listening\n");

    while(1){
        new_socket=accept(server_fd, (struct sockaddr*)&cli_addr, caddrlen); // use new_socket to send/receive data

	if(new_socket < 0){
	    perror("Server: accept error");
	}

	// get client address
	struct addrs cli;
	if(LB == "roundrobin"){
            cli = RR.select_server();
	}

	if((childpid=fork())<0){
            perror("Server: fork error");
        }
	else if(childpid == 0){
	    dup2(new_socket, 1);

	    int len = read(new_socket,buffer,STRLen);

	    if ((cli_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	    {
                perror("client socket create error\n");
		exit(EXIT_FAILURE);
	    }

	    cli_addr.sin_family = AF_INET;
	    if(cli.ip == "localhost") cli_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	    else cli_addr.sin_addr.s_addr = htonl(cli.ip);
	    cli_addr.sin_port = cli.port;

	    if (connect(cli_fd, (struct sockaddr *)&cli_addr, sizeof(cli_addr)) < 0){
	        perror("\nConnection Failed \n");
		exit(EXIT_FAILURE);
	    }

	    send(cli_fd, buffer , len , 0 );
            valread = read(cli_fd, buffer, STRLen);
	    send(new_socket, buffer, valread, 0);

	    close(cli_fd);
	    close(new_socket);
        }
    }
    close(new_socket);

    return 0;
}

static inline void usage(const std::string& progname)
{
	std::cout << 
		"Usage: " + progname + " [-h] -a <algo>\n"
		"    -h, --help             print this help message\n"
		"    -a, --algo <algo>      specify algorithm name\n";
}

void parse_args(int argc, char **argv)
{
	int opt;
	const char *optstring = "ha:";
	const struct option longopts[] = {
		{"help",    no_argument,       0, 'h'},
		{"algo",    required_argument, 0, 'a'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, optstring, longopts, NULL)) != -1) {
		switch (opt) {
			case 'h':
				usage(argv[0]);
				exit(EXIT_SUCCESS);
			case 'a':
				LB = optarg;
				break;
			default:
				usage(argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	if (LB.empty()) {
		std::cerr << "Try '" << argv[0] << " -h' for more information" << std::endl;
		exit(EXIT_FAILURE);
	}
}
