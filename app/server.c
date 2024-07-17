#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

static char *directory;

typedef enum 
{
	HTTP_GET,
	HTTP_POST
}http_method;

typedef enum 
{
	HTTP_1_1
}http_version;

typedef enum 
{
	ECHO,
	USER_AGENT,
	FILER
}req_type;

typedef struct node
{
	char* argument;
	struct node *next;
}node;

typedef struct path
{
	size_t numOfArguments;
	node arguments;
}path;

typedef struct req_line
{
	http_method method;
	path path;
	http_version version;
}req_line;


typedef struct header
{
	char* label;
	char* value;
	struct header *next;
}header;

typedef struct req_header
{
	int headersNumber;
	header headers;
}req_header;

typedef struct http_req
{
	req_line req_line;
	req_header req_header;
	char* req_body;
}http_req;

size_t getNumberOfArguments(char *rawPath)
{
	size_t lengthOfRawPath = strlen(rawPath);
	char placeholderPath[lengthOfRawPath+1];
	strcpy(placeholderPath,rawPath);

	size_t numberOfArguments = 0;

	char* token = strtok(placeholderPath,"/");

	while(token != NULL)
	{
		numberOfArguments += 1;
		token = strtok(NULL,"/");
	}

	return numberOfArguments;
}

path pathParser(char* rawPath)
{
	path path = {0};
	
	path.numOfArguments = getNumberOfArguments(rawPath);

	if(path.numOfArguments == 0) return path;
	
	char* token = strtok(rawPath,"/");

	node *placeholder = &path.arguments;

	while(token != NULL)
	{
		node argument = {0};
		argument.argument = malloc(sizeof(char) * strlen(token) + 1);
		argument.next = (node *)malloc(sizeof(node));
		strcpy(argument.argument,token);
		*placeholder = argument;
		placeholder = placeholder->next;
		token = strtok(NULL,"/");
	}
	
	return path;
}

req_line reqLineParser(char* rawReqLine)
{
	req_line req_line = {0};
	
	char* method = strtok(rawReqLine," ");
	char* path = strtok(NULL," ");
	char* version = strtok(NULL," ");

	if(strcmp(method,"GET")==0)
	{
		req_line.method = HTTP_GET;
	}
	else if(strcmp(method,"POST")==0)
	{
		req_line.method = HTTP_POST;
	}

	req_line.path = pathParser(path);

	if(strcmp(version,"HTTP/1.1")==0)
	{
		req_line.version = HTTP_1_1;
	}

	return req_line;
}

int getNumberOfHeaders(char* rawReq)
{

	size_t lengthOfRawReq = strlen(rawReq);
	char placeholderReq[lengthOfRawReq];
	strcpy(placeholderReq,rawReq);
	int numberOfHeaders = -1;

	char* token = strtok(placeholderReq,"\r\n\r\n");
	
	while(token != NULL)
	{
		numberOfHeaders += 1;
		token = strtok(NULL,"\r\n");
	}

	return numberOfHeaders;
}

header headerParser(node headerStart, int* numberOfHeaders)
{
	header headers = {0};
	node* ptrRaw = &headerStart;
	header* ptrHeader = &headers;

	for(int i = 0; i < *numberOfHeaders; ++i)
	{
		char* label = strtok(ptrRaw->argument,": ");
		char* value = strtok(NULL,": ");

		if(value == NULL) 
		{
			break;
			*numberOfHeaders -= 1;
		}

		ptrHeader->label = malloc(sizeof(char) * strlen(label) + 1);
		strcpy(ptrHeader->label,label);

		ptrHeader->value = malloc(sizeof(char) * strlen(value) + 1);
		strcpy(ptrHeader->value,value);

		ptrHeader->next = (header *)malloc(sizeof(header)); 

		ptrHeader = ptrHeader->next;
		ptrRaw = ptrRaw->next;
	}

	header* ptr = &headers;

	
	return headers;
}

header* getHeaderByLabel(http_req* req,char* label)
{
	header* ptrHeader = &req->req_header.headers;
	while(ptrHeader->next != NULL)
	{
						
		if(strcmp(ptrHeader->label,label) == 0)
		{
			return ptrHeader;
		}
		ptrHeader = ptrHeader->next;
	}
	return NULL;
} 

http_req httpReqParser(char* rawReq)
{
	http_req req = {0};
	printf("%s\n",rawReq);

	req.req_header.headersNumber = getNumberOfHeaders(rawReq);

	char* body = strstr(rawReq,"\r\n\r\n") + 4;
	req.req_body = malloc(sizeof(char) * strlen(body) + 1);
	strcpy(req.req_body,body);
	char* rawReqLine = strtok(rawReq,"\r\n");
	
	header *header = &req.req_header.headers;

	node head = {0};
	node* ptr = &head;
	
	for(int i = 0; i < req.req_header.headersNumber; ++i)
	{
		char* rawHeader = strtok(NULL,"\r\n");
		ptr->argument = malloc(sizeof(char) * strlen(rawHeader) + 1);
		if(i < req.req_header.headersNumber-1) ptr->next = (node *)malloc(sizeof(node));

		strcpy(ptr->argument,rawHeader);
		ptr = ptr->next;
	}
	

	req.req_line = reqLineParser(rawReqLine);

	req.req_header.headers = headerParser(head,&req.req_header.headersNumber);

	return req;
}


void* handleReq(void* sock)
{
	int sock_fd = *((int *)sock);

	char buffer[1024];
	if(recv(sock_fd,buffer,sizeof(buffer),0) == -1)
	{
		printf("recv failed\n");
	}
	
	http_req req = httpReqParser(buffer);
	
	if(req.req_line.path.numOfArguments == 0)
	{

		char* sucRes = "HTTP/1.1 200 OK\r\n\r\n";
		send(sock_fd,sucRes,strlen(sucRes),0);
		return 0;

	}
	else
	{

		node* pathArgument = &req.req_line.path.arguments;

		req_type type;

		for(int i = 0; i < req.req_line.path.numOfArguments; ++i)
		{
			
			if(i==0)
			{
				if(strcmp(pathArgument->argument, "echo") == 0)
				{
					type = ECHO;
				}
				else if(strcmp(pathArgument->argument, "user-agent") == 0)
				{
					type = USER_AGENT;
					header* headerUA = getHeaderByLabel(&req,"User-Agent");
					if(headerUA != NULL)
					{
						char* res;
						asprintf(&res, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n\r\n%s", strlen(headerUA->value), headerUA->value);
						send(sock_fd,res,strlen(res),0);
						return 0;
					}
				}
				else if(strcmp(pathArgument->argument, "files") == 0)
				{
					type = FILER;
				}
			}
			else if(i==1)
			{

				if(type == ECHO)
				{
					header* headerEncoding = getHeaderByLabel(&req,"Accept-Encoding");
					if(headerEncoding == NULL || strcmp(headerEncoding->value,"gzip") != 0)
					{
						char* res;
						asprintf(&res, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n\r\n%s", strlen(pathArgument->argument), pathArgument->argument);
						send(sock_fd,res,strlen(res),0);
						return 0;
					}
					else
					{
						char* res;
						asprintf(&res, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n\r\n%s", strlen(pathArgument->argument), pathArgument->argument);
						send(sock_fd,res,strlen(res),0);
						return 0;
					}
					
				}
				else if(type == FILER)
				{
					char* filename = pathArgument->argument;
					char fullPath[strlen(directory) + strlen(filename) + 1];
					strcpy(fullPath,directory);
					strcat(fullPath,filename);
					FILE *fptr;
					switch(req.req_line.method)
					{
						case HTTP_GET:
						{
							
							fptr = fopen(fullPath, "r");
							if(fptr == NULL)
							{
								char* failRes = "HTTP/1.1 404 Not Found\r\n\r\n";
								send(sock_fd,failRes,strlen(failRes),0);
								return 0;
							}
							char fileContent[500];

							fgets(fileContent, 500, fptr);

							printf("%s\n", fileContent);

							fclose(fptr);
							char* res;
							asprintf(&res, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %zu\r\n\r\n%s", strlen(fileContent), fileContent);
							send(sock_fd,res,strlen(res),0);
							return 0;
						}
						case HTTP_POST:
						{
							fptr = fopen(fullPath, "w");

							fprintf(fptr, req.req_body);

							fclose(fptr);

							char* createdRes = "HTTP/1.1 201 Created\r\n\r\n";
							send(sock_fd,createdRes,strlen(createdRes),0);
							return 0;

						}
					}
					
				}
			}
			
			pathArgument =  pathArgument->next;
		}
	}
	
	char* failRes = "HTTP/1.1 404 Not Found\r\n\r\n";
	send(sock_fd,failRes,strlen(failRes),0);
	return 0;
}

int main(int argc, char *argv[]) {

	// Disable output buffering
	setbuf(stdout, NULL);
 	setbuf(stderr, NULL);
	if(argc >= 3)
	{
		if(strcmp(argv[1],"--directory") == 0)
		{
			directory = argv[2];
		}
	}
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	printf("Logs from your program will appear here!\n");

	// Uncomment this block to pass the first stage
	//
	int server_fd;
	
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1) {
		printf("Socket creation failed: %s...\n", strerror(errno));
	 	return 1;
	}
	
	// // Since the tester restarts your program quite often, setting SO_REUSEADDR
	// // ensures that we don't run into 'Address already in use' errors

	int reuse = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		printf("SO_REUSEADDR failed: %s \n", strerror(errno));
	 	return 1;
	}
	
	struct sockaddr_in serv_addr = { .sin_family = AF_INET ,
									 .sin_port = htons(4221),
	 								 .sin_addr = { htonl(INADDR_ANY) },
									};
	
	if (bind(server_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0) {
	 	printf("Bind failed: %s \n", strerror(errno));
	 	return 1;
	}
	
	int connection_backlog = 5;
	if (listen(server_fd, connection_backlog) != 0) {
	 	printf("Listen failed: %s \n", strerror(errno));
	 	return 1;
	}

	while(1)
	{
		int client_addr_len;
		struct sockaddr_in client_addr;

		printf("Waiting for a client to connect...\n");
		client_addr_len = sizeof(client_addr);

		int sock_fd = accept(server_fd, (struct sockaddr *) &client_addr, &client_addr_len);
		printf("Client connected\n");

		pthread_t new_process;

		int *pclient_socket = &sock_fd;
		pthread_create(&new_process, NULL, handleReq, pclient_socket);
		pthread_detach(new_process);
	}
	

	return 0;
}
