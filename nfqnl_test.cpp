#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#define BUF_LEN 2048


typedef struct trie_node{char c; int child_size; trie_node **child;}trie_node;

char *data[1000000];
char temp[100];

int fail[700];

int failure(char word[],int n) {
	int i=0,j=-1;
	for(i=0;i<n;i++) fail[i] = -1;
	i=1;
	fail[0]=-1;
	while(i<n) {
		if(word[fail[i]+1]==word[i+1]) {
			j++;
			fail[i] = j;
			i++;
		} else if(j>-1) j=fail[j];
		else {
			i++;
		}
	}
	return 0;	
}

int KMP(char sentence[], char word[], int len) {
	failure(word,strlen(word));
	int i=0,j=-1;
	int word_len = strlen(word);
	for(i=0;i<len;i++) {
		//printf("%d %d\n",i,j);
		j++;
		if(sentence[i] == word[j]) {
			if(j==word_len-1) return i-j;
		}
		else j = fail[j];
	}
	return -1;
}

int print_host(char **host_n, u_char *buf, int size) {
	int i,j=0,k=0;
	int found = 0;
	char get[][10] = {"GET","POST","HEAD","PUT","DELETE","OPTIONS","CONNECT"};
	char host[] = "Host: ";
	char host_buf[1000]={0};
	for(i=0;i<7;i++) {
		if(KMP((char *)buf,get[i],size)!=-1) break;
		if(i==7) return 0;
	}
	if((found = KMP((char *)buf,host,size))==-1) return 0;
	sscanf((const char *)buf+found,"%s %s",host,host_buf);
	*host_n = (char *)malloc(strlen(host_buf)+1);
	strcpy(*host_n,host_buf);
	printf("%s\n", *host_n);
	return strlen(*host_n);
/*
	for(i=0;i<size;i++) {
		if(!found) {
			if(buf[i] == get[j]) j++;
			else j=0;
			if(j==4) {
				found = 1;
				j=0;
			}
		}
		if(!found) continue;
		if(buf[i] == host[j]) j++;
		else j=0;
		if(j!=6) continue;
		int start = ++i;
		while(buf[i]!=0x0a && buf[i]!=0x0d && i<size) i++;
		
		if(*host_n!=NULL) free(host_n);
		*host_n = (char *)malloc(sizeof(char)*(i-start+1));
		memcpy(*host_n,buf+start,i-start);
		memcpy(*host_n+i-start,"\0",1);
		
		return i-start;
	}
	return 0;*/
}

int msgcmp(char *buffer, const char *cmp) {
	int i, len = strlen(cmp);
	if(strlen(buffer)<len) return 0;
	for(i=0;i<len;i++) {
		if(buffer[i]!=cmp[i]) return 0;
	}
	return 1;
}
int child_count = 0;
int main() {
//	char sentence[100];
//	scanf("%s",sentence);
//	scanf("%s",temp);
//	printf("%d\n",KMP(sentence,temp,strlen(sentence)));
	int i,j;
//	return 0;
	pid_t pid;
	struct sockaddr_in addr_in, cli_addr, serv_addr;
	struct hostent *host;
	int sockfd, newsockfd;

	memset((char *)&serv_addr, 0x00, sizeof(serv_addr));
	memset((char *)&cli_addr, 0x00, sizeof(serv_addr));
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(8080);

	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		printf("Server fd error\n");
		return 0;
	}
	if(bind(sockfd,(struct sockaddr *)&serv_addr, sizeof(serv_addr))<0) {
		printf("Binding error\n");
		return 0;
	}

	listen(sockfd,50);
	int clilen = sizeof(cli_addr);

	//accepting
accepting:
	
	newsockfd = accept(sockfd,(struct sockaddr *)&cli_addr, (unsigned int *)&clilen);
	printf("packet accepted\n");
	if(newsockfd < 0) {
		printf("Accepting connection error\n");
		return 0;
	}
	pid = fork();
	if(pid == 0) {
		pid = ++child_count;
		struct sockaddr_in host_addr;
		int flag = 0, newclifd=-1, n, port=0, i, clifd;
		char *buffer;
		buffer = (char *)malloc(sizeof(char)*1110);
		char new_buffer[1110];
		char temp1[50];
		char httpreq[50] = "HTTP";
		char *hostname = NULL;
		char *temp = NULL;
		int count = 0;
		while(1) {
			if(flag >= 2) break;
			memset(buffer, 0, 505);
			n = recv(newsockfd, buffer, 500, 0);
			if(n!=500) flag |= 2;
			count++;
			printf("received n : %d, count : %d, c_count : %d\n",n,count,pid);
			if(n<=0) break;
			buffer[n] = '\0';
			printf("/***************iqnqpquqtq*********\n");
			printf("%s\n",buffer);	
			printf("***********************************/\n");
			if(flag%2==0) {
				
				flag |= 1;
			//GET http://www.dummy.com HTTP/1.1\r\n 35
			//Host: www.dummy.com\r\n\r\n 23
				if(!print_host(&hostname,(u_char *)buffer, strlen(buffer))) {
					sscanf(buffer,"%s%s",temp1,new_buffer);
					for(i=0;new_buffer[i+7]!=' ' && new_buffer[i+7]!='\n' && new_buffer[i+7]!='/';i++);
					hostname = (char *)malloc(i+1);
					memcpy(hostname, new_buffer+7, i);
					hostname[i] = '\0';
				}
				printf("hostname : %s\n",hostname);
				host = gethostbyname(hostname);
				memset(&host_addr, 0, sizeof(host_addr));
				host_addr.sin_port = htons(80);
				host_addr.sin_family = AF_INET;
				memcpy((char *)&host_addr.sin_addr.s_addr, (char *)host->h_addr, host->h_length);
				printf("IP : %s\n",inet_ntoa(host_addr.sin_addr));
				clifd = socket(AF_INET, SOCK_STREAM, 0);
				newclifd = connect(clifd, (struct sockaddr*)&host_addr, sizeof(struct sockaddr));
				printf("\tconnect success\n");
				if(newclifd<0) {
					printf("error with connecting host\n");
					return 0;
				}
				sprintf(new_buffer, "%s%s","GET http://test.gilgil.net/ HTTP/1.1\r\nHost: test.gilgil.net\r\n\r\n",buffer);
				printf("new_buffer : \n%s\n",new_buffer);
				//n = send(clifd,buffer,strlen(buffer),0);
				n = send(clifd,new_buffer,strlen(new_buffer),0);
				printf("\tsend success\n");
			}
			else if(n>0) {
				if(newclifd<0) return 0;
				n = send(clifd, buffer, strlen(buffer),0);
			}
		}	
		if(newclifd<0) return 0;
		printf("\tsend complete\n");
		flag = 0;
		int totlen = 0x7fffffff;
		int dellen = 0;
		char *save = buffer;
		while(1) {
			buffer = save;
			if(totlen<=0) break;
			memset(buffer,0,1010);
			n = recv(clifd, buffer, 1000, 0);
			printf("\tn : %d\n",n);
			if(n<=0) break;
			//if(n!=500) flag|=2;
			buffer[n] = '\0';
			printf("////////////////////////////////////\n");
			printf("/*********oquqtqpquqtq**************\n");
			printf("%s\n",buffer);	
			printf("***********************************/\n");
			printf("////////////////////////////////////\n");
			printf("\treceived n : %d, flag : %d, totlen : %d\n",n,flag,totlen);

			if(flag == 0 && msgcmp(buffer, httpreq)) {
				//delete dummy packet
				int d_len = -1;
				d_len = KMP(buffer, "Content-Length: ",strlen(buffer));
				if(d_len == -1) d_len = KMP(buffer, "content-length: ",strlen(buffer));
				if(d_len == -1) {
					printf("couldn't found content-length\n");
					n = send(newsockfd,buffer,strlen(buffer),0);
					break;
				}
				sscanf(buffer+d_len+16,"%d",&dellen);
				
				d_len = KMP(buffer, "\r\n\r\n",strlen(buffer));
				if(d_len == -1) break;
				dellen += d_len + 4;
				if(dellen >=n) 	dellen-=n;
				else {
					buffer += dellen;
					flag = 1;
					n-=dellen;
				}
				if(dellen == 0) {
					flag = 1;
					n=0;
				}
			}
			else if(flag == 0) {
				if(dellen >=n) 	dellen-=n;
				else {
					buffer += dellen;
					flag = 1;
				}
				if(dellen == 0) flag = 1;
			}
			printf("moved buffer : \n%s\n",buffer);
			if(flag == 1 && msgcmp(buffer, httpreq)) {
				int c_len = -1;
				c_len = KMP(buffer, "Content-Length: ",strlen(buffer));
				if(c_len == -1) c_len = KMP(buffer, "content-length: ",strlen(buffer));
				if(c_len == -1) {
					printf("couldn't found content-length\n");
					n = send(newsockfd,buffer,strlen(buffer),0);	
					break;
				}
				sscanf(buffer+c_len+16,"%d",&totlen);
				c_len = KMP(buffer, "\r\n\r\n",strlen(buffer));
				if(c_len == -1) break;
				totlen += c_len + 4;
				printf("\ttotal len : %d\n",totlen);
				n = send(newsockfd,buffer,n,0);	
				totlen-=n;
			}
			else if(flag == 1){
				n = send(newsockfd,buffer,n,0);
				totlen-=n;
			}
		}
		close(newsockfd);
		close(clifd);
		close(newclifd);
		printf("\tchild %d close\n",pid);
		return 0;
	}
	else {
		close(newsockfd);
		child_count++;
		goto accepting;
	}
	return 0;
}

