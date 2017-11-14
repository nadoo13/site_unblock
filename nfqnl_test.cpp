
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>

#include <libnetfilter_queue/libnetfilter_queue.h>


typedef struct trie_node{char c; int child_size; trie_node **child;}trie_node;

char *data[1000000];
char temp[100];

int print_host(char **host_n, u_char *buf, int size) {
	int i,j=0,k=0;
	int found = 0;
	char get[] = "GET ";
	char host[] = "Host: ";
	
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
	return 0;
}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);
/*
	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		printf("payload_len=%d ", ret);
		dump(data,ret>0xff?0xff:ret);
		char *host_name = NULL;	
		int host_len = print_host(&host_name,data,ret);	
	//	printf("addr of host_n : %x\n",host_name);
		if(host_len) {
			printf("%s\n",host_name);
		}
		if(host_name!=NULL) free(host_name);
	}
*/
	fputc('\n', stdout);

	return id;
}
	
char *block_host;
trie_node *root;

trie_node *connect_node(int start, int end, int depth) {
	int st=start,en=end,md;
	int node_count = 0;
	int dir_start = st;
	trie_node *save[300];
	int save_count=0;
	trie_node *result = (trie_node *)malloc(sizeof(trie_node));
	while(dir_start<=end &&(depth<0||data[start][depth]!='\0')) {
		st = dir_start;
		en = end;
		md = (st+en)/2;
		while(st<en-1) {
			if(data[dir_start][depth+1]<data[md][depth+1]) en=md;
			else st=md;
			md = (st+en)/2;
		}
		if(data[st][depth+1] == data[en][depth+1]) md = en;
		else md = st;
		save[save_count++] = connect_node(dir_start,md,depth+1);
		dir_start = md+1;
	}
	if(save_count) result->child = (trie_node **)malloc(sizeof(trie_node *)*save_count);
	else result->child = NULL;
	for(int i=0;i<save_count;i++) {
		result->child[i] = save[i];
	}
	result->child_size = save_count;
	if(depth>=0) result->c=data[start][depth];
	else result->c = '\0';
	return result;
}

int trip(char *str,trie_node *root,int depth) {
	int i;
	int size = root->child_size;
	for(i=0;i<size;i++) {
		if(root->child[i]->c == str[depth]) {
			if(root->child[i]->c == '\0') return 1;
			else return trip(str,root->child[i],depth+1);
		}
	}
	return 0;
}

trie_node *make_trie() {
	FILE *fpr = fopen("sorted_data.data","r");
	int i;
	for(i=0;i<1000000;i++) {
		fscanf(fpr,"%s",temp);
		int len = strlen(temp);
		data[i] = (char *)malloc(len+1);
		strcpy(data[i],temp);
	}
	trie_node *root = NULL;
	
	root = connect_node(0,999999,-1);
	for(i=0;i<1000000;i++) free(data[i]);
	fclose(fpr);
	return root;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	int ret = nfq_get_payload(nfa, (unsigned char **)&data);
	if (ret >= 0) {
		printf("payload_len=%d ", ret);
//		dump((u_char *)data,ret>0xff?0xff:ret);
		char *host_name = NULL;	
		int host_len = print_host(&host_name,(u_char *)data,ret);	
	//	printf("addr of host_n : %x\n",host_name);
		if(host_len) {
			printf("h_n : %s\n",host_name);
			if(trip(host_name,root,0)) {
				sleep(3);
				printf("blocked host\n");
				return nfq_set_verdict(qh,id,NF_DROP,0,NULL);
			}
		}
		if(host_name!=NULL) free(host_name);
	}


	printf("entering callback\n");
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}
	
int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	root = make_trie();
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
