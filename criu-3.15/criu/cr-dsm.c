#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <ptrace.h>
#include <asm/types.h>

#include <sys/ioctl.h>
#include "images/core.pb-c.h"
#include "pie/parasite-blob.h"
#include "parsemap.h"
#include "pstree.h"
#include "types.h"
#include "asm/infect-types.h"
#include "parasite.h"
#include "../compel/include/infect-priv.h"

#ifndef COMPEL_ARCH_SYSCALL_TYPES_H__
#define COMPEL_ARCH_SYSCALL_TYPES_H__


#define SIGMAX                  64

#define SA_RESTORER   0x04000000
#define PATH_MAX 10000
#define PROCMAPS_LINE_MAX_LENGTH  (PATH_MAX + 100)

typedef void rt_signalfn_t(int, siginfo_t *, void *);
typedef rt_signalfn_t *rt_sighandler_t;

typedef void rt_restorefn_t(void);
typedef rt_restorefn_t *rt_sigrestore_t;

#define _KNSIG          64
#define _NSIG_BPW       64

#define _KNSIG_WORDS    (_KNSIG / _NSIG_BPW)

typedef struct {
        unsigned long sig[_KNSIG_WORDS];
} k_rtsigset_t;

typedef struct {
        rt_sighandler_t rt_sa_handler;
        unsigned long   rt_sa_flags;
        rt_sigrestore_t rt_sa_restorer;
        k_rtsigset_t    rt_sa_mask;
} rt_sigaction_t;

#endif /* COMPEL_ARCH_SYSCALL_TYPES_H__ */


extern struct vm_area_list *g_vma_area_list;

struct page_list{
	long saddr;
	short state;
	short owner;
	pthread_mutex_t mutex;
};

pthread_mutex_t bus_lock = PTHREAD_MUTEX_INITIALIZER;

#define MAX_PAGE_COUNT 100000

enum __compel_log_levels
{
	COMPEL_LOG_MSG,		/* Print message regardless of log level */
	COMPEL_LOG_ERROR,	/* Errors only, when we're in trouble */
	COMPEL_LOG_WARN,	/* Warnings */
	COMPEL_LOG_INFO,	/* Informative, everything is fine */
	COMPEL_LOG_DEBUG,	/* Debug only */

	COMPEL_DEFAULT_LOGLEVEL	= COMPEL_LOG_WARN
};

int uffd;
struct msg_info{
	int msg_type;
	long page_addr;
	int page_size;
	long msg_id;
};

enum msg_type{
	MSG_GET_PAGE_LIST,
	MSG_GET_PAGE_DATA,
	MSG_INVALIDATE_PAGE,
	MSG_INVALIDATE_ACK,
	MSG_GET_PAGE_DATA_INVALID,
	MSG_SEND_INVALIDATE,
	MSG_WAKE_THREAD,
};

enum page_state{
	PAGE_MODIFIED,
	PAGE_SHARED,
	PAGE_INVALID,
};



struct page_list *page_list_data;
int total_pages = 0;


struct thread_param{
	int sock;
	int uffd;
	int pipe_fd;
	int pipe_fd_ack;
};

int msg_counter = 0;

int page_size = 4096;

void send_page_invalidate_msg(long addr,int fd){
	struct msg_info dsm_msg;

	dsm_msg.msg_type = MSG_SEND_INVALIDATE;
	dsm_msg.page_addr = addr;
	dsm_msg.msg_id = msg_counter++;
	printf("[FAULT] id=%d send_page_invalidate_msg :%lx \n",dsm_msg.msg_id,addr);

	write(fd,&dsm_msg,sizeof(struct msg_info));
}

static void print_vmsg(unsigned int lvl, const char *fmt, va_list parms)
{
	printf("\tLC%u: ", lvl);
	vprintf(fmt, parms);
}


void setup_connections(int *remote_uffd_server_fd,int *remote_msg_server_fd){

	int new_socket, valread;
	struct sockaddr_in address;
	int opt = 1;
	int addrlen = sizeof(address);
	char buffer[1024] = {0};

	// create server socket
	if ((*remote_uffd_server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	// set server options
	if (setsockopt(*remote_uffd_server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons( 8080 );

	// bind socket to address and port
	if (bind(*remote_uffd_server_fd, (struct sockaddr *)&address, sizeof(address))<0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	/**/

	// create server socket
	if ((*remote_msg_server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	// set server options
	if (setsockopt(*remote_msg_server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons( 8081 );

	// bind socket to address and port
	if (bind(*remote_msg_server_fd, (struct sockaddr *)&address, sizeof(address))<0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}	

}

#if 0
int start_remote_msg_socket(){

	int server_fd, new_socket, valread;
	struct sockaddr_in address;
	int opt = 1;
	int addrlen = sizeof(address);
	char buffer[1024] = {0};

	// create server socket
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	// set server options
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons( 8080 );

	// bind socket to address and port
	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	printf("waiting for connection\n");
	if (listen(server_fd, 3) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}
	if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}
	printf("waiting for connection: CONNECTED\n");

	return new_socket;
}
#endif 

int accept_remote_uffd_socket(server_fd){
	
	struct sockaddr_in address;
	int addrlen = sizeof(address);
	int new_socket;

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(8080);

	printf("waiting for connection uffd_socket\n");
	if (listen(server_fd, 3) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}
	printf("waiting for connection: CONNECTED\n");

	return new_socket;
}

int accept_remote_dsm_socket(server_fd){
	
	struct sockaddr_in address;
	int addrlen = sizeof(address);
	int new_socket;

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(8081);

	printf("waiting for connection dsm_socket\n");
	if (listen(server_fd, 3) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}
	printf("waiting for connection: CONNECTED\n");

	return new_socket;
}


static int get_page_data_from_remote(int pipe_fd,int pipe_fd_ack, long addr,unsigned char *page_content, bool is_write){

        struct msg_info dsm_msg;
	printf("[FAULT] page data get_page_data_from_remote\n");
	int ack ;

	dsm_msg.msg_type = is_write ? MSG_GET_PAGE_DATA_INVALID :MSG_GET_PAGE_DATA;
        dsm_msg.page_addr = addr;

	/*send message to page server*/
        write(pipe_fd, &dsm_msg, sizeof(struct msg_info));
        int data_read = 0;
	printf("[FAULT] page data get_page_data_from_remote..\n");
	int  page_owner_fd = 0;
	read(pipe_fd_ack,&page_owner_fd,sizeof(int));
	printf("ACK Recieved. page_owner_fd %d\n",(int)page_owner_fd);
        while(data_read < page_size){
                int ret = read((int)page_owner_fd,page_content+data_read,page_size);
                printf("[FAULT] page data ret=%d\n",ret);
                data_read += ret;
        }
        write(pipe_fd, &ack, 1);
        return 0;
}


volatile int uffd_in_progress  = 0;
volatile int invalidate_in_progress = 0;
//uffd_handler
static void *handler(void *arg)
{

	struct thread_param *p  = arg;
	printf("handler uffd:%d\n",p->uffd);

	for (;;) {
		struct uffd_msg msg;

		struct pollfd pollfd[1];
		pollfd[0].fd  = p->uffd;
		pollfd[0].events = POLLIN;

		// wait for a userfaultfd event to occur
		int pollres = poll(pollfd, 1, 2000);

		printf("polling\n");
		switch (pollres) {
			case -1:
				perror("poll/userfaultfd");
				continue;
			case 0:
				continue;
			case 1:
				break;
			default:
				fprintf(stderr, "unexpected poll result\n");
				exit(1);
		}

		if (pollfd[0].revents & POLLERR) {
			fprintf(stderr, "pollerr\n");
			exit(1);
		}
		if (!pollfd[0].revents & POLLIN) {
			continue;
		}

		int readres = read(p->uffd, &msg, sizeof(msg));
		if (readres == -1) {
			if (errno == EAGAIN)
				continue;
			perror("read/userfaultfd");
			exit(1);
		}

		if (readres != sizeof(msg)) {
			fprintf(stderr, "invalid msg size--- \n");
			exit(1);
		}

		printf("[FAULT] fault Start ###########\n");

		long long addr = msg.arg.pagefault.address;

		//pthread_mutex_lock(&page_list_data[addr_to_index(addr)].mutex);

		uffd_in_progress = 1;

		// handle the page fault by copying a page worth of bytes
		if (msg.event & UFFD_EVENT_PAGEFAULT) {
			struct msg_info dsm_msg;

			if(msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP)
			{
				invalidate_in_progress = 1;
				printf("[FAULT] fault for write-protect 0x%llx\n",addr);
				send_page_invalidate_msg(addr,p->pipe_fd);

				unsigned char ack = 0x10;
				read(p->pipe_fd_ack,&ack,1);
				printf("ACK Recieved : %x\n",ack);

				struct uffdio_writeprotect prms;
				prms.range.start = addr;
				prms.range.len = 4096;
				prms.mode =  0;

				if (ioctl(p->uffd, UFFDIO_WRITEPROTECT, &prms))
					perror("write_protect #1\n");
				printf("[FAULT] fault for write-protect done\n");
			}
			else{
				struct uffdio_copy copy;
				bool is_write =  msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE;
				printf("[FAULT] ^^^^^^^^^^^^^^^^^^^^ fault for missing page %llx, write : %d\n",(long long)addr,is_write);
				unsigned char page_content[4096] = {0};
				get_page_data_from_remote(p->pipe_fd, p->pipe_fd_ack,addr,page_content,is_write);
				copy.src = (long long)page_content;
				copy.dst = (long long)addr;
				copy.len = page_size;
				copy.mode =  is_write ? 0 :UFFDIO_COPY_MODE_WP;
				if (ioctl(p->uffd, UFFDIO_COPY, &copy) == -1) {
					perror("ioctl/copy");
					exit(1);
				}
                                printf("@@~~~~~~ page write ~~~~~~~~\n");
                                        for(int i=0x26;i<0x30;i++)
                                                printf("%03d ",page_content[i]);
                                        printf("\n");
			}
		}
		//pthread_mutex_unlock(&page_list_data[addr_to_index(addr)].mutex);
		uffd_in_progress = 0;
		printf("[FAULT] fault DONE ############\n");

	}

}

void handle_page_list_request(int sk){
	/*1. Send no of pages */
	send(sk,&total_pages,sizeof(total_pages),0);

	/*1. Send page address */
	for(int i=0;i<total_pages;i++){
		send(sk,&page_list_data[i].saddr,sizeof(long),0);
	}
}
struct parasite_ctl *parasite_infect_seized(pid_t pid, struct pstree_item *item,
		struct vm_area_list *vma_area_list);

int stealUFFD(int pid,struct pstree_item *item){

	int uffd,val;
	struct parasite_ctl *g_parasite_ctl;

	g_parasite_ctl =	parasite_infect_seized(pid, item, g_vma_area_list);
	if (!g_parasite_ctl) {
		printf("Can't infect (pid: %d) with parasite\n", pid);
	}

	printf("g_parasite_ctl %lx\n",g_parasite_ctl);
	if(compel_rpc_call(PARASITE_CMD_STEAL_UFFD, g_parasite_ctl) ||
	   compel_util_recv_fd(g_parasite_ctl, &uffd) ||                                                                                                                       compel_rpc_sync(PARASITE_CMD_STEAL_UFFD, g_parasite_ctl))
	{
	   printf("failed to get uffd\n");
	   return -1;
	}

	val = compel_stop_daemon(g_parasite_ctl);
	if (compel_cure(g_parasite_ctl))
		pr_err("Can't cure (pid: %d) from parasite\n",pid);

	val = ptrace(PTRACE_CONT, pid, NULL, NULL);
	pr_info("PTRACE_CONT %d\n",val);


	printf("UFFD: %d\n",uffd);
	return uffd;
}

/* Shared to Invalidate*/

void handle_invalidate_page(struct msg_info *dsm_msg,int pid,struct pstree_item *item){
	int val, ret,i;
	long *args;
	struct parasite_ctl *g_parasite_ctl;

	printf("[msg_handler] %s %lx\n",__func__,dsm_msg->page_addr);
	val = ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
	pr_info("[msg_handler] PTRACE_INTERRUPT %d\n",val);

	g_parasite_ctl =  parasite_infect_seized(pid, item, g_vma_area_list);
	args = compel_parasite_args(g_parasite_ctl, long);
	*args = dsm_msg->page_addr;
	page_list_data[addr_to_index(dsm_msg->page_addr)].state = PAGE_INVALID;


	ret = compel_rpc_call(PARASITE_CMD_RUN_MADVISE, g_parasite_ctl);
	if (ret < 0)
		return -1;

	ret = compel_rpc_sync(PARASITE_CMD_RUN_MADVISE, g_parasite_ctl);
	if (ret < 0)
		return -1;

	val = compel_stop_daemon(g_parasite_ctl);
	if (compel_cure(g_parasite_ctl))
		pr_err("Can't cure (pid: %d) from parasite\n",pid);

	printf("continue the mainthread\n");

}

void special_page_data_request(int pid,int sk,long page_addr,struct pstree_item *item){
	int val, ret,i;
	int p[2];
	long *args;
	struct parasite_ctl *g_parasite_ctl;
	unsigned char page_content[4096];

	printf("[msg_handler] %s\n",__func__);
	val = ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
	pr_info("PTRACE_INTERRUPT %d\n",val);

	g_parasite_ctl =  parasite_infect_seized(pid, item, g_vma_area_list);
	args = compel_parasite_args(g_parasite_ctl, long);
	*args = page_addr;
	printf("%x\n",*args);


	ret = compel_rpc_call(PARASITE_CMD_DUMP_SINGLE, g_parasite_ctl);
	if (ret < 0)
		return -1;
	pipe(p);
	ret = compel_util_send_fd(g_parasite_ctl, p[1]);
	if (ret)
		return -1;


	ret = compel_rpc_sync(PARASITE_CMD_DUMP_SINGLE, g_parasite_ctl);
	if (ret < 0)
		return -1;
	page_list_data[addr_to_index(page_addr)].state = PAGE_INVALID;

	//Read from parsite pip
	read(p[0], page_content,4096);
	for(i=0x26;i<0x30;i++){
		printf("%03d ",page_content[i]);
	}
	printf("\n");
	send(sk,page_content,4096,0);
	printf("page_transfer_complete\n");

	printf("Drop the page: \n");
	ret = compel_rpc_call(PARASITE_CMD_RUN_MADVISE, g_parasite_ctl);
	if (ret < 0)
		return -1;

	ret = compel_rpc_sync(PARASITE_CMD_RUN_MADVISE, g_parasite_ctl);
	if (ret < 0)
		return -1;


	val = compel_stop_daemon(g_parasite_ctl);
	if (compel_cure(g_parasite_ctl))
		pr_err("Can't cure (pid: %d) from parasite\n",pid);

	printf("continue the mainthread\n");
	close(p[0]);
	close(p[1]);
}
/* Modified to Shared */
void handle_page_data_request(int pid,int sk,struct msg_info *dsm_msg,struct pstree_item *item){
	int val, ret,i;
	int p[2];
	long *args;
	struct parasite_ctl *g_parasite_ctl;
	unsigned char page_content[4096];

	printf("[msg_handler] %s\n",__func__);
	val = ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
	pr_info("PTRACE_INTERRUPT %d\n",val);

	g_parasite_ctl =  parasite_infect_seized(pid, item, g_vma_area_list);
	args = compel_parasite_args(g_parasite_ctl, long);
	*args = dsm_msg->page_addr;
	printf("%x\n",*args);


	ret = compel_rpc_call(PARASITE_CMD_DUMP_SINGLE, g_parasite_ctl);
	if (ret < 0)
		return -1;
	pipe(p);
	ret = compel_util_send_fd(g_parasite_ctl, p[1]);
	if (ret)
		return -1;


	ret = compel_rpc_sync(PARASITE_CMD_DUMP_SINGLE, g_parasite_ctl);
	if (ret < 0)
		return -1;

	//Read from parsite pip
	read(p[0], page_content,4096);
	for(i=0x26;i<0x30;i++){
		printf("%03d ",page_content[i]);
	}
	send(sk,page_content,4096,0);
	printf("page_transfer_complete\n");

	if(dsm_msg->msg_type == MSG_GET_PAGE_DATA_INVALID){
		printf("Drop the page: \n");
		ret = compel_rpc_call(PARASITE_CMD_RUN_MADVISE, g_parasite_ctl);
		if (ret < 0)
			return -1;

		ret = compel_rpc_sync(PARASITE_CMD_RUN_MADVISE, g_parasite_ctl);
		if (ret < 0)
			return -1;

		page_list_data[addr_to_index(dsm_msg->page_addr)].state = PAGE_INVALID;
	}else // TO SHARED
	{
		change_to_wp( dsm_msg->page_addr,uffd);
		page_list_data[addr_to_index(dsm_msg->page_addr)].state = PAGE_SHARED;
	}


	val = compel_stop_daemon(g_parasite_ctl);
	if (compel_cure(g_parasite_ctl))
		pr_err("Can't cure (pid: %d) from parasite\n",pid);

	printf("continue the mainthread\n");
	close(p[0]);
	close(p[1]);
}

void register_and_write_protect(int uffd,int pid){

	struct uffdio_writeprotect uf_wp;
	struct uffdio_api uffdio_api;
	// enable for api version and check features
	uffdio_api.api = UFFD_API;
	uffdio_api.features = 0;
	if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1) {
		perror("ioctl/uffdio_api");
		exit(1);
	}

	if (uffdio_api.api != UFFD_API) {
		fprintf(stderr, "unsupported userfaultfd api\n");
		exit(1);
	}

	struct uffdio_register uffdio_register;

	for(int i=0;i<total_pages;i++){
		uffdio_register.range.start = page_list_data[i].saddr ;
		uffdio_register.range.len = 4096;
		uffdio_register.mode =  UFFDIO_REGISTER_MODE_WP | UFFDIO_REGISTER_MODE_MISSING;

		if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
			perror("ioctl/uffdio_register\n"  );
			printf("ioctl/uffdio_register :%llx\n",  page_list_data[i].saddr  );
			continue;
		}

		uf_wp.range.start = page_list_data[i].saddr;
		uf_wp.range.len = 4096;
		uf_wp.mode =  UFFDIO_WRITEPROTECT_MODE_WP;

		if (ioctl(uffd, UFFDIO_WRITEPROTECT, &uf_wp))
		{
			perror("write_protect\n");
			printf("page : %llx\n",page_list_data[i].saddr);
		}
		page_list_data[i].state = PAGE_SHARED;
	}
}

void change_to_wp(long addr,int uffd){

	struct uffdio_writeprotect uf_wp;

	uf_wp.range.start = addr;
	uf_wp.range.len = 4096 ;
	uf_wp.mode =  UFFDIO_WRITEPROTECT_MODE_WP;

	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &uf_wp))
	{
		perror("write_protect\n");
		printf("page : %llx\n",addr);
	}
	printf("change_to_wp %lx \n",addr);

}


void create_page_list(struct pstree_item *item)
{
	int index=0;
	procmaps_iterator* maps;
	procmaps_struct* maps_tmp=NULL;
	maps = pmparser_parse(item->threads[0].real);

	page_list_data = (struct page_list*) malloc(sizeof(struct page_list)* MAX_PAGE_COUNT);
	while( (maps_tmp = pmparser_next(maps)) != NULL){

                if(maps_tmp->track_uffd == 0){
                        continue;
                }

                printf("maps_tmp->addr_start %lx maps_tmp->addr_length %d (%d pages)\n",maps_tmp->addr_start,
				maps_tmp->length, maps_tmp->length/4096);
                printf("................................\n");
		for(int i=0; i < (maps_tmp->length/4096); i++)
		{
			page_list_data[i+index].saddr = maps_tmp->addr_start + i*4096;
			page_list_data[i+index].owner = 0;
			page_list_data[i+index].state = PAGE_SHARED;
		}
		index += maps_tmp->length/4096;
		total_pages = index;

       }
       printf("total_pages = %d\n",total_pages);

       // Create MUTEX
//       for (int i=0;i<total_pages;i++)
//		pthread_mutex_init(&page_list_data[i].mutex, NULL);
}

int addr_to_index(long long addr){

	for(int i=0;i<total_pages;i++){
		if(addr == page_list_data[i].saddr)
			return i;
	}
	printf("FATAL: Page not found %llx\n",addr);

	for(int i=0;i<total_pages;i++)
	{
		printf("FATAL: Page not found =%d %llx %llx\n",i,addr,page_list_data[i].saddr);
		
	}
	exit(0);
}


int broadcast_invalidate_page(long page_addr , int remote_id,int *r_msock ,int  n_remote_threads){
	struct msg_info dsm_msg;
	printf("broadcast_invalidate_page\n");

	dsm_msg.msg_type = MSG_INVALIDATE_PAGE;
        dsm_msg.page_addr = page_addr;
	
	for(int i=1;i<=n_remote_threads;i++)
	{
		if(remote_id != i)
			write(r_msock[i], &dsm_msg,sizeof(struct msg_info));
	}
}


int get_page_owner(long addr){
	return  page_list_data[addr_to_index(addr)].owner;
}

void start_dsm_server(struct pstree_item *item)
{
	struct vma_area *vma_area;
	int  nr_pages=0,vma_count=0;
	int i;
	int wait_status,val,main_pid;
	pthread_t uffd_thread;
	struct thread_param param;
	int p[2],p_ack[2];
	int *r_usock,*r_msock;
	int n_remote_threads;

	main_pid = item->threads[0].real;

	uffd = stealUFFD(main_pid,item);

	create_page_list(item);

	pr_info("nr_threads : %d\n",item->nr_threads);
	for(i=0;i<item->nr_threads;i++)
		pr_info("pid-%d : %d\n",i,item->threads[i].real);

	pipe(p);
	pipe(p_ack);

	n_remote_threads = item->nr_threads-1;
	r_usock = (int *)malloc(sizeof(int)* (n_remote_threads+1)); 
	r_msock = (int *)malloc(sizeof(int)* (n_remote_threads+1)); 

	int remote_uffd_server_fd,remote_msg_server_fd;
	setup_connections(&remote_uffd_server_fd, &remote_msg_server_fd);


	for(int i=1;i<=n_remote_threads;i++)
	{
		r_usock[i] = accept_remote_uffd_socket(remote_uffd_server_fd);
	 	r_msock[i] = accept_remote_dsm_socket(remote_msg_server_fd);
		handle_page_list_request(r_usock[i]);
	}

	//page_data_socket = r_msock[1]; //TODO Fix this
	param.uffd = uffd;
	param.pipe_fd = p[1]; // writer
	param.pipe_fd_ack = p_ack[0];
	int msg_served = -1;

	register_and_write_protect(uffd,item->threads[0].real);
	printf("# uffd : %d\n",param.uffd);
	pthread_create(&uffd_thread, NULL, handler, (void *)&param);

	int no_of_fds = n_remote_threads + 1;
	printf("# n_remote_threads : %d\n",n_remote_threads);
	printf("# no_of_fds : %d\n",no_of_fds);

	struct pollfd  *fds= (struct pollfd *)malloc(sizeof(struct pollfd) * no_of_fds);
	for(;;){
		val = ptrace(PTRACE_CONT,item->threads[0].real, NULL, NULL);
		pr_info("PTRACE_CONT %d\n",val);

		fds[0].fd = p[0];
		fds[0].events = POLLIN;
	
		for(int i=1;i<no_of_fds;i++){
				// remote uffd layer socket
				fds[i].fd = r_usock[i];    //1->1, 3->2
				fds[i].events = POLLIN;
				printf("fd[%d]=%d\n",fds[i],r_usock[i]);
		}

		int pollres = poll(fds, no_of_fds, 20000);
		int read_fd = -1;
		if(fds[0].revents & POLLIN){
			struct msg_info dsm_msg;
			printf("MSG FROM own uffd thread\n");
			read_fd = p[0];
			int readres = read(read_fd, &dsm_msg, sizeof(dsm_msg));
			if (readres == -1) {
				if (errno == EAGAIN)
					continue;
				perror("read/userfaultfd");
				exit(1);
			}

			if (readres != sizeof(dsm_msg)) {
				fprintf(stderr, "invalid msg size--- \n");
				exit(1);
			}
			unsigned char ack = 0x10;
			int page_owner=0,page_owner_fd;
			switch(dsm_msg.msg_type){
#if 1
				case MSG_SEND_INVALIDATE:
					printf("uffd MSG_SEND_INVALIDATE\n");
					if(  page_list_data[addr_to_index(dsm_msg.page_addr)].state == PAGE_MODIFIED &&
						page_list_data[addr_to_index(dsm_msg.page_addr)].owner != 0)
					{
						printf("Lost ownership\n");
						ack = 0x11 ; // drop wp
						write(p_ack[1],&ack,1);
						break;
					}
					dsm_msg.msg_type = MSG_INVALIDATE_PAGE;
					// broadcast invalidation
					for(int i=1;i<n_remote_threads;i++){
						send(r_msock[i],&dsm_msg,sizeof(dsm_msg),0);
						read(r_msock[i],&ack,1);
					}
					write(p_ack[1],&ack,1); //ACK to UFFD thread
					page_list_data[addr_to_index(dsm_msg.page_addr)].state = PAGE_MODIFIED;
					page_list_data[addr_to_index(dsm_msg.page_addr)].owner = 0;
					invalidate_in_progress  = 0;
					break;


				case MSG_GET_PAGE_DATA_INVALID:
				case MSG_GET_PAGE_DATA:
					printf("uffd MSG_GET_PAGE_DATA\n");
					page_owner = get_page_owner(dsm_msg.page_addr); 
					send(r_msock[page_owner],&dsm_msg,sizeof(dsm_msg),0);
					
					page_owner_fd = r_msock[page_owner];	
					write(p_ack[1],&page_owner_fd,sizeof(int));
					page_list_data[addr_to_index(dsm_msg.page_addr)].state = dsm_msg.msg_type == MSG_GET_PAGE_DATA ? PAGE_SHARED
										: PAGE_MODIFIED ;
					page_list_data[addr_to_index(dsm_msg.page_addr)].owner =  0;  /* orgin has a copy*/
					printf("final ack\n");
					read(p[0],&ack,1);
					printf("final ack done\n");
					break;
#endif
			}
			continue;
		}
//		else if(fds[1].revents & POLLIN){
			read_fd=-1;
			int remote_id=-1;
		
#if 1
			for(int i=1; i<=no_of_fds; i++)
			{		
				if(fds[i].revents & POLLIN){ //   1,3,4
					read_fd = r_usock[i];
				        remote_id = i;	
					printf("fd with new msg\n");
					break;
				}
				if(i==no_of_fds){
					printf("no fd with new msg\n");
					continue;  //no new msg
				}
			}

			if(read_fd < 0)
			{
				printf("Invalid fd\n");
				continue;
			}
#endif
			struct msg_info dsm_msg;
			unsigned char ack = 0x10;
			printf("MSG FROM remote thread=%d \n",remote_id);

			int readres = read(read_fd, &dsm_msg, sizeof(dsm_msg));
			if (readres == -1) {
				if (errno == EAGAIN)
					continue;
				perror("read/userfaultfd");
				exit(1);
			}

			if (readres != sizeof(dsm_msg)) {
				fprintf(stderr, "invalid msg size--- \n");
				exit(1);
			}
			printf("MSG FROM remote thread msg=%d\n",dsm_msg.msg_type);

			switch(dsm_msg.msg_type){
				case MSG_INVALIDATE_PAGE:
					printf("REMOTE MSG_INVALIDATE_PAGE\n");
					if(page_list_data[addr_to_index(dsm_msg.page_addr)].state == PAGE_MODIFIED && page_list_data[addr_to_index(dsm_msg.page_addr)].owner == 0)

					{
						printf("((((((( Remote is not the owner\n");
						ack = 0x89;
						send(r_usock,&ack,1,0);
						special_page_data_request(item->threads[0].real,r_usock,dsm_msg.page_addr,item);
						page_list_data[addr_to_index(dsm_msg.page_addr)].state = PAGE_MODIFIED;
						page_list_data[addr_to_index(dsm_msg.page_addr)].owner = 1; // remote
						break;
					}
					handle_invalidate_page(&dsm_msg, item->threads[0].real,item);
					
					broadcast_invalidate_page(dsm_msg.page_addr , remote_id,r_msock , n_remote_threads);
					page_list_data[addr_to_index(dsm_msg.page_addr)].state = PAGE_MODIFIED;
					page_list_data[addr_to_index(dsm_msg.page_addr)].owner = remote_id; // remote
					send(r_usock[remote_id],&ack,1,0);
					break;
				case MSG_GET_PAGE_DATA_INVALID:
				case MSG_GET_PAGE_DATA:
					printf("REMOTE MSG_GET_PAGE_DATA\n");
					if(page_list_data[addr_to_index(dsm_msg.page_addr)].owner != 0)
					{
						printf("Lost ownership\n");
						break;
					}
					handle_page_data_request(item->threads[0].real,r_usock[remote_id],&dsm_msg,item);
					page_list_data[addr_to_index(dsm_msg.page_addr)].state = PAGE_SHARED;
					page_list_data[addr_to_index(dsm_msg.page_addr)].owner = 1; // remote
					break;
			}//switch
	//	}// elseif

	}// for

}

procmaps_iterator* pmparser_parse(int pid){
	procmaps_iterator* maps_it = malloc(sizeof(procmaps_iterator));
	char maps_path[500];
	if(pid>=0 ){
		sprintf(maps_path,"/proc/%d/maps",pid);
	}else{
		sprintf(maps_path,"/proc/self/maps");
	}
	printf("path : %s\n",maps_path);
	FILE* file=fopen(maps_path,"r");
	if(!file){
		fprintf(stderr,"pmparser : cannot open the memory maps, %s\n",strerror(errno));
		return NULL;
	}
	int ind=0;char buf[PROCMAPS_LINE_MAX_LENGTH];
	int c;
	procmaps_struct* list_maps=NULL;
	procmaps_struct* tmp;
	procmaps_struct* current_node=list_maps;
	char addr1[20],addr2[20], perm[8], offset[20], dev[10],inode[30],pathname[PATH_MAX];
	while( !feof(file) ){
		if (fgets(buf,PROCMAPS_LINE_MAX_LENGTH,file) == NULL){
			fprintf(stderr,"pmparser : fgets failed, %s\n",strerror(errno));
	//		return NULL;
		}
		//allocate a node
		tmp=(procmaps_struct*)malloc(sizeof(procmaps_struct));
		//fill the node
		_pmparser_split_line(buf,addr1,addr2,perm,offset, dev,inode,pathname);
		unsigned long l_addr_start;
		sscanf(addr1,"%lx",(long unsigned *)&tmp->addr_start );
		sscanf(addr2,"%lx",(long unsigned *)&tmp->addr_end );
		//size
		tmp->length=(unsigned long)(tmp->addr_end-tmp->addr_start);
		//perm
		strcpy(tmp->perm,perm);
		tmp->is_r=(perm[0]=='r');
		tmp->is_w=(perm[1]=='w');
		tmp->is_x=(perm[2]=='x');
		tmp->is_p=(perm[3]=='p');

		//offset
		sscanf(offset,"%lx",&tmp->offset );
		//device
		strcpy(tmp->dev,dev);
		//inode
		tmp->inode=atoi(inode);
		//pathname
		strcpy(tmp->pathname,pathname);
		tmp->track_uffd=0;
		printf("pathname -> %s start 0x%llx\n",pathname,tmp->addr_start);
		if(strlen(pathname) == 0 && tmp->is_r && tmp->is_w)
		{
			printf("add to list\n");
			tmp->track_uffd=1;
		}
		tmp->next=NULL;
		//attach the node
		if(ind==0){
			list_maps=tmp;
			list_maps->next=NULL;
			current_node=list_maps;
		}
		current_node->next=tmp;
		current_node=tmp;
		ind++;
		//printf("%s",buf);
	}

	//close file
	fclose(file);


	//g_last_head=list_maps;
	maps_it->head = list_maps;
	maps_it->current =  list_maps;
	return maps_it;
}


procmaps_struct* pmparser_next(procmaps_iterator* p_procmaps_it){
	if(p_procmaps_it->current == NULL)
		return NULL;
	procmaps_struct* p_current = p_procmaps_it->current;
	p_procmaps_it->current = p_procmaps_it->current->next;
	return p_current;
	/*
	if(g_current==NULL){
		g_current=g_last_head;
	}else
		g_current=g_current->next;

	return g_current;
	*/
}



void pmparser_free(procmaps_iterator* p_procmaps_it){
	procmaps_struct* maps_list = p_procmaps_it->head;
	if(maps_list==NULL) return ;
	procmaps_struct* act=maps_list;
	procmaps_struct* nxt=act->next;
	while(act!=NULL){
		free(act);
		act=nxt;
		if(nxt!=NULL)
			nxt=nxt->next;
	}
	free(p_procmaps_it);
}


void _pmparser_split_line(
		char*buf,char*addr1,char*addr2,
		char*perm,char* offset,char* device,char*inode,
		char* pathname){
	//
	int orig=0;
	int i=0;
	//addr1
	while(buf[i]!='-'){
		addr1[i-orig]=buf[i];
		i++;
	}
	addr1[i]='\0';
	i++;
	//addr2
	orig=i;
	while(buf[i]!='\t' && buf[i]!=' '){
		addr2[i-orig]=buf[i];
		i++;
	}
	addr2[i-orig]='\0';

	//perm
	while(buf[i]=='\t' || buf[i]==' ')
		i++;
	orig=i;
	while(buf[i]!='\t' && buf[i]!=' '){
		perm[i-orig]=buf[i];
		i++;
	}
	perm[i-orig]='\0';
	//offset
	while(buf[i]=='\t' || buf[i]==' ')
		i++;
	orig=i;
	while(buf[i]!='\t' && buf[i]!=' '){
		offset[i-orig]=buf[i];
		i++;
	}
	offset[i-orig]='\0';
	//dev
	while(buf[i]=='\t' || buf[i]==' ')
		i++;
	orig=i;
	while(buf[i]!='\t' && buf[i]!=' '){
		device[i-orig]=buf[i];
		i++;
	}
	device[i-orig]='\0';
	//inode
	while(buf[i]=='\t' || buf[i]==' ')
		i++;
	orig=i;
	while(buf[i]!='\t' && buf[i]!=' '){
		inode[i-orig]=buf[i];
		i++;
	}
	inode[i-orig]='\0';
	//pathname
	pathname[0]='\0';
	while(buf[i]=='\t' || buf[i]==' ')
		i++;
	orig=i;
	while(buf[i]!='\t' && buf[i]!=' ' && buf[i]!='\n'){
		pathname[i-orig]=buf[i];
		i++;
	}
	pathname[i-orig]='\0';

}

void pmparser_print(procmaps_struct* map, int order){

	procmaps_struct* tmp=map;
	int id=0;
	if(order<0) order=-1;
	while(tmp!=NULL){
		//(unsigned long) tmp->addr_start;
		if(order==id || order==-1){
			printf("Backed by:\t%s\n",strlen(tmp->pathname)==0?"[anonym*]":tmp->pathname);
			printf("Range:\t\t%p-%p\n",tmp->addr_start,tmp->addr_end);
			printf("Length:\t\t%ld\n",tmp->length);
			printf("Offset:\t\t%ld\n",tmp->offset);
			printf("Permissions:\t%s\n",tmp->perm);
			printf("Inode:\t\t%d\n",tmp->inode);
			printf("Device:\t\t%s\n",tmp->dev);
		}
		if(order!=-1 && id>order)
			tmp=NULL;
		else if(order==-1){
			tmp=tmp->next;
		}else tmp=tmp->next;

		id++;
	}
}

