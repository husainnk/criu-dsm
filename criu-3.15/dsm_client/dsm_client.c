#include <assert.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <netinet/in.h>

#include "parasite.h"
#include "log.h"
#include "infect-rpc.h"
#include "../compel/include/infect-priv.h"
#include "parsemap.h"
#include "config.h"
#include "dsm_log.h"


#define err_and_ret(msg) do { fprintf(stderr, msg);  return -1; } while (0)

#define MAX_THREADS 10
#define MAX_STRING 250

#define GET_UFFD PARASITE_USER_CMDS
#define EXEC_MADVISE PARASITE_USER_CMDS+1
#define DUMP_SINGLE_PAGE PARASITE_USER_CMDS+2

struct params {
    int uffd;
    long page_size;
    int sock;
};

int compel_rpc_sync(unsigned int cmd, struct parasite_ctl *ctl);
int compel_util_recv_fd(struct parasite_ctl *ctl, int *pfd);
int compel_syscall(struct parasite_ctl *ctl, int nr, long *ret,
                                         unsigned long arg1,
                                         unsigned long arg2,
                                         unsigned long arg3,
                                         unsigned long arg4,
                                         unsigned long arg5,
                                         unsigned long arg6);



struct page_list{
        long saddr;
        short state ;
	pthread_mutex_t mutex;
};

struct page_list *page_list_data;
int total_pages; 

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
	MSG_WAKE_THREAD
};

enum page_state{
        PAGE_MODIFIED,
        PAGE_SHARED,
        PAGE_INVALID,
};


volatile int fault_in_progress = 0;
volatile long fault_in_progress_addr = 0;
volatile int uffd_interrupted = 0;
static volatile int stop;
procmaps_iterator* maps;
pthread_mutex_t    mutex = PTHREAD_MUTEX_INITIALIZER;
int page_data_socket;
pthread_t uffd_thread;


int page_size = 4096;
pid_t thread_id[MAX_THREADS];	
volatile int  uffd_in_progress = 0;

static void print_vmsg(unsigned int lvl, const char *fmt, va_list parms)
{
}

int stealUFFD(struct parasite_ctl *ctx) {
	int uffd;
	if(compel_rpc_call(GET_UFFD, ctx) ||
			compel_util_recv_fd(ctx, &uffd) ||
			compel_rpc_sync(GET_UFFD, ctx))
		return -1;

	return uffd;
}

int get_thread_ids(pid_t *thread_id, pid_t pid, size_t *entries, size_t max_size)
{
	char dir_name[MAX_STRING];
	DIR *dir;
	struct dirent *entry;
	int tid, e;
	int max_threads;
	char d;

	*entries = 0;
	e = 0;

	max_threads = max_size/sizeof(pid_t);

	if (snprintf(dir_name, sizeof(dir_name), "/proc/%d/task/", (int)pid) \
			>= sizeof(dir_name))
		return -ENOTSUP;

	dir = opendir(dir_name);
	if (!dir) 
		return -ENOENT;

	while(1) {
		entry = readdir(dir);

		if(!entry)
			break;

		if(e >= max_threads)
			break;

		if(sscanf(entry->d_name, "%d%c", &tid, &d) != 1)
			continue;

		if(tid < 1)
			continue;

		thread_id[e++] = (pid_t)tid;
	}

	*entries = e;

	if(closedir(dir))
		return -ENOTSUP;

	return 0;
}

static int connect_page_data_server(){

	printf("connect_page_data_server\n");
	int sock = 0, valread;
	struct sockaddr_in serv_addr;

	// create socket
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("\n Socket creation error \n");
		return -1;
	}

	// set server address
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(8081);
	if(inet_pton(AF_INET, SERVER_ADDR, &serv_addr.sin_addr)<=0) {
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	// connect to server
	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		printf("\nConnection Failed \n");
		return -1;
	}
	return sock;
}


static int connect_server(){

	int sock = 0, valread;
	struct sockaddr_in serv_addr;

	// create socket
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("\n Socket creation error \n");
		return -1;
	}

	// set server address
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(8080);
	if(inet_pton(AF_INET, SERVER_ADDR, &serv_addr.sin_addr)<=0) {
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	// connect to server
	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		printf("\nConnection Failed \n");
		return -1;
	}

	return sock;
}

static int get_page_data_from_origin(int sock,long addr,unsigned char *page_content,bool is_write){

	struct msg_info dsm_msg;

	dsm_msg.msg_type = is_write ? MSG_GET_PAGE_DATA_INVALID :MSG_GET_PAGE_DATA;
	dsm_msg.page_addr = addr;

	send(sock, &dsm_msg, sizeof(struct msg_info), 0);
	int data_read = 0;

	while(data_read < page_size){
		int ret = read(sock,page_content + data_read,page_size);
		FT_PRINTF("page_read ret=%d\n",ret);
		if(ret == 0)
			exit(0);
		data_read += ret;
	}
	return 0;
}

static void *handler(void *arg)
{
	struct params *p = arg;
	char buf[page_size];


	for (;;) {
		struct uffd_msg msg;

		struct pollfd pollfd[1];
		pollfd[0].fd = p->uffd;
		pollfd[0].events = POLLIN;
		// wait for a userfaultfd event to occur
		int pollres = poll(pollfd, 1, 2000);

		if (stop)
			return NULL;

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
		uffd_interrupted = 0;
		FT_PRINTF("####### Fault START\n");

		if (readres == -1) {
			if (errno == EAGAIN)
				continue;
			perror("read/userfaultfd");
			exit(1);
		}

		if (readres != sizeof(msg)) {
			fprintf(stderr, "invalid msg size\n");
			exit(1);
		}

		fault_in_progress = 1;
		fault_in_progress_addr = msg.arg.pagefault.address;
		long long addr = msg.arg.pagefault.address;
//		pthread_mutex_lock(&page_list_data[addr_to_index(addr)].mutex);
		unsigned char ack ;
		// handle the page fault by copying a page worth of bytes
		if (msg.event & UFFD_EVENT_PAGEFAULT) {

			if(msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP)
			{
				FT_PRINTF("fault for write-protect 0x%llx\n",addr);
/*
				if(page_list_data[addr_to_index(addr)].state == PAGE_INVALID ){
					FT_PRINTF("--------------- $$$$$$$$ PAGE_INVALID\n");
					bool is_write = 1;
					FT_PRINTF("fault for over missing page %llx , writefault : %d\n",(long long)addr,is_write);
					unsigned char page_content[page_size];
					get_page_data_from_origin(p->sock,addr,page_content,is_write);
					FT_PRINTF("got the page\n");

					struct uffdio_copy copy;
					copy.src = (long long)page_content;
					copy.dst = (long long)addr;
					copy.len = page_size;
					copy.mode = is_write ? 0 : UFFDIO_COPY_MODE_WP;
					if (ioctl(p->uffd, UFFDIO_COPY, &copy) == -1) {
						perror("ioctl/copy");
						exit(1);
					}
				}
*/
				struct uffdio_writeprotect prms;

				/* Write protection page faults */
				prms.range.start = addr;
				prms.range.len = page_size; 
				/* Undo write-protect, do wakeup after that */
				prms.mode =  0; 

				send_page_invalidate_msg(addr,p->sock);
				read(p->sock, &ack,1);
				if(ack == 0x89)
				{
					FT_PRINTF("Page server says owner changed, we need to get the updated page");
					int data_read = 0;
					
					unsigned char page_content[4096];
					while(data_read < page_size){
						int ret = read(p->sock,page_content+data_read,page_size);
						FT_PRINTF("#3 ret=%d\n",ret);
						if(ret == 0)
							exit(0);
						data_read += ret;
					}
					struct uffdio_copy copy;
					copy.src = (long long)page_content;
					copy.dst = (long long)addr;
					copy.len = page_size;
					copy.mode = 0;
					if (ioctl(p->uffd, UFFDIO_COPY, &copy) == -1) {
						perror("ioctl/copy");
					}
					FT_PRINTF(".........page write........\n");
					for(int i=0x00;i<0x30;i++)
						FT_PRINTF("%03d ",page_content[i]);
					FT_PRINTF("\n");
					FT_PRINTF("updated special page request\n");
				}
				if (ioctl(p->uffd, UFFDIO_WRITEPROTECT, &prms))
					perror("write_protect\n");
				FT_PRINTF("write flag cleared\n");
				set_page_status(addr,PAGE_MODIFIED);
				if(uffd_interrupted)
					FT_PRINTF(".........UFFD_INTERRUPTED..........\n");
			}

			else {
				//	pthread_mutex_lock(&mutex);
				bool is_write =  msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE;
				FT_PRINTF("fault for missing page %llx , writefault : %d\n",(long long)addr,is_write);
				unsigned char page_content[page_size];
				get_page_data_from_origin(p->sock,addr,page_content,is_write);
				FT_PRINTF("got the page\n");

				struct uffdio_copy copy;
				copy.src = (long long)page_content;
				copy.dst = (long long)addr;
				copy.len = page_size;
				// if it is write fault means, allow writing. if read fault, set writeprotect
				copy.mode = is_write ? 0 : UFFDIO_COPY_MODE_WP;
//				copy.mode = is_write ? UFFDIO_COPY_MODE_WP: 0;
				if (ioctl(p->uffd, UFFDIO_COPY, &copy) == -1) {
					perror("ioctl/copy");
					//exit(1);
				}
				FT_PRINTF("@@~~~~~~ page write ~~~~~~~~ copy_mode=%d\n",copy.mode);
					for(int i=0x00;i<0x30;i++)
						FT_PRINTF("%03d ",page_content[i]);
					FT_PRINTF("\n");

				if(is_write)
					set_page_status(addr,PAGE_MODIFIED);
				else
					set_page_status(addr,PAGE_SHARED);

			}
			fault_in_progress = 0;
			uffd_interrupted=0;
		}
		//	pthread_mutex_unlock(&page_list_data[addr_to_index(addr)].mutex);
		FT_PRINTF("####### Fault END\n");

	}

    return NULL;
}


int addr_to_index(long long addr){

        for(int i=0;i<total_pages;i++){
                if(addr == page_list_data[i].saddr)
                        return i;
        }
        printf("FATAL: Page not found\n");
        exit(0);
}

static int get_page_list_from_origin(int sock){

    int  valread;
    struct sockaddr_in serv_addr;
    struct msg_info page_list_msg;

    page_list_msg.msg_type = MSG_GET_PAGE_LIST;
    send(sock,&page_list_msg,sizeof(struct msg_info),0);

    valread = read( sock , &total_pages,sizeof(total_pages));
    printf("total_pages %d\n",total_pages);

    page_list_data = (struct page_list*) malloc(sizeof(struct page_list)*total_pages );
    for(int i=0;i<total_pages;i++){
	valread = read(sock, &page_list_data[i].saddr,sizeof(long));
    }
    for (int i=0;i<total_pages;i++)
	    pthread_mutex_init(&page_list_data[i].mutex, NULL);

#if 0
    for(int i=0;i<total_pages;i++){
	printf("i=%d 0x%lx \n",i,page_list_data[i].saddr);	
    }
#endif

}


void send_page_invalidate_msg(long addr,int sock){

        struct msg_info dsm_msg;

        FT_PRINTF("send_page_invalidate_msg :%lx\n",addr);
        dsm_msg.msg_type = MSG_INVALIDATE_PAGE;
        dsm_msg.page_addr = addr;

        send(sock,&dsm_msg,sizeof(struct msg_info),0);
}


void invalidate_restored_pages(long *addr,int length,int pid,	struct parasite_ctl *ctl){

	int state;
	struct infect_ctx *ictx;
	long *arg;


	arg = compel_parasite_args(ctl, long);

	for( int i=0;i<total_pages;i++)
	{
		if( page_list_data[i].saddr >= 0x800000 && page_list_data[i].saddr <= 0x801000)
		{
			*arg = 	page_list_data[i].saddr ;
			if (compel_rpc_call_sync(EXEC_MADVISE, ctl))
				err_and_ret("Can't run parasite command 1");
			printf("madvise Success for %llx\n", *arg);
			page_list_data[i].state = PAGE_INVALID;
		}
	}

}

void simulate_page_invalidation(int pid){
	
	while(1){
		sleep(1);
		struct msg_info dsm_msg;
		dsm_msg.page_addr = 0x801000;
		handle_invalidate_page(&dsm_msg,pid);
	}

}

int get_page_status(long addr){
	return  page_list_data[addr_to_index(addr)].state;
}

void set_page_status(long addr,int state){
	page_list_data[addr_to_index(addr)].state = state;
}

void handle_invalidate_page(struct msg_info *dsm_msg,int pid){

	int state;
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;
	long *arg;

	if(fault_in_progress && dsm_msg->page_addr == fault_in_progress_addr){

		printf("@@@@@@@@@@@@ fault int prrogress for %lx\n",fault_in_progress_addr);
//		return ;
	}
	printf("=>invaldate page %lx\n",dsm_msg->page_addr);
	compel_log_init(print_vmsg, COMPEL_LOG_DEBUG);

	state = compel_stop_task(pid);
	if (state < 0)
		printf("Can't stop task\n");

	ctl = compel_prepare(pid);
	if (!ctl)
		err_and_ret("Can't prepare for infection\n");

	/*
	 * First -- the infection context. Most of the stuff
	 * is already filled by compel_prepare(), just set the
	 * log descriptor for parasite side, library cannot
	 * live w/o it.
	 */
	ictx = compel_infect_ctx(ctl);
	ictx->log_fd = STDERR_FILENO;

	parasite_setup_c_header(ctl);

	if (compel_infect(ctl, 1, sizeof(int)))
		err_and_ret("Can't infect victim\n");

	arg = compel_parasite_args(ctl, long);
	*arg = 	dsm_msg->page_addr;
	if (compel_rpc_call_sync(EXEC_MADVISE, ctl))
		err_and_ret("Can't run parasite command 1");
	printf("madvise Success for %llx\n", dsm_msg->page_addr);
	
	set_page_status(dsm_msg->page_addr,PAGE_INVALID);

	if(compel_stop_daemon(ctl))
		printf("Can't stop daeomon\n");
	else
		printf("stop success\n");

	if (compel_cure(ctl))
		printf("Can't cure victim\n");
	else
		printf("cure success\n");
		

	if (compel_resume_task(pid, state, state))
		err_and_ret("Can't unseize task");
	else
		printf("resume success\n");

	
	
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

#if 0
void test_vmsplice(int pid){

	int state;
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;
	long *arg;
	int val, ret,i;
        int p[2];
	unsigned char page_content[4096];

	compel_log_init(print_vmsg, COMPEL_LOG_DEBUG);

	printf("Stopping task\n");
	state = compel_stop_task(pid);
	if (state < 0)
		printf("Can't stop task\n");

	printf("Preparing parasite ctl\n");
	ctl = compel_prepare(pid);
	if (!ctl)
		err_and_ret("Can't prepare for infection");

	printf("Configuring contexts\n");

	/*
	 * First -- the infection context. Most of the stuff
	 * is already filled by compel_prepare(), just set the
	 * log descriptor for parasite side, library cannot
	 * live w/o it.
	 */
	ictx = compel_infect_ctx(ctl);
	ictx->log_fd = STDERR_FILENO;

	parasite_setup_c_header(ctl);
		err_and_ret("Can't infect victim\n");

	arg = compel_parasite_args(ctl, long);
	*arg = 	0x801000;

        ret = compel_rpc_call(DUMP_SINGLE_PAGE , ctl);
        if (ret < 0)
                return -1;
        pipe(p);
        ret = compel_util_send_fd(ctl, p[1]);
        if (ret)
                return -1;


        ret = compel_rpc_sync(DUMP_SINGLE_PAGE, ctl);
        if (ret < 0)
                return -1;
        //Read from parsite pip
        read(p[0], page_content,4096);
	printf("~~~~~~~~~~~~~~~\n");
        for(i=0x26;i<0x30;i++){
                printf("%03d ",page_content[i]);
	}
        printf("\n");
        send(page_data_socket,page_content,4096,0);
        printf("page_transfer_complete\n");

        val = compel_stop_daemon(ctl);
        if (compel_cure(ctl))
                printf("Can't cure (pid: %d) from parasite\n",pid);

        close(p[0]);
        close(p[1]);
}
#endif

void handle_page_data_request(int pid,struct msg_info *dsm_msg,int uffd){

	int state;
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;
	long *arg;
	int val, ret,i;
        int p[2];
	unsigned char page_content[4096];

	compel_log_init(print_vmsg, COMPEL_LOG_DEBUG);

	printf("Stopping task\n");
	state = compel_stop_task(pid);
	if (state < 0)
		printf("Can't stop task\n");

	printf("Preparing parasite ctl\n");
	ctl = compel_prepare(pid);
	if (!ctl)
		err_and_ret("Can't prepare for infection");

	printf("Configuring contexts\n");

	/*
	 * First -- the infection context. Most of the stuff
	 * is already filled by compel_prepare(), just set the
	 * log descriptor for parasite side, library cannot
	 * live w/o it.
	 */
	ictx = compel_infect_ctx(ctl);
	ictx->log_fd = STDERR_FILENO;

	parasite_setup_c_header(ctl);

	printf("Infecting\n");
	if (compel_infect(ctl, 1, sizeof(int)))
		err_and_ret("Can't infect victim\n");

	arg = compel_parasite_args(ctl, long);
	*arg = 	dsm_msg->page_addr;

        ret = compel_rpc_call(DUMP_SINGLE_PAGE , ctl);
        if (ret < 0)
                return -1;
        pipe(p);
        ret = compel_util_send_fd(ctl, p[1]);
        if (ret)
                return -1;


        ret = compel_rpc_sync(DUMP_SINGLE_PAGE, ctl);
        if (ret < 0)
                return -1;

        //Read from parsite pip
        read(p[0], page_content,4096);

	printf("..................... 0x%lx\n",dsm_msg->page_addr);
        for(i=0x00;i<0x30;i++){
                printf("%03d ",page_content[i]);
	}
        printf("\n");

        send(page_data_socket,page_content,4096,0);
        printf("page_transfer_complete\n");
	if(dsm_msg->msg_type == MSG_GET_PAGE_DATA_INVALID){
		set_page_status(dsm_msg->page_addr,PAGE_INVALID);
                printf("Drop the page: \n");
		ret = compel_rpc_call_sync(EXEC_MADVISE, ctl);
                if (ret < 0) 
                        return -1;

        }else // TO SHARED
	{
                change_to_wp( dsm_msg->page_addr,uffd); 
		set_page_status(dsm_msg->page_addr,PAGE_SHARED);
	}

        val = compel_stop_daemon(ctl);
        if (compel_cure(ctl))
                printf("Can't cure (pid: %d) from parasite\n",pid);

	if (compel_resume_task(pid, state, state))
		err_and_ret("Can't unseize task");

        close(p[0]);
        close(p[1]);
}

void listen_for_commands(int sock,int pid,int uffd){

	int msg_served=-1,val;

	kill(pid,SIGCONT);

	for(;;){
		struct msg_info dsm_msg;
		msg_served++;

		unsigned char ack = 0x10;
		RED_PRINTF("Waiting for message, msg_served:%d\n",msg_served);
		int valread = read(page_data_socket, &dsm_msg, sizeof(struct msg_info));

                if(valread <0){ 
			printf("invalid read \n");
			exit(1);
		}
		RED_PRINTF("msg_id: %d\n",dsm_msg.msg_id);

                switch(dsm_msg.msg_type){

                        case MSG_GET_PAGE_LIST:

                        case MSG_GET_PAGE_DATA:
			case MSG_GET_PAGE_DATA_INVALID:
				printf("[MSG] MSG_GET_PAGE_DATA 0x%llx\n",dsm_msg.page_addr );
				pthread_mutex_lock(&page_list_data[addr_to_index(dsm_msg.page_addr)].mutex);
				if(get_page_status(dsm_msg.page_addr) == PAGE_INVALID)
				{
					printf("FATAL Page dropped already\n");
				}
				handle_page_data_request(pid,&dsm_msg,uffd);
				pthread_mutex_unlock(&page_list_data[addr_to_index(dsm_msg.page_addr)].mutex);
				printf("[MSG] MSG_GET_PAGE_DATA 0x%llx DONE\n",dsm_msg.page_addr );
                                break;  
			case MSG_INVALIDATE_PAGE:
				uffd_interrupted = 1;
				printf("[MSG] MSG_INVALIDATE_PAGE 0x%llx\n",dsm_msg.page_addr );
				if(get_page_status(dsm_msg.page_addr) == PAGE_INVALID)
				{
					printf("Page dropped already\n");
					send(page_data_socket,&ack,1,0);
					break;
				}
				pthread_mutex_lock(&page_list_data[addr_to_index(dsm_msg.page_addr)].mutex);
				handle_invalidate_page(&dsm_msg,pid);
				pthread_mutex_unlock(&page_list_data[addr_to_index(dsm_msg.page_addr)].mutex);
				printf("[MSG] MSG_INVALIDATE_PAGE DONE 0x%llx\n",dsm_msg.page_addr );
				send(page_data_socket,&ack,1,0);
				break;	
                        default:
                                printf("Invalid DSM message : %x\n",dsm_msg.msg_type);
				exit(0);

                } 
	}
}
 

static int do_infection(int pid ,int sock)
{

	int state;
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;
	long *arg;

	compel_log_init(print_vmsg, COMPEL_LOG_DEBUG);

	printf("Stopping task\n");
	state = compel_stop_task(pid);
	if (state < 0)
		err_and_ret("Can't stop task");

	printf("Preparing parasite ctl\n");
	ctl = compel_prepare(pid);
	if (!ctl)
		err_and_ret("Can't prepare for infection");

	printf("Configuring contexts\n");

	/*
	 * First -- the infection context. Most of the stuff
	 * is already filled by compel_prepare(), just set the
	 * log descriptor for parasite side, library cannot
	 * live w/o it.
	 */
	ictx = compel_infect_ctx(ctl);
	ictx->log_fd = STDERR_FILENO;

	parasite_setup_c_header(ctl);

	printf("Infecting\n");
	if (compel_infect(ctl, 1, sizeof(int)))
		err_and_ret("Can't infect victim");

	arg = compel_parasite_args(ctl, long);

	int uffd = stealUFFD(ctl);
	printf("uffd %d \n",uffd);


	// enable for api version and check features
	struct uffdio_api uffdio_api;
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

	int success=0;
	struct uffdio_register uffdio_register;	
	int i;
	invalidate_restored_pages(NULL,total_pages,pid,ctl);


	procmaps_struct* maps_tmp=NULL;
	
	while( (maps_tmp = pmparser_next(maps)) != NULL){
		if(maps_tmp->track_uffd == 0){
			continue;
		}
		printf("\n............................\n"); 
		printf("maps_tmp->addr_start %lx %d\n",maps_tmp->addr_start,maps_tmp->length,maps_tmp->length/4096);
		uffdio_register.range.start = maps_tmp->addr_start;
		uffdio_register.range.len =  maps_tmp->length; 
		uffdio_register.mode =    UFFDIO_REGISTER_MODE_MISSING ;
		uffdio_register.mode =   UFFDIO_REGISTER_MODE_WP | UFFDIO_REGISTER_MODE_MISSING ;
		if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
			printf("[UFFDIO_REGISTER] Failed page %llx\n",page_list_data[i].saddr);
		}

		struct uffdio_writeprotect uf_wp;
                uf_wp.range.start = maps_tmp->addr_start;
                uf_wp.range.len = maps_tmp->length ;
                uf_wp.mode =  UFFDIO_WRITEPROTECT_MODE_WP;

                if (ioctl(uffd, UFFDIO_WRITEPROTECT, &uf_wp))
                {    
                        perror("write_protect\n");
                        printf("page : %llx\n",page_list_data[i].saddr);
                }   
		success++;
	}
	printf("success:%d/%d\n",success,total_pages);

	if ((uffdio_register.ioctls & UFFD_API_RANGE_IOCTLS) !=
			UFFD_API_RANGE_IOCTLS) {
		fprintf(stderr, "unexpected userfaultfd ioctl set\n");
	}

	printf("register Success\n");

	stop = 0;
	struct params p;
	p.uffd = uffd;
	p.page_size = page_size;
	p.sock = sock;

	/*
	 * Done. Cure and resume the task.
	 */
	printf("Curing\n");
	if(compel_stop_daemon(ctl))
		printf("Can't stop daeomon #1\n");
	if (compel_cure(ctl))
		printf("Can't cure victim\n");


	if (compel_resume_task(pid, state, state))
		err_and_ret("Can't unseize task");


	printf("Done; Starting uffd_thread\n");
	pthread_create(&uffd_thread, NULL, handler, &p);

	return uffd;
}

int main(int argc, char **argv)
{
	int pid,sock;
	int uffd;

	pid = atoi(argv[1]);

	/*Get VMA Areas*/
	maps = pmparser_parse(pid);

	/*Connect to page Servers*/
	sock = connect_server();
	sleep(1);
	page_data_socket = connect_page_data_server();
	get_page_list_from_origin(sock);
	
	/*Register UFFD with parasite and start UFFD Thread*/
	uffd = do_infection(pid,sock);

	/*Start Page server */
	listen_for_commands(sock,pid,uffd);
	
	pthread_join(uffd_thread, NULL);
	
	return 0;
}
