#include <errno.h>

#include <compel/plugins/std.h>
#undef COMPEL_PLUGIN_STD_STD_H__
#include <compel/plugins/plugin-fds.h>
#include <infect-rpc.h>

/*
 * Stubs for std compel plugin.
 */
int parasite_trap_cmd(int cmd, void *args) { return 0; }
void parasite_cleanup(void) { }

#define GET_UFFD PARASITE_USER_CMDS
#define RUN_FD PARASITE_USER_CMDS+1
#define DUMP_SINGLE_PAGE PARASITE_USER_CMDS+2


#define MADV_DONTNEED 4

#define SPLICE_F_GIFT 8
#define SPLICE_F_NONBLOCK 2

#define ERROR( fmt, ... ) \
  std_dprintf(STDERR_FILENO, "ERROR: parasite: " fmt, ##__VA_ARGS__)
#ifndef NDEBUG
# define DEBUG( fmt, ... ) \
  std_dprintf(STDERR_FILENO, "DEBUG: parasite: " fmt, ##__VA_ARGS__)
#else
# define DEBUG( fmt, ... ) {}
#endif

static int dump_single_page(void *args){
        
        int p, ret, tsock;
        int nr_segs =1;
        tsock = parasite_get_rpc_sock();

        p = recv_fd(tsock);

        struct iovec miov;
        miov.iov_base =*(long *)args;
        miov.iov_len = 4096;
        //DEBUG("vmsplice at = %lx\n",miov.iov_base);
        ret = sys_vmsplice(p, &miov, nr_segs,    SPLICE_F_GIFT | SPLICE_F_NONBLOCK);
        //DEBUG("vmsplice ret = %d\n",ret);
        return 0;
        
}


static int createAndSendUFFD(void) {                                                                                                                                              
	int uffd, ret;
	if((uffd = sys_userfaultfd( O_CLOEXEC | O_NONBLOCK)) == -1) {
		ERROR("could not create userfaultfd descriptor %d\n",uffd);
		return -1; 
	}
	DEBUG("initialized uffd %d\n", uffd);
	ret = fds_send_fd(uffd);
	if(ret == 0) {
		 DEBUG("sent uffd\n"); 
	}
	else 
		DEBUG("could not send uffd\n");
  	sys_close(uffd);
 	 return ret;
}


int parasite_daemon_cmd(int cmd, void *args)
{
	int v;

#if 1
	switch (cmd) {
	case GET_UFFD:
		createAndSendUFFD();
		break;
	case RUN_FD:
//		DEBUG("madvise at %lx\n",*(long *)args);
		sys_madvise (*(long *)args, 4096, MADV_DONTNEED);
		break;
	case DUMP_SINGLE_PAGE:
//		DEBUG("vmsplice at %lx\n",*(long *)args);
		dump_single_page(args);
		break;
	default:
		break;
	}
#endif
	
//	sys_write(1, &v, sizeof(int));

	return 0;
}


