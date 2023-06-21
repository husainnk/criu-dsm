
/*
 @Author	: ouadimjamal@gmail.com
 @date		: December 2015

Permission to use, copy, modify, distribute, and sell this software and its
documentation for any purpose is hereby granted without fee, provided that
the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation.  No representations are made about the suitability of this
software for any purpose.  It is provided "as is" without express or
implied warranty.
*/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

//#include "parsemap.c"

/**
 * gobal variables
 */
//procmaps_struct* g_last_head=NULL;
//procmaps_struct* g_current=NULL;


//maximum line length in a procmaps file
#define PATH_MAX 90000
#define PROCMAPS_LINE_MAX_LENGTH  (PATH_MAX + 100) 
/**
 * procmaps_struct
 * @desc hold all the information about an area in the process's  VM
 */
typedef struct procmaps_struct{
	void* addr_start; 	//< start address of the area
	void* addr_end; 	//< end address
	unsigned long length; //< size of the range

	char perm[5];		//< permissions rwxp
	short is_r;			//< rewrote of perm with short flags
	short is_w;
	short is_x;
	short is_p;

	long offset;	//< offset
	char dev[12];	//< dev major:minor
	int inode;		//< inode of the file that backs the area

	char pathname[600];		//< the path of the file that backs the area
	//chained list
	struct procmaps_struct* next;		//<handler of the chinaed list

	short track_uffd;
} procmaps_struct;

/**
 * procmaps_iterator
 * @desc holds iterating information
 */
typedef struct procmaps_iterator{
	procmaps_struct* head;
	procmaps_struct* current;
} procmaps_iterator;


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
		//printf("#%s",buf);
		//printf("%s-%s %s %s %s %s\t%s\n",addr1,addr2,perm,offset,dev,inode,pathname);
		//addr_start & addr_end
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
			printf("#################################\n");
			tmp=tmp->next;
		}else tmp=tmp->next;

		id++;
	}
}
