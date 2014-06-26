#include<stdlib.h>
#include<stdio.h>
#include<string.h>

#include "rdtsc.h"

#define NULL_PORT	0xffffffff
////////////////////////////////////////////////////////////////////////////////////
struct ENTRY{
	unsigned int ip1;
	unsigned int ip2;
	unsigned int ip3;
	unsigned int ip4;
	unsigned char len;
	unsigned int port;
};
////////////////////////////////////////////////////////////////////////////////////
struct list{//structure of binary trie
	unsigned int port;
	struct list *left,*right;
};
typedef struct list node;
typedef node *btrie;
////////////////////////////////////////////////////////////////////////////////////
/*global variables*/
btrie root;
unsigned int *query1;
unsigned int *query2;
unsigned int *query3;
unsigned int *query4;
unsigned int *query_len;
int num_entry=0;
int num_query=0;
struct ENTRY *table;
int N=0;//number of nodes
unsigned long long int begin,end,total=0;
unsigned long long int *clock;
int num_node=0;//total number of nodes in the binary trie
/*
   unsigned int hex2dec( char hex )
   {
   switch( hex )
   {
   case '0': return 0;
   case '1': return 1;
   case '2': return 2;
   case '3': return 3;
   case '4': return 4;
   case '5': return 5;
   case '6': return 6;
   case '7': return 7;
   case '8': return 8;
   case '9': return 9;
   case 'a': return 10;
   case 'b': return 11;
   case 'c': return 12;
   case 'd': return 13;
   case 'e': return 14;
   case 'f': return 15;
   default: return 0;
   }
   }
 */


////////////////////////////////////////////////////////////////////////////////////
btrie create_node(){
	btrie temp;
	num_node++;
	temp=(btrie)malloc(sizeof(node));
	temp->right=NULL;
	temp->left=NULL;
	temp->port=NULL_PORT;//default port
	return temp;
}
////////////////////////////////////////////////////////////////////////////////////
void add_node(unsigned int ip1,unsigned int ip2, unsigned int ip3, unsigned int ip4,unsigned char len,unsigned int nexthop){
	btrie ptr=root;
	int i;

	if( len==0 )
		ptr->port=0;

	for(i=0;i<len;i++)
	{
		if( (i>=0) && (i<32) )		
		{
			if(ip1&(1<<(31-i))){
				if(ptr->right==NULL)
					ptr->right=create_node();
				ptr=ptr->right;
				if((i==len-1)&&(ptr->port==NULL_PORT))
					ptr->port=nexthop;
			}
			else{
				if(ptr->left==NULL)
					ptr->left=create_node();
				ptr=ptr->left;
				if((i==len-1)&&(ptr->port==NULL_PORT))
					ptr->port=nexthop;
			}
		}
		if( (i>=32) && (i<64) )		
		{
			if(ip2&(1<<(63-i))){
				if(ptr->right==NULL)
					ptr->right=create_node();
				ptr=ptr->right;
				if((i==len-1)&&(ptr->port==NULL_PORT))
					ptr->port=nexthop;
			}
			else{
				if(ptr->left==NULL)
					ptr->left=create_node();
				ptr=ptr->left;
				if((i==len-1)&&(ptr->port==NULL_PORT))
					ptr->port=nexthop;
			}
		}
		if( (i>=64) && (i<96) )		
		{
			if(ip3&(1<<(95-i))){
				if(ptr->right==NULL)
					ptr->right=create_node();
				ptr=ptr->right;
				if((i==len-1)&&(ptr->port==NULL_PORT))
					ptr->port=nexthop;
			}
			else{
				if(ptr->left==NULL)
					ptr->left=create_node();
				ptr=ptr->left;
				if((i==len-1)&&(ptr->port==NULL_PORT))
					ptr->port=nexthop;
			}
		}
		if( (i>=96) && (i<128) )		
		{
			if(ip4&(1<<(127-i))){
				if(ptr->right==NULL)
					ptr->right=create_node();
				ptr=ptr->right;
				if((i==len-1)&&(ptr->port==NULL_PORT))
					ptr->port=nexthop;
			}
			else{
				if(ptr->left==NULL)
					ptr->left=create_node();
				ptr=ptr->left;
				if((i==len-1)&&(ptr->port==NULL_PORT))
					ptr->port=nexthop;
			}
		}
	}
}
////////////////////////////////////////////////////////////////////////////////////
void read_table_ipv6c(char *str,unsigned int *ip1, unsigned int *ip2,unsigned int *ip3, unsigned int *ip4,int *len,unsigned int *nexthop){
	char tok1[]="/";
	char buf[100],*str1;

	unsigned int u_ip[8];

	char s_in_ip[200];
	char s_in_len[200];
	unsigned int u_in_len;	
	char s_ip[8][50];
	unsigned int zero_flag;
	unsigned int k;

	sscanf( str, "%x:%x:%x:%x:%x:%x:%x:%x/%u\n", &u_ip[0], &u_ip[1], &u_ip[2], &u_ip[3], &u_ip[4], &u_ip[5], &u_ip[6], &u_ip[7], &u_in_len );
	//u_in_len = atoi(s_in_len);

	//printf("%s/%u\n", s_in_ip, u_in_len);

	//strcpy( s_ip[0], "0000" ); strcpy( s_ip[1], "0000" ); strcpy( s_ip[2], "0000" ); strcpy( s_ip[3], "0000" );
	//strcpy( s_ip[4], "0000" ); strcpy( s_ip[5], "0000" ); strcpy( s_ip[6], "0000" ); strcpy( s_ip[7], "0000" );

	/*
	   if( u_in_len == 128 )
	   sscanf( s_in_ip, "%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%s", s_ip[0], s_ip[1], s_ip[2], s_ip[3], s_ip[4], s_ip[5], s_ip[6], s_ip[7] );
	   if( (u_in_len < 128) && (u_in_len > 112) )
	   sscanf( s_in_ip, "%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]", s_ip[0], s_ip[1], s_ip[2], s_ip[3], s_ip[4], s_ip[5], s_ip[6], s_ip[7] );
	   if( (u_in_len <= 112) && (u_in_len > 96) )
	   sscanf( s_in_ip, "%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]", s_ip[0], s_ip[1], s_ip[2], s_ip[3], s_ip[4], s_ip[5], s_ip[6], s_ip[7] );
	   if( (u_in_len <= 96) && (u_in_len > 80) )
	   sscanf( s_in_ip, "%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]", s_ip[0], s_ip[1], s_ip[2], s_ip[3], s_ip[4], s_ip[5] );
	   if( (u_in_len <= 80) && (u_in_len > 64) )
	   sscanf( s_in_ip, "%[^:]:%[^:]:%[^:]:%[^:]:%[^:]", s_ip[0], s_ip[1], s_ip[2], s_ip[3], s_ip[4] );
	   if( (u_in_len <= 64) && (u_in_len > 48) )
	   sscanf( s_in_ip, "%[^:]:%[^:]:%[^:]:%[^:]", s_ip[0], s_ip[1], s_ip[2], s_ip[3] );
	   if( (u_in_len <= 48) && (u_in_len > 32) )
	   sscanf( s_in_ip, "%[^:]:%[^:]:%[^:]", s_ip[0], s_ip[1], s_ip[2] );
	   if( (u_in_len <= 32) && (u_in_len > 16) )
	   sscanf( s_in_ip, "%[^:]:%[^:]", s_ip[0], s_ip[1] );
	   if( (u_in_len <= 16) && (u_in_len > 0) )
	   sscanf( s_in_ip, "%[^:]", s_ip[0] );
	 */
	/*
	   u_ip[0] = (hex2dec(s_ip[0][0])<<12)+(hex2dec(s_ip[0][1])<<8)+(hex2dec(s_ip[0][2])<<4)+(hex2dec(s_ip[0][3])<<0);
	   u_ip[1] = (hex2dec(s_ip[1][0])<<12)+(hex2dec(s_ip[1][1])<<8)+(hex2dec(s_ip[1][2])<<4)+(hex2dec(s_ip[1][3])<<0);
	   u_ip[2] = (hex2dec(s_ip[2][0])<<12)+(hex2dec(s_ip[2][1])<<8)+(hex2dec(s_ip[2][2])<<4)+(hex2dec(s_ip[2][3])<<0);
	   u_ip[3] = (hex2dec(s_ip[3][0])<<12)+(hex2dec(s_ip[3][1])<<8)+(hex2dec(s_ip[3][2])<<4)+(hex2dec(s_ip[3][3])<<0);
	   u_ip[4] = (hex2dec(s_ip[4][0])<<12)+(hex2dec(s_ip[4][1])<<8)+(hex2dec(s_ip[4][2])<<4)+(hex2dec(s_ip[4][3])<<0);
	   u_ip[5] = (hex2dec(s_ip[5][0])<<12)+(hex2dec(s_ip[5][1])<<8)+(hex2dec(s_ip[5][2])<<4)+(hex2dec(s_ip[5][3])<<0);
	   u_ip[6] = (hex2dec(s_ip[6][0])<<12)+(hex2dec(s_ip[6][1])<<8)+(hex2dec(s_ip[6][2])<<4)+(hex2dec(s_ip[6][3])<<0);
	   u_ip[7] = (hex2dec(s_ip[7][0])<<12)+(hex2dec(s_ip[7][1])<<8)+(hex2dec(s_ip[7][2])<<4)+(hex2dec(s_ip[7][3])<<0);
	 */
	zero_flag=0;

	for( k=0; k<8; k++ )
	{
		if( u_ip[7-k] == 0 )
		{
			zero_flag++;
		}
		else
		{
			break;
		}
	}

	*ip1 = ((u_ip[0]<<16)+(u_ip[1]));
	*ip2 = ((u_ip[2]<<16)+(u_ip[3]));
	*ip3 = ((u_ip[4]<<16)+(u_ip[5]));
	*ip4 = ((u_ip[6]<<16)+(u_ip[7]));

	*len = u_in_len;
	*nexthop = *ip1;
}

void read_query_ipv6c(char *str,unsigned int *ip1, unsigned int *ip2,unsigned int *ip3, unsigned int *ip4 ){
	char tok1[]="/";
	char buf[100],*str1;

	unsigned int u_ip[8];

	char s_in_ip[200];
	char s_in_len[200];
	unsigned int u_in_len;	
	char s_ip[8][50];
	unsigned int zero_flag;
	unsigned int k;

	sscanf( str, "%x:%x:%x:%x:%x:%x:%x:%x\n", &u_ip[0], &u_ip[1], &u_ip[2], &u_ip[3], &u_ip[4], &u_ip[5], &u_ip[6], &u_ip[7] );

	zero_flag=0;

	for( k=0; k<8; k++ )
	{
		if( u_ip[7-k] == 0 )
		{
			zero_flag++;
		}
		else
		{
			break;
		}
	}

	*ip1 = ((u_ip[0]<<16)+(u_ip[1]));
	*ip2 = ((u_ip[2]<<16)+(u_ip[3]));
	*ip3 = ((u_ip[4]<<16)+(u_ip[5]));
	*ip4 = ((u_ip[6]<<16)+(u_ip[7]));
}
////////////////////////////////////////////////////////////////////////////////////
//char * print_ip(unsigned ip)
//{
//	int i;
//	char * result_ip;
//
//	for (i=3; i>=0; i--){
//		printf("%d", ((ip>>(8*i))&0xff));
//		if(i !=0) printf(".");
//	}
//
//}

////////////////////////////////////////////////////////////////////////////////////
/*
   void ipv6_linear_search(unsigned int ip1, unsigned ip2, unsigned int ip3, unsigned int ip4)
   {
   int i, j, oct;
   unsigned int agg_len=0;
   unsigned int temp_len=0;
   unsigned int current_len;
   unsigned int mark = 0xffffffff;

   for( i=0; i<num_entry; i++ )
   {
   current_len = table[i].len;

   if( current_len == 128 )
   {
   if( (ip1==table[i].ip1) && (ip2==table[i].ip2) && (ip3==table[i].ip3) && (ip4==table[i].ip4) )
   {
   temp_len = 128;
   mark = table[i].port;
   }
   }
   else if( current_len > 96 )
   {
   if( (ip1==table[i].ip1) && (ip2==table[i].ip2) && (ip3==table[i].ip3) &&
   ((ip4>>(128-current_len)) == (table[i].ip4>>(128-current_len))) )
   {
   if( current_len > temp_len )
   {
   temp_len = current_len;
   mark = table[i].port;
   }
   }
   }
   else if( current_len > 64 )
   {
   if( (ip1==table[i].ip1) && (ip2==table[i].ip2) && 
   ((ip3>>(96-current_len)) == (table[i].ip3>>(96-current_len))) )
   {
   if( current_len > temp_len )
   {
   temp_len = current_len;
   mark = table[i].port;
   }
   }
   }
   else if( current_len > 32 )
   {
   if( (ip1==table[i].ip1) && ((ip2>>(64-current_len)) == (table[i].ip2>>(64-current_len))) )
   {
   if( current_len > temp_len )
   {
   temp_len = current_len;
   mark = table[i].port;
   }
   }
   }
   else if( current_len > 0 )
   {
   if( ((ip1>>(32-current_len)) == (table[i].ip1>>(32-current_len))) )
   {
   if( current_len > temp_len )
   {
   temp_len = current_len;
   mark = table[i].port;
   }
   }
   }
   else
   {
   temp_len = 0;
   mark = 0;
}			
}
printf("%u\n", mark);
}*/
////////////////////////////////////////////////////////////////////////////////////
void ipv6_binary_trie_search(unsigned int ip1, unsigned ip2, unsigned int ip3, unsigned int ip4)
{
	int j, oct;
	unsigned int agg_len=0;

	char * result_prefix="";
	btrie current=root,temp=NULL,temp2=NULL;

	for(j=127;j>=(-1);j--)
	{	
		if(current==NULL)
			break;
		if(current->port!=NULL_PORT)
			temp=current;
		if((j<128)&&(j>=96))
		{
			if(ip1&(1<<(j-96)))
			{
				current=current->right;
			}
			else{
				current=current->left; 
			}
		}
		if((j<96)&&(j>=64))
		{
			if(ip2&(1<<(j-64)))
			{
				current=current->right;
			}
			else{
				current=current->left; 
			}
		}
		if((j<64)&&(j>=32))
		{
			if(ip3&(1<<(j-32)))
			{
				current=current->right;
			}
			else{
				current=current->left; 
			}
		}
		if((j<32)&&(j>=(-1)))
		{
			if(ip4&(1<<(j-0)))
			{
				current=current->right;
			}
			else{
				current=current->left; 
			}
		}
		agg_len++;
	}
	//if( temp == NULL ) printf("0\n");
	//else if( temp->port != NULL_PORT )
	//	printf("%u\n", temp->port);
	//else printf("0\n");
}
////////////////////////////////////////////////////////////////////////////////////
void set_table(char *file_name){
	FILE *fp;
	int len;
	char string[200];
	unsigned int ip1, ip2, ip3, ip4,nexthop;
	fp=fopen(file_name,"r");
	while(fgets(string,150,fp)!=NULL){
		read_table_ipv6c(string,&ip1,&ip2,&ip3,&ip4,&len,&nexthop);
		num_entry++;
	}
	rewind(fp);
	table=(struct ENTRY *)malloc(num_entry*sizeof(struct ENTRY));
	num_entry=0;
	while(fgets(string,50,fp)!=NULL){
		//read_table(string,&ip,&len,&nexthop);
		read_table_ipv6c(string,&ip1,&ip2,&ip3,&ip4,&len,&nexthop);
		table[num_entry].ip1=ip1;
		table[num_entry].ip2=ip2;
		table[num_entry].ip3=ip3;
		table[num_entry].ip4=ip4;
		table[num_entry].port=num_entry;
		table[num_entry++].len=len;
	}
	fclose(fp);
}
////////////////////////////////////////////////////////////////////////////////////
void set_query(char *file_name){
	FILE *fp;
	int len;
	char string[100];
	//unsigned int ip,nexthop;
	unsigned int ip1, ip2, ip3, ip4,nexthop;
	fp=fopen(file_name,"r");
	while(fgets(string,50,fp)!=NULL){
#ifdef DEBUG_MODE
		read_table_ipv6c(string,&ip1,&ip2,&ip3,&ip4,&len,&nexthop);
#else
		read_query_ipv6c(string,&ip1,&ip2,&ip3,&ip4);
#endif
		num_query++;
	}
	rewind(fp);
	query1=(unsigned int *)malloc(num_query*sizeof(unsigned int));
	query2=(unsigned int *)malloc(num_query*sizeof(unsigned int));
	query3=(unsigned int *)malloc(num_query*sizeof(unsigned int));
	query4=(unsigned int *)malloc(num_query*sizeof(unsigned int));
	query_len=(unsigned int *)malloc(num_query*sizeof(unsigned int));
	clock=(unsigned long long int *)malloc(num_query*sizeof(unsigned long long int));
	num_query=0;
	while(fgets(string,50,fp)!=NULL){
#ifdef DEBUG_MODE
		read_table_ipv6c(string,&ip1,&ip2,&ip3,&ip4,&len,&nexthop);
#else
		read_query_ipv6c(string,&ip1,&ip2,&ip3,&ip4);
#endif
		query1[num_query]=ip1;
		query2[num_query]=ip2;
		query3[num_query]=ip3;
		query4[num_query]=ip4;
		query_len[num_query]=len;
		clock[num_query++]=10000000;
	}
	fclose(fp);
}
////////////////////////////////////////////////////////////////////////////////////
void create(){
	int i;
	root=create_node();
	begin=rdtsc();
	for(i=0;i<num_entry;i++)
		add_node(table[i].ip1,table[i].ip2, table[i].ip3, table[i].ip4,table[i].len,table[i].port);
	end=rdtsc();
}
////////////////////////////////////////////////////////////////////////////////////
void count_node(btrie r){
	if(r==NULL)
		return;
	count_node(r->left);
	N++;
	count_node(r->right);
}
////////////////////////////////////////////////////////////////////////////////////
int main(int argc,char *argv[])
{
	int i,j;
	unsigned int binary_trie_node_count;
	double ms;

	set_query(argv[2]);
	set_table(argv[1]);
	create();

	for(j=0;j<100;j++)
	{
		for(i=0;i<num_query;i++)
		{
			begin=rdtsc();
			ipv6_binary_trie_search(query1[i], query2[i], query3[i], query4[i]);
			end=rdtsc();
			if(clock[i]>(end-begin))
				clock[i]=(end-begin);
		}
	}
	total=0;
	for(j=0;j<num_query;j++)
		total+=clock[j];
	ms=(total/num_query);
	printf("%.0f\n",ms);

	return 0;
}
