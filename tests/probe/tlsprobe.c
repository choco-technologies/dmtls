/* Hardware interoperability diagnostic. TLS transport callbacks only touch
 * memory. Waiting for the host happens outside the library, never in BIO. */
#include "dmod.h"
#include "dmtls.h"
#include "dmrng.h"
#include "dmosi.h"
#include "dmtty_types.h"
#include <string.h>
#define CAPACITY 32768u
struct transport {unsigned char rx[CAPACITY];size_t rx_pos,rx_size;unsigned char tx[CAPACITY];size_t tx_size;};
static int entropy(void* user, uint8_t* out, size_t size) {(void)user;return dmrng_fill(out,size);}
static dmtls_result_t send_bytes(void* user,const uint8_t* in,size_t size,size_t* sent)
{
    struct transport* t=user;*sent=0;
    size_t n=CAPACITY-t->tx_size;if(n==0)return DMTLS_WANT_WRITE;
    if(n>size)n=size;if(n>257)n=257;
    memcpy(t->tx+t->tx_size,in,n);t->tx_size+=n;*sent=n;return DMTLS_OK;
}
static dmtls_result_t receive_bytes(void* user,uint8_t* out,size_t size,size_t* received)
{
    struct transport* t=user;*received=0;
    size_t n=t->rx_size-t->rx_pos;if(n==0)return DMTLS_WANT_READ;
    if(n>size)n=size;if(n>113)n=113;
    memcpy(out,t->rx+t->rx_pos,n);t->rx_pos+=n;*received=n;return DMTLS_OK;
}
static void flush(struct transport* t)
{
    if(t->tx_size==0)return;
    static const char digits[]="0123456789abcdef";
    Dmod_Printf("TLS_OUT ");
    char line[128];
    for(size_t pos=0;pos<t->tx_size;){
        size_t count=0;
        while(pos<t->tx_size && count<sizeof(line)) {
            line[count++]=digits[t->tx[pos]>>4];line[count++]=digits[t->tx[pos]&15];++pos;
        }
        Dmod_FileWrite(line,1,count,DMOD_STDOUT);
    }
    Dmod_Printf("\n");t->tx_size=0;
}
static int unhex(int c)
{if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;return -1;}
static bool exchange(struct transport* t)
{
    flush(t);Dmod_Printf("TLS_INPUT\n");
    if(t->rx_pos!=0){memmove(t->rx,t->rx+t->rx_pos,t->rx_size-t->rx_pos);t->rx_size-=t->rx_pos;t->rx_pos=0;}
    int ch;do{ch=Dmod_Getc();}while(ch=='\r'||ch=='\n');
    if(ch!='I')return false;
    int high=-1;
    while((ch=Dmod_Getc())!='\n' && ch!='\r' && ch!=DMOD_EOF){
        if(ch==' ')continue;
        int nibble=unhex(ch);if(nibble<0)return false;
        if(high<0)high=nibble;
        else {if(t->rx_size==CAPACITY)return false;t->rx[t->rx_size++]=(unsigned char)((high<<4)|nibble);high=-1;}
    }
    return high<0 && ch!=DMOD_EOF;
}
int main(int argc,char* argv[])
{
    if(argc!=3){Dmod_Printf("Usage: tlsprobe HOSTNAME CA_FILE\n");return 1;}
    Dmod_Printf("TLS_STAGE start\n");
    struct transport* t=Dmod_Malloc(sizeof(*t));
    if(t==NULL)return 1;memset(t,0,sizeof(*t));
    void* file=Dmod_FileOpen(argv[2],"rb");
    if(file==NULL){Dmod_Free(t);return 1;}
    unsigned char ca[4096];size_t size=Dmod_FileRead(ca,1,sizeof(ca),file);Dmod_FileClose(file);
    dmtls_platform_t platform={entropy,NULL,512*1024,1};
    dmtls_config_t config=NULL;dmtls_connection_t connection=NULL;
    Dmod_Printf("TLS_STAGE initialize\n");
    dmtls_result_t rc=dmtls_initialize(&platform);
    Dmod_Printf("TLS_STAGE initialized %d\n",(int)rc);
    bool initialized=rc==DMTLS_OK;
    if(rc==DMTLS_OK)rc=dmtls_config_create(ca,size,&config);
    Dmod_Printf("TLS_STAGE config %d\n",(int)rc);
    dmtls_transport_t bio={send_bytes,receive_bytes,t};
    if(rc==DMTLS_OK)rc=dmtls_connection_create(config,argv[1],&bio,30000,10000,&connection);
    Dmod_Printf("TLS_STAGE connection %d\n",(int)rc);
    uint32_t flags=Dmod_Stdin_GetFlags();
    void* input=Dmod_LockStdio(DMOD_STDIN);
    if(input==NULL || Dmod_Ioctl(input,dmtty_ioctl_cmd_claim_foreground,NULL)!=0)rc=DMTLS_ERR_TRANSPORT;
    Dmod_UnlockStdio(DMOD_STDIN);
    Dmod_Stdin_SetFlags(0);
    if(rc==DMTLS_OK){
        do {rc=dmtls_handshake(connection);if(rc==DMTLS_WANT_READ||rc==DMTLS_WANT_WRITE){if(!exchange(t)){rc=DMTLS_ERR_TRANSPORT;break;}}}
        while(rc==DMTLS_WANT_READ||rc==DMTLS_WANT_WRITE);
    }
    if(rc==DMTLS_OK){
        Dmod_Printf("TLS_OPEN\n");
        static const char message[]="hardware TLS echo";size_t offset=0,n;
        while(rc==DMTLS_OK && offset<sizeof(message)-1){
            rc=dmtls_write(connection,message+offset,sizeof(message)-1-offset,&n);
            if(rc==DMTLS_WANT_READ||rc==DMTLS_WANT_WRITE){if(!exchange(t)){rc=DMTLS_ERR_TRANSPORT;break;}rc=DMTLS_OK;}
            else if(rc==DMTLS_OK)offset+=n;
        }
        flush(t);offset=0;unsigned char reply[sizeof(message)]={0};
        while(rc==DMTLS_OK && offset<sizeof(message)-1){
            rc=dmtls_read(connection,reply+offset,sizeof(message)-1-offset,&n);
            if(rc==DMTLS_WANT_READ||rc==DMTLS_WANT_WRITE){if(!exchange(t)){rc=DMTLS_ERR_TRANSPORT;break;}rc=DMTLS_OK;}
            else if(rc==DMTLS_OK)offset+=n;
        }
        if(rc==DMTLS_OK && memcmp(reply,message,sizeof(message)-1)!=0)rc=DMTLS_ERR_PROTOCOL;
        if(rc==DMTLS_OK){
            Dmod_Printf("TLS_DATA_OK\n");
            do{rc=dmtls_close(connection);if(rc==DMTLS_WANT_READ||rc==DMTLS_WANT_WRITE){if(!exchange(t)){rc=DMTLS_ERR_TRANSPORT;break;}}}
            while(rc==DMTLS_WANT_READ||rc==DMTLS_WANT_WRITE);
        }
    }
    flush(t);dmtls_status_t status={0};
    if(connection!=NULL){dmtls_status(connection,&status);dmtls_connection_destroy(connection);}
    if(config!=NULL)dmtls_config_destroy(config);
    if(initialized)dmtls_shutdown();
    Dmod_Stdin_SetFlags(flags);Dmod_Free(t);
    Dmod_Printf("TLS_DONE result=%d verify=%u\n",(int)rc,(unsigned)status.verification_flags);
    return rc==DMTLS_OK?0:1;
}
