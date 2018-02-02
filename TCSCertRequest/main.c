//
//  main.c
//  
//
//

#include "dce/dcethread.h"
#import "ms-icp.h"
#import <CoreFoundation/CoreFoundation.h>

#define CR_DISP_ISSUED 0x00000003
#define CR_DISP_UNDER_SUBMISSION 0x00000005


void usage(void);
void c_to_utf16(char *in,char *out,int *outlength) ;

int main (int argc, char * argv[])
{
   
    unsigned char cert[2048];
    unsigned int bytes_read;
    char *servername=NULL;
    char *csr_path=NULL;
    char *ca_name=NULL;
    char *out_file_path=NULL;
    char *cert_template=NULL;
    int ch;
    

    if (argc<10) {
        usage();
        return -1;
    }
    while ((ch = getopt(argc, argv, "r:s:c:w:t:")) != -1) {
        switch (ch) {
            case 'r':
                csr_path=optarg;
                break;
            case 's':
                servername=optarg;
                break;
            case 'c':
                ca_name=optarg;
                break;
            case 'w':
                out_file_path=optarg;
                break;
            case 't':
                cert_template=optarg;
                break;
                
            case '?':
            default:
                usage();
                return -1;
                break;
        }
    }
    argc -= optind;
    argv += optind;    

    if (csr_path==NULL || servername==NULL || ca_name==NULL|| out_file_path==NULL||cert_template==NULL ) {
        usage();
        return -1;
    }
    FILE * cert_file=fopen(csr_path,"r");
    
    if (cert_file==NULL){
        printf("Could not open file %s\n",csr_path);
        return -1;
    }

    bytes_read=(unsigned int)fread(cert, 1, 2048,cert_file);
    
    fclose(cert_file);
    
    CERTTRANSBLOB pctbCert;
    CERTTRANSBLOB pctbEncodedCert;
    CERTTRANSBLOB pctbDispositionMessage;

    DWORD pdwDisposition;
    CERTTRANSBLOB pctbAttribs;
    CERTTRANSBLOB pctbRequest;
    DWORD pdwRequestId;
    
    const char * protocol_family;
    char partial_string_binding[128];
    error_status_t status;
    unsigned32 authn_protocol = rpc_c_authn_gss_mskrb;
    unsigned32 authn_level = rpc_c_protect_level_pkt_privacy;
    rpc_binding_handle_t binding_handle;

    protocol_family = "ncacn_ip_tcp";
    
    sprintf(partial_string_binding, "%s:%s[]",
            protocol_family,
            servername);
    
    rpc_binding_from_string_binding((unsigned char *)partial_string_binding,
                                    &binding_handle,
                                    &status);

    if (status!=0) {
        printf("Could not create RPC binding.  Status is %x\n",status);
        return -1;
        
    }
    unsigned_char_t *server_princ_name=malloc(1024);
    snprintf((char *)server_princ_name,1024,"host/%s",servername);
    
    rpc_ep_resolve_binding(binding_handle,
                           ICertPassage_v0_0_c_ifspec,
                           &status);
    
    
    rpc_binding_set_auth_info(binding_handle,
                              (unsigned_char_p_t)server_princ_name,
                              authn_level,
                              authn_protocol,
                              NULL,
                              rpc_c_authz_name,
                              &status);
   
    if (status!=0) {
        printf("Cound not set authentication mechanism.  Error is %x\n",status);
        return -1;
        
    }
        
    DWORD dwFlags=0xFF;
    int outlength;
    char *pwszAuthority=calloc(1024,1);
    c_to_utf16(ca_name,(char *)pwszAuthority,&outlength);
   
    
    pctbRequest.pb=cert;
    pctbRequest.cb=bytes_read;
    
    int attribute_string_len;
    char *c_attributes=calloc(1024,1);
    sprintf(c_attributes, "CertificateTemplate:%s",cert_template);
    char *attributes=calloc(2048,1);
    
    c_to_utf16(c_attributes,attributes,&attribute_string_len);
    

    pctbAttribs.pb=(unsigned char *)attributes;

    pctbAttribs.cb=attribute_string_len+2;

    
  
    DCETHREAD_TRY {
        DWORD outstatus=CertServerRequest(binding_handle,dwFlags,(unsigned short *)pwszAuthority,&pdwRequestId,&pdwDisposition,&pctbAttribs,&pctbRequest,&pctbCert,&pctbEncodedCert,&pctbDispositionMessage);
        
        if (outstatus!=0) {
            
            printf("ERROR: CertServerRequest %i\n",outstatus);
            return -1;
        }
        if (pdwDisposition==CR_DISP_ISSUED) printf("Certificate issued.\n");
        else if (pdwDisposition==CR_DISP_UNDER_SUBMISSION) printf("Certificate submitted\n");
        else  printf("Certificate request error\n");

    }
    DCETHREAD_CATCH_ALL(thread_exc){
        printf("ERROR: CertServerRequest\nVerify that you have a kerberos ticket and that the service principal name of \"%s\" is correct\n",server_princ_name);
        return -1;

    }
    DCETHREAD_ENDTRY

    free (server_princ_name);
        
    if (pdwRequestId>0) {
        FILE *outfile=fopen(out_file_path,"w");

        if (pctbEncodedCert.cb==0) {
            printf("Failed.  Check Failed Requests with request ID %i in the CA for the reason why\n",pdwRequestId);


        }
        int i;

        for (i=0;i<pctbEncodedCert.cb;i++){
            fputc(pctbEncodedCert.pb[i], outfile);
        }
        fclose (outfile);

        printf("Certificate saved to %s. \n",out_file_path);

    }
    else {
        printf("Failed.  Check Failed Requests in the CA for the reason why.\n");
        
    }
    
    return 0;
}



void c_to_utf16(char *in,char *out,int *outlength) {
    CFStringRef cfstring=CFStringCreateWithCString (
                                                    NULL,
                                                    in,
                                                    kCFStringEncodingASCII
                                                    );
    
    CFDataRef string_data=CFStringCreateExternalRepresentation (
                                                                NULL,
                                                                cfstring,
                                                                kCFStringEncodingUTF16LE,
                                                                '?'
                                                                );
    
    
    CFDataGetBytes ( string_data,
                    CFRangeMake(0,CFDataGetLength(string_data)),
                    (unsigned char *)out
                    );
    

 
    
    *outlength=(int)CFDataGetLength(string_data);
    CFRelease(string_data);
    CFRelease(cfstring);
    
}

void usage(void) {
    printf("tcscertrequest -r <csr path> -s <server dns name> -c <name of ca> -w <output file path> -t <template name>\n");
    printf("\ntcscertrequest is a command line tool to send a certificate request via RPCs to a Microsoft certificate authority.\n\n");
    printf("Options:\n");
    printf("    -r <csr path>           Path to certificate signing request in binary (DER) format. Can use \"openssl req -nodes -newkey rsa:2048 -keyout domain.key -out domain.csr -subj '/CN=computername' -outform der\" command to generate.\n");
    printf("    -s <server path>        CA Server DNS name.\n");
    printf("    -c <name of ca>         Name of the certificate authority.  This is not the server name but the name used in the Common Name of the issuing authority.\n");
    printf("    -w <output file path>   Signed certificate will be written to <output file path> in DER format.\n");
    printf("    -t <template name>      Name of the template to use when signing the certificate. Common template names include User or Machine.\n");


}

