//
//  main.c
//  
//
//

#include "dce/dcethread.h"
#import "ms-icp.h"
#import <CoreFoundation/CoreFoundation.h>
#include "TCSCertificateSigningRequest.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CoreServices/CoreServices.h>
#include <pwd.h>

#define CR_DISP_ISSUED 0x00000003
#define CR_DISP_UNDER_SUBMISSION 0x00000005


void usage(void);
void c_to_utf16(char *in,char *out,int *outlength) ;

int main (int argc, char * argv[])
{
    char cert[2048];
    unsigned int bytes_read;
    char *servername=NULL;
    char *csr_path=NULL;
    char *ca_name=NULL;
    char *cert_template=NULL;
    char *cert_label=NULL;
    char *cert_cn=NULL;
    char *keychain_path=NULL;
    bool verbose=false;
    int ch;
    

//    if (argc<10) {
//        usage();
//        return -1;
//    }
    while ((ch = getopt(argc, argv, "k:g:n:r:s:c:w:t:v")) != -1) {
        switch (ch) {
            case 'r':
                csr_path=optarg;
                break;
            case 'k':
                keychain_path=optarg;
                break;
            case 's':
                servername=optarg;
                break;
            case 'c':
                ca_name=optarg;
                break;
            case 't':
                cert_template=optarg;
                break;
            case 'g':
                cert_cn=optarg;
                break;
            case 'n':
                cert_label=optarg;
                break;
            case 'v':
                verbose=true;
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
    if (((csr_path==NULL)&&(cert_cn==NULL)) || servername==NULL || ca_name==NULL||cert_template==NULL ) {
        usage();
        return -1;
    }
    
   

    if (cert_cn) {
        if (!cert_label) {
            fprintf(stderr, "Please provide a label\n");
            return -1;
        }
        if (verbose) fprintf(stderr,"Generating CSR\n");
        int res=generate_csr(cert, &bytes_read,cert_label, keychain_path,algorithm_type_RSA, key_size_2048, key_usage_signing_encrypting, algorithm_sha1, cert_label, cert_cn, "", "", "", "", "");
        
        if (res) {
            fprintf(stderr,"Error generating certificate\n");
            return -1;
        }
    }
    
    else {
        if (verbose) fprintf(stderr,"Loading CSR from %s\n",csr_path);

        FILE * cert_file=fopen(csr_path,"r");
        
        if (cert_file==NULL){
            printf("Could not open file %s\n",csr_path);
            return -1;
        }

        bytes_read=(unsigned int)fread(cert, 1, 2048,cert_file);
        
        fclose(cert_file);
    }
    
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
    if (verbose) fprintf(stderr,"rpc_binding_from_string_binding\n");

    rpc_binding_from_string_binding((unsigned char *)partial_string_binding,
                                    &binding_handle,
                                    &status);

    if (status!=0) {
        printf("Could not create RPC binding.  Status is %x\n",status);
        return -1;
        
    }
    unsigned_char_t *server_princ_name=malloc(1024);
    snprintf((char *)server_princ_name,1024,"host/%s",servername);
    if (verbose) fprintf(stderr,"rpc_ep_resolve_binding\n");

    rpc_ep_resolve_binding(binding_handle,
                           ICertPassage_v0_0_c_ifspec,
                           &status);
    
    if (verbose) fprintf(stderr,"rpc_binding_set_auth_info");

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
   
    
    pctbRequest.pb=(unsigned char *)cert;
    pctbRequest.cb=bytes_read;
    
    int attribute_string_len;
    char *c_attributes=calloc(1024,1);
    sprintf(c_attributes, "CertificateTemplate:%s",cert_template);
    char *attributes=calloc(2048,1);
    
    c_to_utf16(c_attributes,attributes,&attribute_string_len);
    

    pctbAttribs.pb=(unsigned char *)attributes;

    pctbAttribs.cb=attribute_string_len+2;

    if (verbose) fprintf(stderr,"requesting certificate\n");

  
    DCETHREAD_TRY {
        DWORD outstatus=CertServerRequest(binding_handle,dwFlags,(unsigned short *)pwszAuthority,&pdwRequestId,&pdwDisposition,&pctbAttribs,&pctbRequest,&pctbCert,&pctbEncodedCert,&pctbDispositionMessage);
        
        if (outstatus!=0) {
            
            printf("ERROR: CertServerRequest %i\n",outstatus);
            return -1;
        }
        if (pdwDisposition==CR_DISP_ISSUED) fprintf(stderr,"Certificate issued.\n");
        else if (pdwDisposition==CR_DISP_UNDER_SUBMISSION) printf("Certificate submitted\n");
        else  fprintf(stderr,"Certificate request error\n");

    }
    DCETHREAD_CATCH_ALL(thread_exc){
        printf("ERROR: CertServerRequest\nVerify that you have a kerberos ticket and that the service principal name of \"%s\" is correct\n",server_princ_name);
        return -1;

    }
    DCETHREAD_ENDTRY

    if (verbose) fprintf(stderr,"freeing principal name\n");

    free (server_princ_name);
        
    if (pdwRequestId>0) {
//        FILE *outfile=fopen(out_file_path,"w");

        if (pctbEncodedCert.cb==0) {
            fprintf(stderr,"Failed.  Check Failed Requests with request ID %i in the CA for the reason why\n",pdwRequestId);


        }
        CFStringRef keys[3];
        CFStringRef values[3];
        CFDictionaryRef aDict;
        SecCertificateRef cert;
        CFDataRef cert_data=CFDataCreate(NULL, pctbEncodedCert.pb, pctbEncodedCert.cb);
        
        if (verbose) fprintf(stderr,"Creating certificate reference\n");

        cert = SecCertificateCreateWithData(NULL, (CFDataRef) cert_data);
        SecKeychainRef keychain_ref;
        
        
        if (!keychain_path) {
            struct passwd *pw = getpwuid(getuid());
            assert(pw);

            keychain_path=malloc(PATH_MAX);
            sprintf(keychain_path,"%s/Library/Keychains/login.keychain",pw->pw_dir);
        }
        if (verbose) fprintf(stderr,"Opening keychain %s\n",keychain_path);

        SecKeychainOpen(keychain_path, &keychain_ref);

        
        keys[0] = kSecValueRef;
        keys[1] = kSecClass;
        keys[2]=kSecUseKeychain;
        values[0] = (CFStringRef) cert;
        values[1] = kSecClassCertificate;
        values[2]=(CFStringRef)keychain_ref;

        aDict=CFDictionaryCreate(NULL, (const void **)keys, (const void **)values, 3, &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        OSStatus status =SecItemAdd(aDict,NULL );
        if (status != errSecSuccess) {
            // Handle the error
        }

//        int i;
//
//        for (i=0;i<pctbEncodedCert.cb;i++){
//            fputc(pctbEncodedCert.pb[i], outfile);
//        }
//        fclose (outfile);

        fprintf(stderr,"Certificate saved to keychain\n");

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
    printf("tcscertrequest -r <csr path> -s <server dns name> -c <name of ca> [-k <path_to_keychain>] -t <template name>\n");
    printf("\ntcscertrequest is a command line tool to send a certificate request via RPCs to a Microsoft certificate authority.\n\n");
    printf("Options:\n");
    printf("    -r <csr path>           Path to certificate signing request in binary (DER) format. Can use \"openssl req -nodes -newkey rsa:2048 -keyout domain.key -out domain.csr -subj '/CN=computername' -outform der\" command to generate.\n");
    printf("    -g   <Common Name>      Generate CSR with Common Name. Certificate will be generated with RSA 2048 bits SHA512 \n");
    printf("    -n   <label>      Label in keychain for imported identity\n");

    printf("    -s <server path>        CA Server DNS name.\n");
    printf("    -c <name of ca>         Name of the certificate authority.  This is not the server name but the name used in the Common Name of the issuing authority.\n");
    printf("    -k <path to keychain>   keychain to store certificate and private key. Stores in user keychain if not specified.\n");
    printf("    -t <template name>      Name of the template to use when signing the certificate. Common template names include User or Machine.\n");
    printf("    -v                      Verbose output\n");

}

