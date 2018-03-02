//
//  main.c
//
//
//

#import <Foundation/Foundation.h>
#import <CoreServices/CoreServices.h>
#import <TCSCertificateRequest/TCSCertificateRequest.h>
#import "TCSCertAppHelper.h"
#import "dce/dcethread.h"
#import "ms-icp.h"

#import <Security/Security.h>
#import <pwd.h>
#define CR_DISP_ISSUED 0x00000003
#define CR_DISP_UNDER_SUBMISSION 0x00000005


void usage(void);
void c_to_utf16(char *in,char *out,int *outlength) ;

int main(int argc,  char * argv[]) {
    @autoreleasepool {
        
        
        char *servername=NULL;
        char *csr_path=NULL;
        char *ca_name=NULL;
        char *cert_template=NULL;
        char *cert_label=NULL;
        char *cert_cn=NULL;
        char *keychain_path=NULL;
        bool verbose=false;
        char *yubikeyslot=NULL;
        char *yubikeymanagementkey=NULL;
        int ch;
        bool use_yubikey=false;
        
        
        while ((ch = getopt(argc, argv, "yl:m:k:g:n:r:s:c:w:t:v")) != -1) {
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
                case 'y':
                    use_yubikey=true;
                    break;
                case 'l':
                    yubikeyslot=optarg;
                    break;
                case 'm':
                    yubikeymanagementkey=optarg;
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
        if ((use_yubikey==true) && (!yubikeymanagementkey || !yubikeyslot)) {
            
            fprintf(stderr, "You must specify a management key and slot with the yubikey option.\n");
            return -1;
        }

        if (servername==NULL || ca_name==NULL||cert_template==NULL ) {
            usage();
            return -1;
        }
        
        NSData *csr=nil;
        NSError *error;

        if (cert_cn==NULL) cert_cn="TCSCertRequest";
        NSString *serverNameString=[NSString stringWithUTF8String:servername];
        NSString *certAuthNameString=[NSString stringWithUTF8String:ca_name];
        NSString *templateString=[NSString stringWithUTF8String:cert_template];
        NSString *commonName=[NSString stringWithUTF8String:cert_cn];

        if (use_yubikey==true) {
            NSString *yubikeyManagementKey=[NSString stringWithUTF8String:yubikeymanagementkey];
             NSString *yubikeyManagementSlot=[NSString stringWithUTF8String:yubikeyslot];
            csr=[TCSCertAppHelper generateCSRFromYubikeyWithManagementKey:yubikeyManagementKey inSlot:yubikeyManagementSlot commonName:commonName error:&error];
        }
        else {
            csr=[TCSCertAppHelper generateCSRFromKeychainWithCommonName:commonName error:&error];
        }
        if (!csr) {
            fprintf(stderr,"Could not not generate CSR");
            return -1;
        }
        
        
        TCSADCertificateRequest *request=[[TCSADCertificateRequest alloc] initWithServerName:serverNameString certificateAuthorityName:certAuthNameString certificateTemplate:templateString verbose:NO error:nil];
        
        NSError *err;
        [request submitRequestToActiveDirectoryWithCSR:csr error:&err];
        if (err) {
            fprintf(stderr, "%s\n", [[err.userInfo objectForKey:@"Error"] UTF8String]);
            
            return -1;
        }

        
        
        
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
    printf("tcscertrequest  -s <server dns name> -c <name of ca> -t <template name> [-r <csr path>] [-k <path_to_keychain>] [-y] [-m <yubikey_management_key] [-s <yubikey slot]\n");
    printf("\ntcscertrequest is a command line tool to send a certificate request via RPCs to a Microsoft certificate authority.\n\n");
    printf("Options:\n");
    printf("    -r <csr path>           Path to certificate signing request in binary (DER) format. Can use \"openssl req -nodes -newkey rsa:2048 -keyout domain.key -out domain.csr -subj '/CN=computername' -outform der\" command to generate.\n");
    printf("    -g <Common Name>        Generate CSR with Common Name. Certificate will be generated with RSA 2048 bits SHA512 \n");
    printf("    -n <label>              Label in keychain for imported identity\n");
    
    printf("    -s <server path>        CA Server DNS name.\n");
    printf("    -c <name of ca>         Name of the certificate authority.  This is not the server name but the name used in the Common Name of the issuing authority.\n");
    printf("    -k <path to keychain>   keychain to store certificate and private key. Stores in user keychain if not specified.\n");
    printf("    -y                      generate key in Yubikey.  Requires slot (-l) and management key (-m)\n");
        printf("    -l <Yubikey slot>       Specify yubikey slot. For example, 9a. Requires -y.\n");
        printf("    -m                      Yubikey management key. PIN not supported. Must use full management key. Requires -y.\n");
    printf("    -t <template name>      Name of the template to use when signing the certificate. Common template names include User or Machine.\n");
    printf("    -v                      Verbose output\n");
    
}


