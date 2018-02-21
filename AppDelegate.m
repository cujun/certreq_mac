//
//  AppDelegate.m
//  TCS Cert Request
//
//  Created by Tim Perfitt on 2/16/18.
//

#import "AppDelegate.h"
#import "dce/dcethread.h"
#import "ms-icp.h"

#import <Security/Security.h>
#import <pwd.h>
#import <TCSCertificateRequest/TCSCertificateRequest.h>

#define CR_DISP_ISSUED 0x00000003
#define CR_DISP_UNDER_SUBMISSION 0x00000005

@interface AppDelegate ()

@property (weak) IBOutlet NSWindow *window;
@property (strong) NSString *certificateAuthorityDNSName;
@property (strong) NSString *certificateAuthorityName;
@property (strong) NSString *certificateTemplate;

@end

@implementation AppDelegate
- (IBAction)requestCertificate:(id)sender {
    //-n macpower.twocanoes.com -g tperfitt -s win-fgivt3j3gi9.twocanoes.com -c tcsca  -t Machine
    
    //    char cert[2048];
    //    unsigned int bytes_read;
    const char *servername=[self.certificateAuthorityDNSName UTF8String];
    //    char *csr_path=NULL;
    const char *ca_name=[self.certificateAuthorityName UTF8String];
    const char *cert_template=[self.certificateTemplate UTF8String];
    //    char *cert_label="macpower.twocanoes.com";
    char *keychain_path=NULL;
    bool verbose=true;
    //    int ch;
    
    
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
        [self showErrorWithMessage:[NSString stringWithFormat:@"Could not initiate connection. Please verify you can reach the KDC and that you have a kerberos ticket.  Status is %x.\n",status]];
        printf("Could not initiate connection. Please verify you can reach the KDC and that you have a kerberos ticket.  Status is %x.\n",status);
        return;
        
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
        return;
        
    }
    
    DWORD dwFlags=0xFF;
    int outlength;
    char *pwszAuthority=calloc(1024,1);
    c_to_utf16((char*)ca_name,(char *)pwszAuthority,&outlength);
    
    
    SecKeyRef privateKeyRef=[TCSecurity generatePrivateKeyWithIdentifer:@"TCSCertficateSigningRequest"];
    NSData *publicKey=[TCSecurity generatePublicKeyFromPrivateKey:privateKeyRef];
    NSData *csr=[CertificateSigningRequest createCertificateSigningRequestWithCommonName:@"test" publicKey:publicKey privateKey:privateKeyRef];
    
    
    
    pctbRequest.pb=(unsigned char *)[csr bytes];
    pctbRequest.cb=(unsigned int)csr.length;
    
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
            return ;
        }
        if (pdwDisposition==CR_DISP_ISSUED) fprintf(stderr,"Certificate issued.\n");
        else if (pdwDisposition==CR_DISP_UNDER_SUBMISSION) printf("Certificate submitted\n");
        else  fprintf(stderr,"Certificate request error\n");
        
    }
    DCETHREAD_CATCH_ALL(thread_exc){
        printf("ERROR: CertServerRequest\nVerify that you have a kerberos ticket and that the service principal name of \"%s\" is correct\n",server_princ_name);
        
        [self showErrorWithMessage:[NSString stringWithFormat:@"Verify that you have a kerberos ticket and that the service principal name of \"%s\" is correct.",server_princ_name]];

        return ;
        
    }
    DCETHREAD_ENDTRY
    
    if (verbose) fprintf(stderr,"freeing principal name\n");
    
    free (server_princ_name);
    
    if (pdwRequestId>0) {
        //        FILE *outfile=fopen(out_file_path,"w");
        
        if (pctbEncodedCert.cb==0) {
            fprintf(stderr,"Failed.  Check Failed Requests with request ID %i in the CA for the reason why\n",pdwRequestId);
            
             [self showErrorWithMessage:[NSString stringWithFormat:@"Certificate request failed. Check Failed Requests with request ID %i in the Certificate Authority.",pdwRequestId]];
            

            return;
            
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
        
        NSAlert *alert = [[NSAlert alloc] init];
        [alert addButtonWithTitle:@"OK"];
    
        [alert setMessageText:@"Certificate Request Succeeded"];
        [alert setInformativeText:@"Certificate saved to keychain."];
        [alert runModal];

        
        
    }
    else {

        [self showErrorWithMessage:@"Certificate request failed. Please verify that you have a kerberos ticket, can contact the certificate authority, and that you enter the information correctly."];
    }

}

-(void)showErrorWithMessage:(NSString *)message{
    NSAlert *alert = [[NSAlert alloc] init];
    [alert addButtonWithTitle:@"OK"];
    
    [alert setMessageText:@"Certificate Request Failed"];
    [alert setInformativeText:message];
    [alert setAlertStyle:NSAlertStyleWarning];
    [alert runModal];

}
- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
//    self.certificateAuthorityDNSName=@"win-fgivt3j3gi9.twocanoes.com";
//    self.certificateAuthorityName=@"tcsca";
//    self.certificateTemplate=@"User";

    
}


- (void)applicationWillTerminate:(NSNotification *)aNotification {
    // Insert code here to tear down your application
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

@end
