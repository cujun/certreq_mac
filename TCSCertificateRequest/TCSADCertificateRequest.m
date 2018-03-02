//
//  TCSADCertificateRequest.m
//  TCSCertificateRequest
//
//  Created by Tim Perfitt on 2/27/18.
//  Copyright © 2018 Twocanoes Software. All rights reserved.
//

#import "TCSADCertificateRequest.h"
#import "ms-icp.h"
#import "dce/dcethread.h"
#import "TCSecurity.h"
#import "TCSCStringUtilities.h"
#import "CertificateSigningRequest.h"
#import "TCSCertificateRequest.h"
#define CR_DISP_ISSUED 0x00000003
#define CR_DISP_UNDER_SUBMISSION 0x00000005



@interface TCSADCertificateRequest()
@property (strong) NSString *certificateAuthorityDNSName;
@property (strong) NSString *certificateAuthorityName;
@property (strong) NSString *certificateTemplate;
@property (nonatomic, strong) NSData *certificate;

@end
@implementation TCSADCertificateRequest
- (instancetype)initWithServerName:(NSString *)serverName certificateAuthorityName:(NSString *)certificateAuthorityName certificateTemplate:(NSString *)certificateTemplate verbose:(BOOL)isVerbose error:(NSError **)error
{
    self = [super init];
    if (self) {
        self.certificateAuthorityDNSName=serverName;
        self.certificateAuthorityName=certificateAuthorityName;
        self.certificateTemplate=certificateTemplate;
        
    }
    return self;
}
-(void)submitRequestToActiveDirectoryWithCSR:(NSData *)inCSR error:(NSError **)error{
    const char *servername=[self.certificateAuthorityDNSName UTF8String];
    const char *ca_name=[self.certificateAuthorityName UTF8String];
    const char *cert_template=[self.certificateTemplate UTF8String];
    bool verbose=false;
    
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
        *error=[NSError errorWithDomain:@"TCS" code:-1 userInfo:@{@"Error":@"Could not initiate connection. Please verify you can reach the KDC and that you have a kerberos ticket."}];
        
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
    
    
//    SecKeyRef privateKeyRef=[TCSecurity generatePrivateKeyWithIdentifer:@"TCSCertficateSigningRequest"];
//    NSData *publicKey=[TCSecurity generatePublicKeyFromPrivateKey:privateKeyRef];
//
//    CertificateSigningRequest *request=[[CertificateSigningRequest alloc] initWithPublicKey:publicKey commonName:@"None"];
//
//    NSData *msgToSign=[request messageToSign];
//
//    NSData *signature=[TCSecurity signBytes:msgToSign withPrivateKey:privateKeyRef];
//
//    request.signatureData=signature;
//
//    NSData *csr=[request certificateSigningRequest];
//
    
    
    pctbRequest.pb=(unsigned char *)[inCSR bytes];
    pctbRequest.cb=(unsigned int)inCSR.length;
    
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
        NSLog(@"Request ID is %i",pdwRequestId);
        if (outstatus!=0) {
            
            printf("ERROR: CertServerRequest %i\n",outstatus);
            return ;
        }
        if (pdwDisposition==CR_DISP_ISSUED) fprintf(stderr,"Certificate issued.\n");
        else if (pdwDisposition==CR_DISP_UNDER_SUBMISSION) printf("Certificate submitted\n");
        else  fprintf(stderr,"Certificate request error\n");
        
    }
    DCETHREAD_CATCH_ALL(thread_exc){
        *error=[NSError errorWithDomain:@"TCS" code:-1 userInfo:@{@"Error":[NSString stringWithFormat:@"Verify that you have a kerberos ticket and that the service principal name of \"%s\" is correct.",server_princ_name]}];

        return ;
        
    }
    DCETHREAD_ENDTRY
    
    if (verbose) fprintf(stderr,"freeing principal name\n");
    
    free (server_princ_name);
    
    if (pdwRequestId>0) {
        //        FILE *outfile=fopen(out_file_path,"w");
        
        if (pctbEncodedCert.cb==0) {
        
            *error=[NSError errorWithDomain:@"TCS" code:-1 userInfo:@{@"Error":[NSString stringWithFormat:@"Certificate request failed. Check Failed Requests with request ID %i in the Certificate Authority.",pdwRequestId]}];
            
            
                
            
            return;
            
        }
        SecCertificateRef cert;
        CFDataRef cert_data=CFDataCreate(NULL, pctbEncodedCert.pb, pctbEncodedCert.cb);
        
        if (verbose) fprintf(stderr,"Creating certificate reference\n");
        
        cert = SecCertificateCreateWithData(NULL, (CFDataRef) cert_data);
        
        self.certificate=(NSData *)CFBridgingRelease(cert_data);
        [TCSecurity installCertificateToKeychain:CFBridgingRelease(cert_data) error:nil];
    }
}

@end
