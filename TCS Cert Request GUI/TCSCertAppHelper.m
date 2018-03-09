//
//  TCSCertAppHelper.m
//  TCSCertRequest
//
//  Created by Tim Perfitt on 3/1/18.
//  Copyright © 2018 Twocanoes Software. All rights reserved.
//

#import "TCSCertAppHelper.h"
#import "TCSYubiManager.h"
#import "TCSADCertificateRequest.h"
#import "CertificateSigningRequest.h"
#import "TCSecurity.h"
@implementation TCSCertAppHelper
+(NSData *)generateCSRFromYubikeyWithManagementKey:(NSString *)managementKey inSlot:(NSString *)yubiKeySlot commonName:(NSString *)commonName error:(NSError **)error{
    
    if (!commonName || [commonName isEqualToString:@""]) {
        
        commonName=@"TCSCertificate";
    }
    TCSYubiManager *ym=[TCSYubiManager sharedManager];
    [ym authenticateWithManagementKey:
     managementKey];
    NSData *publicKey=[ym generateKeyInSlot:yubiKeySlot];
    if (!publicKey) {
        fprintf(stderr,"public key not generated!\n");
        return nil;
    }
    
    
    CertificateSigningRequest *signingRequest=[[CertificateSigningRequest alloc] initWithPublicKey:publicKey commonName:@"test"];
    
    NSData *dataToSign=[signingRequest messageToSign];
    if (!dataToSign) {
        NSLog(@"could not get message to sign");
        return nil;
    }
    NSData *signatureData=[[TCSYubiManager  sharedManager] signBytes:dataToSign withYubiKeySlot:yubiKeySlot];
    
    if (!signatureData) {
        NSLog(@"could not get signature data");
        return nil;
    }
    signingRequest.signatureData=signatureData;
    
    NSData *csr=[signingRequest certificateSigningRequest];
    
    return csr;
    
}
+(NSData *)generateCSRFromKeychainWithCommonName:(NSString *)commonName error:(NSError **)error{

    if (!commonName || [commonName isEqualToString:@""]) {
        
        commonName=@"TCSCertificate";
    }
    SecKeyRef privateKeyRef=[TCSecurity generatePrivateKeyWithIdentifer:@"TCSCertficateSigningRequest"];
    NSData *publicKey=[TCSecurity generatePublicKeyFromPrivateKey:privateKeyRef];
    
    
    CertificateSigningRequest *signingRequest=[[CertificateSigningRequest alloc] initWithPublicKey:publicKey commonName:@"test"];
    
    NSData *dataToSign=[signingRequest messageToSign];
    if (!dataToSign) {
        NSLog(@"could not get message to sign");
        return nil;
    }
    
    NSData *signatureData=[TCSecurity signBytes:dataToSign withPrivateKey:privateKeyRef];
    
    if (!signatureData) {
        NSLog(@"could not get signature data");
        return nil;
    }
    signingRequest.signatureData=signatureData;
    
    NSData *csr=[signingRequest certificateSigningRequest];
    
    return csr;
    
}
+(int)installSignedCertificate:(NSData *)inCert ToYubikeySlot:(NSString *)inSlot error:(NSError **)error{
    TCSYubiManager *ym=[TCSYubiManager sharedManager];
    if([ym installCertificate:inCert intoSlot:inSlot]==YES) return 0;
    return -1;
}
@end
