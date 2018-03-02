//
//  CertificateSigningRequest.m
//  TCSCertificateRequest
//
//  Created by Tim Perfitt on 2/14/18.
//  Copyright © 2018 Twocanoes Software. All rights reserved.
//

#
#import "TCSCertificateRequest/CertificateSigningRequest.h"
#import <CommonCrypto/CommonCryptor.h>
#import "DER.h"
#import "ASN1Primative.h"
#import "ykpiv.h"
#import "ykpiv-version.h"
#import "TCSecurity.h"
#import "TCSYubiManager.h"
#include <CommonCrypto/CommonDigest.h>
#import "ASN1Utilities.h"
#define ENCRYPTED_CONTENT_INFO @"0.2"
#define VERSION @"0.0"
#define RECIPIENTINFOS @"0.1"

@interface CertificateSigningRequest()
@property (nonatomic,strong) ASN1Composite *signingRequest;
@property (nonatomic,strong) NSData *publicKey;
@property (nonatomic, strong) NSString *commonName;

@end
@implementation CertificateSigningRequest

- (instancetype)initWithPublicKey:(NSData *)inPublicKey commonName:(NSString *)inCommonName{
    self = [super init];
    if (self) {
        self.publicKey=inPublicKey;
        self.commonName=inCommonName;
    }
    return self;
}

-(NSData *)messageToSign{
    ASN1Composite *certReqMsg=[self asn1DataToSign];
    
    NSData *toSign=[ASN1Utilities encodeASN1:certReqMsg useINF:NO];
    
    return toSign;
    
}
-(NSData *)certificateSigningRequest{
    if (!self.signatureData) {
        NSLog(@"you must set a signature first!");
        return nil;
    }
    if (!self.publicKey) {
        NSLog(@"you must set a public key!");
        
        return nil;
    }

    ASN1Composite *certificateSigningRequest=[self unSignedCertificate];
    
    
    ASN1Composite *signatureAlgorithmComposite=[ASN1Composite asn1Composite];
    [signatureAlgorithmComposite setClass:ASN1_CLASS_UNIVERSAL type:ASN1_TYPE_SEQUENCE category:ASN1_CATEGORY_COMPOSITE];
    
    [certificateSigningRequest addObject:signatureAlgorithmComposite];
    
    //1.2.840.113549.1.1.5
    ASN1Primative *signatureAlgorithms=[ASN1Primative asn1PrimativeWithOID:@"1.2.840.113549.1.1.13"]; //11 for sha256 //1.2.840.113549.1.1.13
    //1.2.840.113549.1.1.5
    [signatureAlgorithmComposite addObject:signatureAlgorithms];
    ASN1Primative *nullPrimative=[ASN1Primative asn1PrimativeWithNull];
    
    [signatureAlgorithmComposite addObject:nullPrimative];
    
    ASN1Primative *signature=[ASN1Primative asn1PrimativeWithBitString:self.signatureData];
    
    [certificateSigningRequest addObject:signature];

    return [ASN1Utilities encodeASN1:certificateSigningRequest useINF:NO];


    

}
-(ASN1Composite *)asn1DataToSign{
    
    ASN1Composite *certificationRequestInfo=[ASN1Composite asn1Composite];
    [certificationRequestInfo setClass:ASN1_CLASS_UNIVERSAL type:ASN1_TYPE_SEQUENCE category:ASN1_CATEGORY_COMPOSITE];
    
    char zero=0x00;
    ASN1Primative *certReqId=[ASN1Primative asn1PrimativeWithInteger:[NSData dataWithBytes:&zero length:1]];
    
    [certificationRequestInfo addObject:certReqId];
    
    ASN1Composite *certRequestSubject=[ASN1Composite asn1Composite];
    [certRequestSubject setClass:ASN1_CLASS_UNIVERSAL type:ASN1_TYPE_SEQUENCE category:ASN1_CATEGORY_COMPOSITE];
    [certificationRequestInfo addObject:certRequestSubject];
    
    ASN1Composite *certSubjectSet=[ASN1Composite asn1Composite];
    [certSubjectSet setClass:ASN1_CLASS_UNIVERSAL type:ASN1_TYPE_SET category:ASN1_CATEGORY_COMPOSITE];
    [certRequestSubject addObject:certSubjectSet];
    
    ASN1Composite *commonNameSequence=[ASN1Composite asn1Composite];
    [commonNameSequence setClass:ASN1_CLASS_UNIVERSAL type:ASN1_TYPE_SEQUENCE category:ASN1_CATEGORY_COMPOSITE];
    [certSubjectSet addObject:commonNameSequence];
    
    ASN1Primative *commonNamePrimativeKey=[ASN1Primative asn1PrimativeWithOID:@"2.5.4.3"];
    [commonNameSequence addObject:commonNamePrimativeKey];
    
    ASN1Primative *commonNamePrimativeValue=[ASN1Primative asn1PrimativeWithUTF8String:self.commonName];
    [commonNameSequence addObject:commonNamePrimativeValue];
    ASN1Primative *publicKeyData;
    publicKeyData=[ASN1Primative asn1PrimativeWithData:self.publicKey];
    
    [certificationRequestInfo addObject:publicKeyData];
    
    ASN1Composite *contextComposite=[ASN1Composite asn1Composite];
    [contextComposite setClass:ASN1_CLASS_CONTENT_SPECIFIC type:0 category:ASN1_CATEGORY_COMPOSITE];
    
    [certificationRequestInfo addObject:contextComposite];
    return certificationRequestInfo;

    
}
-(ASN1Composite *)unSignedCertificate{
    ASN1Composite *certificationRequestInfo=[self asn1DataToSign];
    ASN1Composite *certReqMsg=[ASN1Composite asn1Composite];
    [certReqMsg setClass:ASN1_CLASS_UNIVERSAL type:ASN1_TYPE_SEQUENCE category:ASN1_CATEGORY_COMPOSITE];

    [certReqMsg addObject:certificationRequestInfo];
    
    return certReqMsg;

}
@end
