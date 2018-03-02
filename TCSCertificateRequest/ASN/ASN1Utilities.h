//
//  ASN1Utilties.h
//  TCSCertificateRequest
//
//  Created by Tim Perfitt on 2/16/18.
//  Copyright © 2018 Twocanoes Software. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>
#import "ASN1Composite.h"
#import "ASN1Primative.h"

#define ENCRYPTED_CONTENT_INFO @"0.2"
#define VERSION @"0.0"
#define RECIPIENTINFOS @"0.1"
#define ASN1_CLASS_UNIVERSAL 0
#define ASN1_CLASS_APPLICATION 64
#define ASN1_CLASS_CONTENT_SPECIFIC 128
#define ASN1_CLASS_PRIVATE 192
#define ASN1_CATEGORY_COMPOSITE 32
#define ASN1_CATEGORY_PRIMATIVE 0


#define ASN1_TYPE_INTEGER    2
#define ASN1_TYPE_BIT_STRING    3
#define ASN1_TYPE_OCTET_STRING 4
#define ASN1_TYPE_NULL    5
#define ASN1_TYPE_OBJECT_IDENTIFIER    6
#define ASN1_TYPE_SEQUENCE    16
#define ASN1_TYPE_SET    17
#define ASN1_TYPE_PRINTABLESTRING    19
#define ASN1_TYPE_T61STRING    20
#define ASN1_TYPE_IA5STRING    22
#define ASN1_TYPE_UTCTIME    23
#define OID_ENVELOPED_DATA @"1.2.840.113549.1.7.3"
#define OID_SIGNED_DATA @"1.2.840.113549.1.7.2"
#define OID_RSA_MAIN @"1.2.840.113549.1.1.1"
#define OID_RSA_DATA @"1.2.840.113549.1.7.1"
#define OID_3DES @"1.2.840.113549.3.7"
#define OID_SHA1 @"1.2.840.113549.1.1.5"
#define OID_MESSAGE_DIGEST @"1.2.840.113549.1.9.4"
#define OID_ALG_SHA1 @"1.3.14.3.2.26"
#define OID_CONTENT_TYPE @"1.2.840.113549.1.9.3"
#define OID_RSA_ENCRYPTION @"1.2.840.113549.3"


@interface ASN1Utilities : NSObject
+(NSData *)encodeASN1:(ASN1Composite *)composite useINF:(BOOL)useINF;
+(NSData *)encodedLengthFromData:(NSData *)inData;
@end
