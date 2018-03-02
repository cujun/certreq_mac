//
//  ASN1Primative.h
//  SMIME Reader
//
//  
//  Copyright 2012-2017 Twocanoes Software Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#define ASN1_TYPE_INTEGER    2    
#define ASN1_TYPE_BIT_STRING    3    
#define ASN1_TYPE_OCTET_STRING 4
#define ASN1_TYPE_NULL    5
#define ASN1_TYPE_OBJECT_IDENTIFIER    6
#define ASN1_TYPE_UTF8STRING    12
#define ASN1_TYPE_SEQUENCE    16
#define ASN1_TYPE_SET    17
#define ASN1_TYPE_PRINTABLESTRING    19    
#define ASN1_TYPE_T61STRING    20
#define ASN1_TYPE_IA5STRING    22
#define ASN1_TYPE_UTCTIME    23
#define ASN1_CLASS_UNIVERSAL 0
#define ASN1_CLASS_APPLICATION 64
#define ASN1_CLASS_CONTENT_SPECIFIC 128
#define ASN1_CLASS_PRIVATE 192
#define ASN1_CATEGORY_PRIMATIVE 0
#define ASN1_RAW_DATA -1
@interface ASN1Primative : NSObject {
    int asn1Type;
    int asn1Category;
    int asn1Class;    
    id primativeData;
}
@property (assign,nonatomic) int asn1Type;
@property (assign,nonatomic) int asn1Category;
@property (assign,nonatomic) int asn1Class;
@property (strong, nonatomic) id primativeData;

+(ASN1Primative *)asn1PrimativeWithOID:(NSString *)oid;
+(ASN1Primative *)asn1PrimativeWithInteger:(NSData *)inIntData;
+(ASN1Primative *)asn1PrimativeWithBitString:(NSData *)inBitString;
+(ASN1Primative *)asn1PrimativeWithUTF8String:(NSString *)inString;
+(ASN1Primative *)asn1PrimativeWithNull;
+(ASN1Primative *)asn1PrimativeWithPrintableString:(NSString *)inString;
+(ASN1Primative *)asn1PrimativeWithData:(NSData *)inData;
+(ASN1Primative *)asn1PrimativeWithOctetString:(NSData *)inData;
+(ASN1Primative *)asn1PrimativeWithDate:(NSDate *)inDate;
+(ASN1Primative *)asn1PrimativeWithID:(id)inVal;
- (NSString *)descriptionWithLocale:(id)locale indent:(NSUInteger)level;
@end
