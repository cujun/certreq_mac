//
//  DER.h
//  SMIME Reader
//
//  
//  Copyright 2012-2017 Twocanoes Software Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ASN1Composite.h"
#import "ASN1Primative.h"
#define DER_EOC 0x00
#define DER_BOOLEAN 0x01
#define DER_INTEGER 0x02
#define DER_BIT_STRING 0x03
#define DER_OCTET_STRING 0x04
#define DER_NULL 0x05
#define DER_OBJECT_IDENTIFIER 0x06
#define DER_OBJECT_DESCRIPTOR 0x07
#define DER_EXTERNAL 0x08
#define DER_REAL 0x09
#define DER_ENUMERATED 0x0A
#define DER_EMBEDDED_PDV 0x0B
#define DER_UTF8STRING 0x0C
#define DER_RELATIVE_OID 0x0D
#define DER_SEQUENCE 0x10
#define DER_SET 0x11
#define DER_NUMBERIC_STRING 0x12
#define DER_PRINTABLE_STRING 0x13
#define DER_T61STRING 0x14
#define DER_VIDEOTEXSTRING 0x015
#define DER_IA5STRING 0x16
#define DER_UTCTIME 0X17
#define DER_GENERALIZEDTIME 0X18
#define DER_GRAPHICSTRING 0X19
#define DER_VISIBLESTRING 0X1A
#define DER_GENERALSTRING 0X1B
#define DER_UNIVERSALSTRING 0X1C
#define DER_CHARACTER_STRING 0x1D
#define DER_BMPSTRING 0x1E

#define DER_CLASS_UNIVERSAL 0X00
#define DER_CLASS_APPLICATION 0X40
#define DER_CLASS_CONTEXT_SPECIFIC 0X80
#define DER_CLASS_PRIVATE 0XC0
//#define ASN1_CATEGORY_COMPOSITE 1
#define ASN1_CATEGORY_PRIMATIVE 0


@interface DER : NSObject {

}
+(DER *)der;
+(NSString *)oidFromDerData:(NSData *)inDer;
-(NSDictionary *)processBlob:(NSData *)inData isINF:(BOOL)isINF currPos:(int)inPos isChoice:(BOOL)isChoice;
-(NSDictionary *)processBlob:(NSData *)inData isINF:(BOOL)isINF currPos:(int)inPos;
-(NSDictionary *)decodedLengthFromTLV:(NSData *)inData;

@end
