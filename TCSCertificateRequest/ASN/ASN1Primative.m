//
//  ASN1Primative.m
//  SMIME Reader
//
//  
//  Copyright 2012-2017 Twocanoes Software Inc. All rights reserved.
//

#import "ASN1Primative.h"


@implementation ASN1Primative
@synthesize asn1Type,asn1Category,asn1Class,primativeData;

+(ASN1Primative *)asn1PrimativeWithNull{
    ASN1Primative *primative=[[ASN1Primative alloc] init];

    primative.asn1Type=ASN1_TYPE_NULL;
    primative.asn1Class=ASN1_CLASS_UNIVERSAL;
    primative.asn1Category=ASN1_CATEGORY_PRIMATIVE;
    return primative;
    
}
+(ASN1Primative *)asn1PrimativeWithOID:(NSString *)oid{
    ASN1Primative *primative=[[ASN1Primative alloc] init];
    [primative setPrimativeData:oid];
    primative.asn1Type=ASN1_TYPE_OBJECT_IDENTIFIER;
    primative.asn1Class=ASN1_CLASS_UNIVERSAL;
    primative.asn1Category=ASN1_CATEGORY_PRIMATIVE;
    return primative;
    
}
+(ASN1Primative *)asn1PrimativeWithInteger:(NSData *)inIntData{
    ASN1Primative *primative=[[ASN1Primative alloc] init];
    [primative setPrimativeData:inIntData];
    primative.asn1Type=ASN1_TYPE_INTEGER;
    primative.asn1Class=ASN1_CLASS_UNIVERSAL;
    primative.asn1Category=ASN1_CATEGORY_PRIMATIVE;
    return primative;
    
}
+(ASN1Primative *)asn1PrimativeWithBitString:(NSData *)inBitString{
    ASN1Primative *primative=[[ASN1Primative alloc] init];
    [primative setPrimativeData:inBitString];
    primative.asn1Type=ASN1_TYPE_BIT_STRING;
    primative.asn1Class=ASN1_CLASS_UNIVERSAL;
    primative.asn1Category=ASN1_CATEGORY_PRIMATIVE;
    return primative;
    
}
+(ASN1Primative *)asn1PrimativeWithUTF8String:(NSString *)inString{
    ASN1Primative *primative=[[ASN1Primative alloc] init];
    NSData *utf8Data=[inString dataUsingEncoding:NSUTF8StringEncoding];
    [primative setPrimativeData:utf8Data];
    primative.asn1Type=ASN1_TYPE_UTF8STRING;
    primative.asn1Class=ASN1_CLASS_UNIVERSAL;
    primative.asn1Category=ASN1_CATEGORY_PRIMATIVE;
    return primative;
    
}

+(ASN1Primative *)asn1PrimativeWithPrintableString:(NSString *)inString{
    ASN1Primative *primative=[[ASN1Primative alloc] init];
    [primative setPrimativeData:inString];
    primative.asn1Type=ASN1_TYPE_PRINTABLESTRING;
    primative.asn1Class=ASN1_CLASS_UNIVERSAL;
    primative.asn1Category=ASN1_CATEGORY_PRIMATIVE;
    return primative;
    
}
+(ASN1Primative *)asn1PrimativeWithData:(NSData *)inData{
    ASN1Primative *primative=[[ASN1Primative alloc] init];
    [primative setPrimativeData:inData];
    primative.asn1Type=ASN1_RAW_DATA;
    primative.asn1Class=ASN1_RAW_DATA;
    primative.asn1Category=ASN1_RAW_DATA;
    return primative;
    
}


+(ASN1Primative *)asn1PrimativeWithOctetString:(NSData *)inData{
    ASN1Primative *primative=[[ASN1Primative alloc] init];
    [primative setPrimativeData:inData];
    primative.asn1Type=ASN1_TYPE_OCTET_STRING;
    primative.asn1Class=ASN1_CLASS_UNIVERSAL;
    primative.asn1Category=ASN1_CATEGORY_PRIMATIVE;
    return primative;
    
}

+(ASN1Primative *)asn1PrimativeWithDate:(NSDate *)inDate{
    ASN1Primative *primative=[[ASN1Primative alloc] init];
    [primative setPrimativeData:inDate];
    primative.asn1Type=ASN1_TYPE_OCTET_STRING;
    primative.asn1Class=ASN1_CLASS_UNIVERSAL;
    primative.asn1Category=ASN1_CATEGORY_PRIMATIVE;
    return primative;
    
}
+(ASN1Primative *)asn1PrimativeWithID:(id)inVal{
    ASN1Primative *primative=[[ASN1Primative alloc] init];
    [primative setPrimativeData:inVal];
    primative.asn1Type=ASN1_TYPE_OCTET_STRING;
    primative.asn1Class=ASN1_CLASS_UNIVERSAL;
    primative.asn1Category=ASN1_CATEGORY_PRIMATIVE;
    return primative;
    
}
- (NSString *)descriptionWithLocale:(id)locale{
        return [self descriptionWithLocale:locale indent:0];
}
- (NSString *)description{
    
    return [self descriptionWithLocale:nil indent:0];
}

- (NSString *)descriptionWithLocale:(id)locale indent:(NSUInteger)level{
    return [NSString stringWithFormat:@"Type:%i,Category:%i,Class:%i,Data:%@",
            asn1Type,asn1Category,asn1Class,primativeData];
    
    
}


@end
