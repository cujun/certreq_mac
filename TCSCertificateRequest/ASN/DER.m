/*
 //
//  DER.m
//  SMIME Reader
//
//  
//  Copyright 2012-2017 Twocanoes Software Inc. All rights reserved.
//
*/

#import "DER.h"


@implementation DER

+(DER *)der{
        
    DER *newDer=[[DER alloc] init];
    return newDer;
    
}
+(NSString *)oidFromDerData:(NSData *)inDer{
    int oid=0;
    int oid1;
    int oid2;
    
    if ([inDer length]==0)  {NSLog(@"Issue with next  ! %i",__LINE__); return nil;}
    
    [[inDer subdataWithRange:NSMakeRange(0,1)] getBytes:&oid length:1];
    
    oid1=oid/40;
    oid2=oid%40;
    
    
    
    NSMutableString *oids=[NSMutableString string];
    [oids appendString:[NSString stringWithFormat:@"%i.%i",oid1,oid2]];
    
    int i;
    int currentByte=0;
    int currentOID=0;
    BOOL shouldStop=NO;
    for (i=1;i<[inDer length];i++){
        currentByte=0;
        
        if ([inDer length]<i+1)  {NSLog(@"Issue with inDer:  ! %i",__LINE__); return nil;}
        [[inDer subdataWithRange:NSMakeRange(i,1)] getBytes:&currentByte length:1];
        
        if ((currentByte&0x80)==0) shouldStop=YES;
        currentByte=currentByte&0x7F;
        
        currentOID=currentByte|currentOID;
        if (shouldStop==YES) {
            
            [oids appendString:[NSString stringWithFormat:@".%i",currentOID]];
            currentOID=0;
            shouldStop=NO;
            
        }
        else {
            currentOID=currentOID<<7;
        }
    }
    
    return [NSString stringWithString:oids];
    
    
}
-(NSDictionary *)processBlob:(NSData *)inData isINF:(BOOL)isINF currPos:(int)inPos{
    return [self processBlob:inData isINF:isINF currPos:inPos isChoice:NO];


}

-(NSDictionary *)processBlob:(NSData *)inData isINF:(BOOL)isINF currPos:(int)inPos isChoice:(BOOL)isChoice{

    if (inData==nil) {NSLog(@"inData is nil!"); return nil;}
    
    ASN1Composite *rawReturnArray=[[ASN1Composite alloc] init];
    ASN1Composite *returnArray=[[ASN1Composite alloc] init];
    NSData *next;
    int compositeLength;
    BOOL nextIsINF=NO;
    Byte buffer;
    int pos=0;
    
    while (pos<[inData length]){ 
        
        int startPos=pos;

        //get first bytes to determine the class, type and size info
        if (pos+1>[inData length]) {NSLog(@"inData too short! %i",__LINE__); return nil;}
        [inData getBytes:&buffer range:NSMakeRange(pos, 1)];

        pos++;
        
        if (buffer==DER_EOC) { 
            if ([inData length]==1) {
                //NSLog(@"null ignorning");
                continue;
            }
            if (pos+1>[inData length]) {
                NSLog(@"inData too short! %i",__LINE__); 
                return nil;
            }
            [inData getBytes:&buffer range:NSMakeRange(pos, 1)];
            
            if (buffer==DER_EOC && isINF==YES) {  // double zeros, so we have a EOC, and bail
                
                if (pos+1+([inData length]-(pos+1))>[inData length]) {NSLog(@"inData too short! %i",__LINE__); return nil;}
            
                    //                [rawReturnArray addObject:[inData subdataWithRange:NSMakeRange(0,pos)]];
                [rawReturnArray addObject:[NSString stringWithFormat:@"%i,%i",inPos,pos]];
                return [NSDictionary dictionaryWithObjectsAndKeys:returnArray,@"array",
                        [inData subdataWithRange:NSMakeRange(pos+1, [inData length]-(pos+1))],@"remaining",
                        rawReturnArray,@"rawReturnArray",nil];
            }
            continue;
        }
        //the first byte we get has the class, whether it is a princial or composite
        //and the length (or number of bytes for the length)
        Byte dataType=0x1F & buffer;
        Byte dataCategory=0x20 & buffer;
        Byte class=0xC0 & buffer;  
        
        
        //DER_BMPSTRING is the last known data type
        if (dataType>DER_BMPSTRING) {
            NSLog(@"extended datatype! bailing");
            return nil;
        }
        
        NSDictionary *data=[self decodedLengthFromTLV:[inData subdataWithRange:NSMakeRange(pos, [inData length]-pos)]];
        compositeLength=0;
        
        NSUInteger bytesReturned=[[data valueForKey:@"value"] length];
        
        if (pos+1>[inData length]) {
            NSLog(@"inData too short! %i",__LINE__); return nil;
        }
        
        NSData *nextData=[data valueForKey:@"value"];
        if ((![nextData isKindOfClass:[NSData class]]) ||
            ([nextData length]<bytesReturned) 
            ){NSLog(@"nextData too short or not data! %i",__LINE__); return nil;}
        

        [nextData getBytes:&compositeLength length:bytesReturned];

        if (bytesReturned==2) compositeLength=CFSwapInt16BigToHost(compositeLength);
        else if (bytesReturned==3) {
            
            compositeLength=compositeLength<<8;
            compositeLength=CFSwapInt32BigToHost(compositeLength);
        }
        
        else if (bytesReturned==4) compositeLength=CFSwapInt32BigToHost(compositeLength);
        else if (bytesReturned>4) {
            NSLog(@"data blob is too long: %lu bytes",(unsigned long)bytesReturned);
            return nil;
        }

        if (([data valueForKey:@"offset"]==nil) ||
            (![[data valueForKey:@"offset"] isKindOfClass:[NSNumber class]])
            ) NSLog(@"problem with data %lu bytes",(unsigned long)bytesReturned);
        
        int skip=[[data valueForKey:@"offset"] intValue];
        pos=pos+skip;
        if ((pos >=[inData length]) ||(compositeLength >=[inData length]))  break;
        
        
        if ([inData length]<compositeLength+pos) {NSLog(@"inData too short! %i",__LINE__); return nil;}
        
        next=[inData subdataWithRange:NSMakeRange(pos, compositeLength)];
        if ([next length]==0) {
            
            next=[inData subdataWithRange:NSMakeRange(pos, [inData length]-pos)];
            nextIsINF=YES;
            
        }
        
        if ( (class==DER_CLASS_UNIVERSAL && dataCategory==0x20) || 
            (class==DER_CLASS_CONTEXT_SPECIFIC && dataCategory==0x20) ||
            ((class==DER_CLASS_UNIVERSAL) && (dataType==0x10)) ||
            ((class==DER_CLASS_UNIVERSAL) && (dataType==0x11))
            ) {
            
            NSDictionary *retDic=[self processBlob:next isINF:nextIsINF currPos:inPos+pos isChoice:isChoice];


            pos=pos+(int)[next length];
            ASN1Composite *recArray=[retDic objectForKey:@"array"];
            recArray.asn1Type=dataType;
            recArray.asn1Category=dataCategory;
            recArray.asn1Class=class;
            
            if (recArray==nil)  {
                NSLog(@"Issue with recArray! %i",__LINE__); 
                return nil;
            }
            recArray.rangeOfData=[NSString stringWithFormat:@"%i,%i",inPos+startPos,pos-startPos];
            [returnArray addObject:recArray];
            [rawReturnArray addObject:[NSDictionary dictionaryWithObjectsAndKeys:
                                       [NSString stringWithFormat:@"%i,%i",inPos+startPos,pos-startPos],
                                       @"location",
                                       [retDic objectForKey:@"rawReturnArray"],
                                       @"value",nil]];

            if ([retDic objectForKey:@"remaining"]) {

                inPos=inPos+(int)[inData length]-(int)[[retDic objectForKey:@"remaining"] length];
                inData=[retDic objectForKey:@"remaining"];
                pos=0;

                nextIsINF=NO;
                continue;
            }
           
        }
        else {
            [rawReturnArray addObject:[NSString stringWithFormat:@"%i,%i",inPos+startPos,compositeLength]];
            if (dataType==DER_OCTET_STRING || isChoice==YES || class==DER_CLASS_CONTEXT_SPECIFIC) { //octet string
                
                
                ASN1Primative *primative=[ASN1Primative asn1PrimativeWithData:[next subdataWithRange:NSMakeRange(0,compositeLength)]];
                
                [primative setAsn1Type:dataType];
                [primative setAsn1Category:dataCategory];
                [primative setAsn1Class:class];
                [returnArray addObject:primative];
                pos=pos+compositeLength;
            }
            else if (dataType==DER_BOOLEAN) {  //boolean
                int myBool=0;
                if ([next length]==0) {NSLog(@"Issue with next! %i",__LINE__); return nil;}
                [[next subdataWithRange:NSMakeRange(0,1)] getBytes:&myBool length:1];
                ASN1Primative *primative=[ASN1Primative asn1PrimativeWithID:[NSNumber numberWithInt:myBool]];
                [primative setAsn1Type:dataType];
                [primative setAsn1Category:dataCategory];
                [primative setAsn1Class:class];

                [returnArray addObject:primative];
                pos=pos+compositeLength;
            }
            else if (dataType==DER_INTEGER) {//integer
                
                int versionByte=0;
                
                NSData *versionData=[next subdataWithRange:NSMakeRange(0,compositeLength)];
                
                if ([versionData length]==0) {NSLog(@"Issue with versionData! %i",__LINE__); return nil;}
                
                [versionData getBytes:&versionByte length:1];
                ASN1Primative *primative=[ASN1Primative asn1PrimativeWithInteger:versionData];
                [primative setAsn1Type:dataType];
                [primative setAsn1Category:dataCategory];
                [primative setAsn1Class:class];

                [returnArray addObject:primative];
                
                pos=pos+compositeLength;
            }
            else if (dataType==DER_BIT_STRING) {  // bit string
                
                NSData *bitStringData=[next subdataWithRange:NSMakeRange(0,compositeLength)];
                Byte bitsToSkip;
                
                if ([bitStringData length]==0) {NSLog(@"Issue with bitStringData! %i",__LINE__); return nil;}
                
                [bitStringData getBytes:&bitsToSkip length:1];
                
                if ([next length]==0) {NSLog(@"Issue with meat! %i",__LINE__); return nil;}
                NSData *meat=[next subdataWithRange:NSMakeRange(1,compositeLength-1)];
                //NSString *hexData=[self hexFromData:meat];
                ASN1Primative *primative=[ASN1Primative asn1PrimativeWithOctetString:meat];
                [primative setAsn1Type:dataType];
                [primative setAsn1Category:dataCategory];
                [primative setAsn1Class:class];
                
                [returnArray addObject:primative];
                pos=pos+compositeLength;
            }
            else if (dataType==DER_OBJECT_IDENTIFIER) {
                
                if ([next length]==0)  {NSLog(@"Issue with next  ! %i",__LINE__); return nil;}
                
                NSString *oids=[DER oidFromDerData:next];//
                ASN1Primative *primative=[ASN1Primative asn1PrimativeWithPrintableString:oids];
                [primative setAsn1Type:dataType];
                [primative setAsn1Category:dataCategory];
                [primative setAsn1Class:class];
                
                [returnArray addObject:primative];
                pos=pos+compositeLength;
            }
            else if (dataType==DER_UTF8STRING) {
                
                if ([next length]<compositeLength) {NSLog(@"Issue with next! DER_UTF8STRING %i",__LINE__); return nil;}
                
                NSString *utf8String=[[NSString alloc] initWithData:[next subdataWithRange:NSMakeRange(0,compositeLength)] encoding:NSUTF8StringEncoding];
                
                ASN1Primative *primative=[ASN1Primative asn1PrimativeWithPrintableString:utf8String];
                [primative setAsn1Type:dataType];
                [primative setAsn1Category:dataCategory];
                [primative setAsn1Class:class];

                [returnArray addObject:primative];
                pos=pos+compositeLength;
            }
            
            else if (dataType==DER_PRINTABLE_STRING) {
                if ([next length]<compositeLength) {NSLog(@"Issue with next! DER_PRINTABLE_STRING %i",__LINE__); return nil;}
                NSString *printableString=[[NSString alloc] initWithData:[next subdataWithRange:NSMakeRange(0,compositeLength)] encoding:NSASCIIStringEncoding];
                
                ASN1Primative *primative=[ASN1Primative asn1PrimativeWithPrintableString:printableString];
                [primative setAsn1Type:dataType];
                [primative setAsn1Category:dataCategory];
                [primative setAsn1Class:class];

                [returnArray addObject:primative];
                pos=pos+compositeLength;
            }
            else if (dataType==DER_T61STRING) {
                if ([next length]<compositeLength) {NSLog(@"Issue with next! DER_T61STRING %i",__LINE__); return nil;}
                NSString *t61String=[[NSString alloc] initWithData:[next subdataWithRange:NSMakeRange(0,compositeLength)] encoding:NSASCIIStringEncoding];
                
                ASN1Primative *primative=[ASN1Primative asn1PrimativeWithPrintableString:t61String];
                [primative setAsn1Type:dataType];
                [primative setAsn1Category:dataCategory];
                [primative setAsn1Class:class];
                
                [returnArray addObject:primative];
                pos=pos+compositeLength;
            }
            else if (dataType==DER_IA5STRING || dataType==DER_BIT_STRING || dataType==DER_VISIBLESTRING || dataType==DER_BMPSTRING) {
                if ([next length]<compositeLength) {NSLog(@"Issue with next! DER_IA5STRING %i",__LINE__); return nil;}
                NSString *iA5String=[[NSString alloc] initWithData:[next subdataWithRange:NSMakeRange(0,compositeLength)] encoding:NSUTF8StringEncoding];
                
                
                ASN1Primative *primative=[ASN1Primative asn1PrimativeWithPrintableString:iA5String];
                [primative setAsn1Type:dataType];
                [primative setAsn1Category:dataCategory];
                [primative setAsn1Class:class];

                [returnArray addObject:primative];
                pos=pos+compositeLength;
            }
            
            else if (dataType==DER_UTCTIME) {
                if ([next length]<compositeLength) {NSLog(@"Issue with next! DER_UTCTIME %i",__LINE__); return nil;}
                NSDateFormatter *inputFormatter = [[NSDateFormatter alloc] init];
                [inputFormatter setDateFormat:@"yyDDmmHHmmssv"];
                
                NSString *dateString=[[NSString alloc] initWithData:[next subdataWithRange:NSMakeRange(0,compositeLength)] encoding:NSASCIIStringEncoding];
                NSString *newDate=[dateString stringByReplacingOccurrencesOfString:@"Z" withString:@"-0000"];
                NSDate *formatterDate = [inputFormatter dateFromString:newDate];
                
                ASN1Primative *primative=[ASN1Primative asn1PrimativeWithDate:formatterDate];
                [primative setAsn1Type:dataType];
                [primative setAsn1Category:dataCategory];
                [primative setAsn1Class:class];

                
                    [returnArray addObject:primative];
                pos=pos+compositeLength;
            }
            else if (dataType==DER_EOC) {
                
                ASN1Primative *primative=[ASN1Primative asn1PrimativeWithData:(NSData *)[ASN1Composite arrayWithObject:[next subdataWithRange:NSMakeRange(0,compositeLength)]]];
                [primative setAsn1Type:dataType];
                [primative setAsn1Category:dataCategory];
                [primative setAsn1Class:class];

                [returnArray addObject:primative];
                pos=pos+compositeLength;
            }
            else {
                NSLog(@"unknown type of %02x",dataType);
                [returnArray addObject:@"unknown type"];
                pos=pos+compositeLength;
            }
                //            [rawReturnArray addObject:[returnArray lastObject]];
            
            
        }
    }
    return [NSDictionary dictionaryWithObjectsAndKeys:returnArray,@"array",rawReturnArray,@"rawReturnArray",nil];
    
    
    
}
-(NSDictionary *)decodedLengthFromTLV:(NSData *)inData{
    
    
    Byte firstByte;
    int returnLength;
    NSData *returnValue;
    
    if ([inData length]==0) {NSLog(@"inData in decodedLengthFromTLV is wrong %i",__LINE__);return nil;};
    [inData getBytes:&firstByte length:1]; 
    
    
    
    //If the highest order bit is set, the first byte contains that length
    if ((firstByte&0x80)==0) {  
        
        int rv=(firstByte&0x7F);
        returnValue=[NSData dataWithBytes:&rv length:1];
        
        returnLength=1;
        
    }
    //else the first bytes contains the number of bytes that have the length
    else {
        returnLength=firstByte&0x1F;
        
        if ([inData length]<returnLength+1) {NSLog(@"inData in decodedLengthFromTLV is wrong %i",__LINE__);return nil;};
        returnValue=[inData subdataWithRange:NSMakeRange(1, returnLength)];
        returnLength++; //add one to include the encoder
        
        
    }
    
    NSDictionary *returnDict=[NSDictionary dictionaryWithObjectsAndKeys:returnValue,@"value",
                              [NSNumber numberWithInt:returnLength],@"offset",nil];
    

    
    return returnDict;
    
}

@end
