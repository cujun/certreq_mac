//
//  ASN1Utilties.m
//  TCSCertificateRequest
//
//  Created by Tim Perfitt on 2/16/18.
//  Copyright © 2018 Twocanoes Software. All rights reserved.
//

#import "ASN1Utilities.h"

@implementation ASN1Utilities
+(int)algorithmForOID:(NSString *)inOID{
    
    int returnAlg=-1;
    
    if (inOID==nil) return returnAlg;
    if ([inOID isEqualToString:@"1.2.840.113549.3.7"]) returnAlg=kCCAlgorithm3DES;
    else if ([inOID isEqualToString:@"1.2.840.113549.3.2"]) returnAlg=kCCAlgorithmRC2;
    else if ([inOID isEqualToString:@"1.2.840.113549.3.4"]) returnAlg=kCCAlgorithmRC4;
    else if ([inOID hasPrefix:@"2.16.840.1.101.3.4.1"]) returnAlg=kCCAlgorithmAES128;  //covers both 128 and 256
    else if ([inOID hasPrefix:@"1.3.14.3.2.7"]) returnAlg=kCCAlgorithmDES;
    
    return returnAlg;
    
    
}
+(NSData *)encodedLengthFromData:(NSData *)inData{
    
    if ([inData length]>0XFFFFFFF) NSLog(@"length too long!");
    int length=(int)[inData length];
    if (length<0x7f) {
        NSData *lengthData=[NSData dataWithBytes:&length length:1];
        return lengthData;
    }
    else {
        
        uint32_t bigLength=CFSwapInt32HostToBig(length);
        
        NSData *lengthByteData=[NSData dataWithBytes:&bigLength length:sizeof(bigLength)];
        
        int currByte;
        int pos=0;
        while (pos<[lengthByteData length]) {
            currByte=0;
            NSData *currByteData=[lengthByteData subdataWithRange:NSMakeRange(pos, 1)];
            [currByteData getBytes:&currByte length:1];
            if (currByte!=0x00) break;
            pos++;
            
        }
        if (pos==[lengthByteData length]) {
            NSLog(@"zero byte length!!");
            return nil;
        }
        NSData *shortendLengthByteData=[lengthByteData subdataWithRange:
                                        NSMakeRange(pos, [lengthByteData length]-pos)];
        int lengthOfLength=(int)[shortendLengthByteData length];
        lengthOfLength=0X80|lengthOfLength;
        
        NSData *lengthOfLengthData=[NSData dataWithBytes:&lengthOfLength length:1];
        
        NSMutableData *returnData=[NSMutableData dataWithData:lengthOfLengthData];
        [returnData appendData:shortendLengthByteData];
        
        return returnData;
        
    }
    
}

+(NSData *)encodeASN1:(ASN1Composite *)composite useINF:(BOOL)useINF{
    
    NSMutableData *finalData=[NSMutableData data];
    int type=[composite asn1Type]|[composite asn1Class]|[composite asn1Category];
    
    NSData *typeData=[NSData dataWithBytes:&type length:1];
    [finalData appendData:typeData];
    
    NSMutableData *innerData=[NSMutableData data];
    
    for (id currentASN in composite) {
        if ([currentASN asn1Category]==ASN1_CATEGORY_COMPOSITE) {
            NSData *compositeData=[ASN1Utilities encodeASN1:currentASN useINF:NO];
            [innerData appendData:compositeData];
            
        }
        else {
            NSData *newPrimativeData=nil;
            ASN1Primative *primative=(ASN1Primative *)currentASN;
            int primativeType=[currentASN asn1Type]|[currentASN asn1Class]|[currentASN asn1Category];
            NSData *primativeTypeData=[NSData dataWithBytes:&primativeType length:1];
            
            
            
            if (primative.asn1Type==ASN1_TYPE_OCTET_STRING){
                newPrimativeData=[primative primativeData];
                
            }
            
            else if (primative.asn1Type==ASN1_TYPE_PRINTABLESTRING){
                NSString *printableString=(NSString *)[primative primativeData];
                NSData *stringData=[printableString dataUsingEncoding:NSUTF8StringEncoding];
                newPrimativeData=stringData;
                
            }
            else if (primative.asn1Type==ASN1_TYPE_UTF8STRING){
                newPrimativeData=(NSData *)[primative primativeData];
                
            }
            
            else if (primative.asn1Type==ASN1_TYPE_INTEGER){
                newPrimativeData=(NSData *)[primative primativeData];
                
                //                newPrimativeData=[NSData dataWithBytes:&integer length:sizeof(int)];
                
            }
            else if (primative.asn1Type==ASN1_TYPE_OBJECT_IDENTIFIER){
                
                NSMutableData *outData;
                NSData *currentOctetData=nil;
                NSMutableData *newData;
                NSString *inOID=(NSString *)[primative primativeData];
                
                NSArray *oidArray=[inOID componentsSeparatedByString:@"."];
                
                int firstByte=[[oidArray objectAtIndex:0] intValue]*40+[[oidArray objectAtIndex:1] intValue];
                
                outData=[NSMutableData dataWithBytes:&firstByte length:1];
                int i;
                for (i=2;i<[oidArray count];i++) {
                    
                    int workingInt=[[oidArray objectAtIndex:i] intValue];
                    int currentOID=workingInt&0x7F;
                    
                    newData=[NSMutableData dataWithBytes:&currentOID length:1];
                    if (currentOctetData!=nil) [newData appendData:currentOctetData];
                    currentOctetData=newData;
                    
                    workingInt=workingInt>>7;
                    while (workingInt!=0) {
                        currentOID=workingInt&0x7F;
                        currentOID=currentOID|0X80;
                        
                        newData=[NSMutableData dataWithBytes:&currentOID length:1];
                        [newData appendData:currentOctetData];
                        currentOctetData=newData;
                        workingInt=workingInt>>7;
                    }
                    [outData appendData:currentOctetData];
                    currentOctetData=nil;
                    
                }
                newPrimativeData=outData;
                
            }
            else if (primative.asn1Type==ASN1_RAW_DATA){
                newPrimativeData=[primative primativeData];
                
                
                
            }
            else if (primative.asn1Type==ASN1_TYPE_BIT_STRING){
                char byte[]={0x00};
                NSMutableData *leadingZero=[NSMutableData dataWithBytes:&byte length:1];
                
                NSData *bulkData=(NSData *)[primative primativeData];
                [leadingZero appendData:bulkData];
                newPrimativeData=[NSData dataWithData:leadingZero];
                
                
                
            }
            if (primative.asn1Type!=ASN1_RAW_DATA) {
                
                [innerData appendData:primativeTypeData];
                [innerData appendData:[ASN1Utilities encodedLengthFromData:newPrimativeData]];
                
                
            }
            
            if (newPrimativeData) [innerData appendData:newPrimativeData];
            
        }
        
    }
    
    int length=(int)[innerData length];
    if (useINF==YES || length>1000) {
        
        int length=0x80; //INF
        NSData *lengthData=[NSData dataWithBytes:&length length:1];
        
        static unsigned char infEnd[]={0x00,0x00};
        NSData *infEndData=[NSData dataWithBytes:infEnd length:2];
        
        
        [finalData appendData:lengthData];
        [finalData appendData:innerData];
        [finalData appendData:infEndData];
    }
    else{
        [finalData appendData:[ASN1Utilities encodedLengthFromData:innerData]];
        [finalData appendData:innerData];
    }
    
    
    return finalData;
}

@end
