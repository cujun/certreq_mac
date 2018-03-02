//
//  ASN1Composite.h
//  SMIME Reader
//
//  
//  Copyright 2012-2017 Twocanoes Software Inc. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface ASN1Composite : NSMutableArray {
    int asn1Type;
    int asn1Category;
    int asn1Class;    
    NSString *rangeOfData;
    NSMutableArray *storageArray;
}
+(ASN1Composite *)asn1Composite;
-(id)objectAtIndexPath:(NSString *)inString;
-(void)setClass:(int)inClass type:(int)inType category:(int)inCategory;
@property (assign,nonatomic) int asn1Type;
@property (assign,nonatomic) int asn1Category;
@property (assign,nonatomic) int asn1Class;
@property (strong, nonatomic) NSString *rangeOfData;
@end
