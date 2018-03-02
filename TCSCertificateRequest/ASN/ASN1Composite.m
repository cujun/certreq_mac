//
//  ASN1Composite.m
//  SMIME Reader
//
//  
//  Copyright 2012-2017 Twocanoes Software Inc. All rights reserved.
//

#import "ASN1Composite.h"


@implementation ASN1Composite
@synthesize asn1Type,asn1Category,asn1Class, rangeOfData;

+(ASN1Composite *)asn1Composite{
    
    ASN1Composite *asn1Composite=[[ASN1Composite alloc] init];
    return asn1Composite;
    
}
- (id)init
{
    self = [super init];
    if (self) {
        storageArray=[[NSMutableArray alloc] init];
    }
    return self;
}
- (id)initWithCapacity:(NSUInteger)numItems{
    self = [super init];
    if (self) {
        storageArray=[[NSMutableArray alloc] initWithCapacity:numItems];
    }
    return self;
    
}
-(void)setClass:(int)inClass type:(int)inType category:(int)inCategory {
    asn1Type=inType;
    asn1Category=inCategory;
    asn1Class=inClass;
}

-(id)objectAtIndexPath:(NSString *)inString{
    NSArray *arrayOfIndexes=[inString componentsSeparatedByString:@"."];
    id currentArray=storageArray;
    for (NSString *currIndex in arrayOfIndexes) {
        
        currentArray=[currentArray objectAtIndex:[currIndex intValue]];
        
    }
    return currentArray;
    
}


-(NSUInteger)count{
    return [storageArray count];
    
}
- (id)objectAtIndex:(NSUInteger)index{
    return [storageArray objectAtIndex:index];
}
- (void)insertObject:(id)anObject atIndex:(NSUInteger)index{
    
}
- (void)removeObjectAtIndex:(NSUInteger)index{
    [storageArray removeObjectAtIndex:index];
}
- (void)addObject:(id)anObject{
    [storageArray addObject:anObject];
}
- (void)removeLastObject{
    [storageArray removeLastObject];
}
- (void)replaceObjectAtIndex:(NSUInteger)index withObject:(id)anObject{
    [storageArray replaceObjectAtIndex:index withObject:anObject];
}


- (NSString *)descriptionWithLocale:(id)locale indent:(NSUInteger)level{
    return [NSString stringWithFormat:@"Type:%i,Category:%i,Class:%i,Range:%@,%@",
            asn1Type,asn1Category,asn1Class,rangeOfData,[storageArray descriptionWithLocale:locale indent:level]];


}
@end
