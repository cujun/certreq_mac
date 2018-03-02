#import "NSString+QP.h"

@implementation NSString (QP)
+ (NSString *)stringFromQPString:(NSString *)aString encoding:(NSInteger)enc{
    NSMutableString *workingString=[NSMutableString stringWithString:aString];
    [workingString replaceOccurrencesOfString:@"=\r\n" withString:@"" options:NSCaseInsensitiveSearch range:NSMakeRange(0,[workingString length])];
    [workingString replaceOccurrencesOfString:@"\r\n" withString:@"\n" options:NSCaseInsensitiveSearch range:NSMakeRange(0,[workingString length])];
    [workingString replaceOccurrencesOfString:@"=\r" withString:@"" options:NSCaseInsensitiveSearch range:NSMakeRange(0,[workingString length])];
    [workingString replaceOccurrencesOfString:@"\r" withString:@"\n" options:NSCaseInsensitiveSearch range:NSMakeRange(0,[workingString length])];
    if ([workingString characterAtIndex:[workingString length]-1]=='=') 
        [workingString deleteCharactersInRange:NSMakeRange([workingString length]-1, 1)];
    NSUInteger i;
    
    for (i=0;i<[workingString length];i++){
        NSMutableString *utfEncoded;
        NSMutableData *mutableData;
        int byte;
        NSInteger start;
        

        if ([[workingString substringWithRange:NSMakeRange(i, 1)] isEqualToString:@"="]){

            start=i;
            utfEncoded=[NSMutableString string];
            mutableData=[NSMutableData data];
            
            while ((i<[workingString length])&&[[workingString substringWithRange:NSMakeRange(i, 1)] isEqualToString:@"="]) {

                // found start of binary
                NSString *code=[workingString substringWithRange:NSMakeRange(i+1, 2)];
                [utfEncoded appendString:code];
                //NSLog(@"code is %@",code);

                sscanf([code UTF8String], "%x",&byte);
                [mutableData appendData:[NSData dataWithBytes:&byte length:1]];
                //NSLog(@"adding %@",code);
                i+=3;
            }


            NSString *newString=[[NSString alloc] initWithData:mutableData encoding:enc];            
            if (newString!=nil) {
                [workingString deleteCharactersInRange:NSMakeRange(start, i-start)];
                [workingString insertString:newString atIndex:start];
                i=start+[newString length]-1;
            }
            else {
                i=start+[mutableData length]-1;
            }


        }
        
    }
    
    //yes, this seems crazy, but we encoded found binary data character by character, and 
    //multibye encodings require a more holistic determination.  So we spit it out and
    //read it back in again, to make it all ok with the world.
    
    //This is a hack, and we really should output the data byte by byte to memory and then
    //read it into a string with the correct encoding.  But meh.
    
    NSData *rawData=[workingString dataUsingEncoding:enc];
    workingString=[[[NSString alloc] initWithData:rawData encoding:enc] mutableCopy];

    
    return workingString;
    
}
+(unsigned long)cocoaEncodingForCEncoding:(NSString *)inEncoding{
    NSStringEncoding nsEncoding;

    if ([[inEncoding uppercaseString] isEqualToString:@"KOI8-R"]) {
        return NSWindowsCP1251StringEncoding;
    }

    CFStringEncoding encoding=CFStringConvertIANACharSetNameToEncoding((CFStringRef)inEncoding);
    nsEncoding=(NSStringEncoding)CFStringConvertEncodingToNSStringEncoding(encoding);
    return nsEncoding;
}

@end
