#import <Foundation/Foundation.h>



@interface NSString (QP)

+ (NSString *)stringFromQPString:(NSString *)aString encoding:(NSInteger)enc;
+(unsigned long)cocoaEncodingForCEncoding:(NSString *)inEncoding;
@end
