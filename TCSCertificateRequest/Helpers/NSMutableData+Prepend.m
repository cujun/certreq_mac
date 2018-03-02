#import "NSMutableData+Prepend.h"
@implementation NSMutableData (Prepend)

-(void)prependData:(NSData *)inData;
{
	NSMutableData *currData=[NSMutableData dataWithData:inData];
	[currData appendData:self];
	[self setData:currData];
}

@end
