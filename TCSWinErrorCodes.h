//
//  TCSWinErrorCodes.h
//  TCSCertRequest
//
//  Created by Tim Perfitt on 3/7/18.
//  Copyright © 2018 Twocanoes Software. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface TCSWinErrorCodes : NSObject
+(NSString *)winErrorForCode:(int)code;
@end
