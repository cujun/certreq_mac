//
//  TCSCertAppHelper.h
//  TCSCertRequest
//
//  Created by Tim Perfitt on 3/1/18.
//  Copyright © 2018 Twocanoes Software. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface TCSCertAppHelper : NSObject
+(NSData *)generateCSRFromYubikeyWithManagementKey:(NSString *)managementKey inSlot:(NSString *)yubiKeySlot commonName:(NSString *)commonName error:(NSError **)error;
+(NSData *)generateCSRFromKeychainWithCommonName:(NSString *)commonName error:(NSError **)error;

@end
