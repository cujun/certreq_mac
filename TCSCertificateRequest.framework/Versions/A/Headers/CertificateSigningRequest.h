//
//  CertificateSigningRequest.h
//  TCSCertificateRequest
//
//  Created by Tim Perfitt on 2/14/18.
//  Copyright © 2018 Twocanoes Software. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface CertificateSigningRequest : NSObject
+(NSData *)createCertificateSigningRequestWithCommonName:(NSString *)inName publicKey:(NSData *)publicKey privateKey:(SecKeyRef) privateKeyRef;
@end
