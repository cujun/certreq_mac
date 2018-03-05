//
//  TCSecurity.m
//  SMIME Reader
//
//
//  Copyright 2012-2017 Twocanoes Software Inc. All rights reserved.
//

#import "TCSecurity.h"
#import "ASN1Primative.h"
#import "DER.h"
#import "ASN1Composite.h"
#import "ASN1Utilities.h"
#include <CommonCrypto/CommonDigest.h>
#import <pwd.h>

#define OID_SIGNED_DATA @"1.2.840.113549.1.7.2"



@implementation TCSecurity


#if DEBUG
#define LOGGING_FACILITY(X, Y)    \
NSAssert(X, Y);

#define LOGGING_FACILITY1(X, Y, Z)    \
NSAssert1(X, Y, Z);
#else
#define LOGGING_FACILITY(X, Y)    \
if (!(X)) {            \
NSLog(Y);        \
exit(-1);        \
}

#define LOGGING_FACILITY1(X, Y, Z)    \
if (!(X)) {                \
NSLog(Y, Z);        \
exit(-1);            \
}
#endif

+(id)attribute:(id)inArr forIdentity:(SecIdentityRef)identityRef{

    
    SecCertificateRef certificateRef;
    SecIdentityCopyCertificate (identityRef,&certificateRef);
    
    NSDictionary *certAttrDict;
    
    OSStatus sanityCheck;
    sanityCheck = SecItemCopyMatching((CFDictionaryRef)[NSDictionary dictionaryWithObjectsAndKeys:
                                                        (id)kSecClassCertificate,           kSecClass,
                                                        kSecMatchLimitOne,      kSecMatchLimit,
                                                        kCFBooleanFalse,         kSecReturnRef,
                                                        kCFBooleanTrue,         kSecReturnAttributes,
                                                        certificateRef,kSecValueRef,
                                                        nil
                                                        ] , (void *)&certAttrDict);

    

    NSData *subject;
    if (sanityCheck!=noErr) {
        NSLog(@"SecIdentityCopyCertificate error");
        return nil;
    }
    subject=(NSData *)[certAttrDict objectForKey:inArr];

    
    return subject;
    
    
}

+(NSData *)wrappedPublicKeyFromModulus:(NSData *)inModulus andExponent:(NSData *)inExponent{
    
    ASN1Composite *publicKeyASN1=[ASN1Composite asn1Composite];
    [publicKeyASN1 setClass:ASN1_CLASS_UNIVERSAL type:ASN1_TYPE_SEQUENCE category:ASN1_CATEGORY_COMPOSITE];
    
    char nullByte[]={0x00};
    NSMutableData *leadingZeroMutableKey=[NSMutableData dataWithBytes:nullByte length:1];
    [leadingZeroMutableKey appendData:inModulus];
    NSData *leadingZeroModulusData=[NSData dataWithData:leadingZeroMutableKey];
    
    ASN1Primative *modulasASN1=[ASN1Primative asn1PrimativeWithInteger:leadingZeroModulusData];
    
    ASN1Primative *exponent=[ASN1Primative asn1PrimativeWithInteger:inExponent];
    
    [publicKeyASN1 addObject:modulasASN1];
    [publicKeyASN1 addObject:exponent];
    NSData *publicKeyData=[ASN1Utilities encodeASN1:publicKeyASN1 useINF:NO];
    
    
    ASN1Composite *publicKeyWrapper=[ASN1Composite asn1Composite];
    [publicKeyWrapper setClass:ASN1_CLASS_UNIVERSAL type:ASN1_TYPE_SEQUENCE category:ASN1_CATEGORY_COMPOSITE];
    
    ASN1Composite *algorithm=[ASN1Composite asn1Composite];
    [algorithm setClass:ASN1_CLASS_UNIVERSAL type:ASN1_TYPE_SEQUENCE category:ASN1_CATEGORY_COMPOSITE];
    
    ASN1Primative *signatureAlgorithms=[ASN1Primative asn1PrimativeWithOID:@"1.2.840.113549.1.1.1"];

    ASN1Primative *nullPrimative=[ASN1Primative asn1PrimativeWithNull];

    ASN1Primative *data=[ASN1Primative asn1PrimativeWithBitString:publicKeyData];
    
    [algorithm addObject:signatureAlgorithms];
    [algorithm addObject:nullPrimative];
    
    [publicKeyWrapper addObject:algorithm];
    [publicKeyWrapper addObject:data];
    
    NSData *wrappedPublicKeyData=[ASN1Utilities encodeASN1:publicKeyWrapper useINF:NO];

    return wrappedPublicKeyData;
}

+(NSData *)wrappedSignature:(NSData *)inSignature{
    
    
    ASN1Composite *wrappedSignature=[ASN1Composite asn1Composite];
    [wrappedSignature setClass:ASN1_CLASS_UNIVERSAL type:ASN1_TYPE_SEQUENCE category:ASN1_CATEGORY_COMPOSITE];
    
    ASN1Composite *algorithm=[ASN1Composite asn1Composite];
    [algorithm setClass:ASN1_CLASS_UNIVERSAL type:ASN1_TYPE_SEQUENCE category:ASN1_CATEGORY_COMPOSITE];
    
    ASN1Primative *signatureAlgorithms=[ASN1Primative asn1PrimativeWithOID:@"2.16.840.1.101.3.4.2.3"];
    
    ASN1Primative *nullPrimative=[ASN1Primative asn1PrimativeWithNull];
    
    ASN1Primative *data=[ASN1Primative asn1PrimativeWithOctetString:inSignature];
    
    [algorithm addObject:signatureAlgorithms];
    [algorithm addObject:nullPrimative];
    
    [wrappedSignature addObject:algorithm];
    [wrappedSignature addObject:data];
    
    NSData *wrappedSignatureData=[ASN1Utilities encodeASN1:wrappedSignature useINF:NO];
    
    return wrappedSignatureData;
}



+(int)importNewP12AtURL:(NSURL *)inURL withPassword:(NSString *)password{
    NSFileManager *fileManager = [NSFileManager defaultManager];

    CFArrayRef retArray;
    NSData *inID=[[NSData alloc] initWithContentsOfURL:inURL];

    OSStatus status=SecPKCS12Import((CFDataRef)inID,(CFDictionaryRef)[NSDictionary dictionaryWithObject:password forKey:(id)kSecImportExportPassphrase],
                                    &retArray);
    
    
    if (status !=0) return -1;
    for (NSDictionary * itemDict in (__bridge id) retArray) {
        SecIdentityRef  identity;
        
        assert([itemDict isKindOfClass:[NSDictionary class]]);
        
        identity = (__bridge SecIdentityRef) [itemDict objectForKey:(NSString *) kSecImportItemIdentity];
        assert(identity != NULL);
        assert( CFGetTypeID(identity) == SecIdentityGetTypeID() );
        SecKeyRef privateKeyRef;
        OSStatus err=SecIdentityCopyPrivateKey (
                                                identity,
                                                &privateKeyRef
                                                );
        
        if (err !=noErr) {
            NSLog(@"SecIdentityCopyPrivateKey error");
            return -1;
        }
        
        
        size_t keySize=SecKeyGetBlockSize (privateKeyRef)*8;
        
        if (keySize>2048) {
//            UIAlertView *alert=[[[UIAlertView alloc] initWithTitle:@"Import Error"
//                                                           message:@"Your identity has RSA keys greater than 2048 bits, which is not supported" delegate:nil cancelButtonTitle:@"OK" otherButtonTitles:nil] autorelease];
//            [alert show];
            return -2;
            
        }
        
        
        err = SecItemAdd(
                         (CFDictionaryRef) [NSDictionary dictionaryWithObjectsAndKeys:
                                            (__bridge id) identity,              kSecValueRef,
                                            kSecAttrAccessibleWhenUnlocked,kSecAttrAccessible,
                                            nil
                                            ],
                         NULL
                         );
        if (err == errSecDuplicateItem) {
            err = noErr;
        }
        
        if (err != noErr) {
            return -3;
        }
    }
    [fileManager removeItemAtURL:inURL error:nil];
    return 0;
}

+(void)installCertificateToKeychain:(NSData *)inCert error:(NSError **)returnErr{
    SecCertificateRef cert = SecCertificateCreateWithData(NULL, (CFDataRef) inCert);
    SecKeychainRef keychain_ref;
    int verbose=1;
    char *keychain_path=NULL;
    if (!keychain_path) {
        struct passwd *pw = getpwuid(getuid());
        assert(pw);
        
        NSString *loginKeychain=[NSString stringWithFormat:@"%s/Library/Keychains/login.keychain-db",pw->pw_dir];
        if (![[NSFileManager defaultManager] fileExistsAtPath:loginKeychain]) {
            fprintf(stderr,"Keychain does not exists at %s. Checking for legacy keychain.\n",[loginKeychain UTF8String]);
            loginKeychain=[NSString stringWithFormat:@"%s/Library/Keychains/login.keychain",pw->pw_dir];
            
            if (![[NSFileManager defaultManager] fileExistsAtPath:loginKeychain]) {
                fprintf(stderr,"Keychain does not exists at %s\n",[loginKeychain UTF8String]);

                return;
            }
                
        }
        keychain_path=malloc(PATH_MAX);
        sprintf(keychain_path,"%s",[loginKeychain UTF8String]);
    }
    if (verbose) fprintf(stderr,"Opening keychain %s\n",keychain_path);
    
    SecKeychainOpen(keychain_path, &keychain_ref);
    CFStringRef keys[3];
    CFStringRef values[3];
    CFDictionaryRef aDict;

    
    keys[0] = kSecValueRef;
    keys[1] = kSecClass;
    keys[2]=kSecUseKeychain;
    values[0] = (CFStringRef) cert;
    values[1] = kSecClassCertificate;
    values[2]=(CFStringRef)keychain_ref;
    
    aDict=CFDictionaryCreate(NULL, (const void **)keys, (const void **)values, 3, &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    OSStatus status =SecItemAdd(aDict,NULL );
    
    if (status != errSecSuccess) {
        *returnErr=[NSError errorWithDomain:@"TCSError" code:100 userInfo:@{@"ErrorMessage":@"Certificate not saved in keychain"}];
        
    }
    
}
-(int)importNewP12sWithPassword:(NSString *)password{
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    
    NSError *err=nil;
    NSString *userDocumentsPath = [paths objectAtIndex:0];
    NSArray *files=[fileManager contentsOfDirectoryAtPath:userDocumentsPath error:&err];
    
    if ([files count] > 0) {
        
        for (NSString *currPath in files) {

            if ((![@"p12" isEqualToString:[currPath pathExtension]])&&
                (![@"pfx" isEqualToString:[currPath pathExtension]]))
                continue;
            
            NSURL *p12URL=[NSURL fileURLWithPath:[userDocumentsPath stringByAppendingPathComponent:currPath]];
            [TCSecurity importNewP12AtURL:p12URL withPassword:password];
        }
    }
    return 0;
}
-(NSArray *)p12sAtPath:(NSURL *)inURL{
    NSMutableArray *returnArray=[NSMutableArray array];
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSError *err;
    
    
    NSArray *files=[fileManager contentsOfDirectoryAtPath:[inURL path] error:&err];
    
    
    for (NSString *currPath in files) {
        
        if ((![@"p12" isEqualToString:[currPath pathExtension]])&&
            (![@"pfx" isEqualToString:[currPath pathExtension]]))
            continue;
        
        [returnArray addObject:currPath];
        
    }
    return [NSArray arrayWithArray:returnArray];
}
-(NSArray *)cerAtPath:(NSURL *)inURL{
    NSMutableArray *returnArray=[NSMutableArray array];
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSError *err;
    
    
    NSArray *files=[fileManager contentsOfDirectoryAtPath:[inURL path] error:&err];
    
    for (NSString *currPath in files) {
        
        if (![@"cer" isEqualToString:[currPath pathExtension]])
            continue;
        
        [returnArray addObject:currPath];
        
    }
    return [NSArray arrayWithArray:returnArray];
}
+(NSData *)wrappedPublicKeyFromSecKeyRef:(SecKeyRef)inPublicKey{
    
    CFDataRef returnData;
    
    SecItemImportExportKeyParameters params;
    
    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    params.flags = 0; // See SecKeyImportExportFlags for details.
    params.passphrase = NULL;
    params.alertTitle = NULL;
    params.alertPrompt = NULL;
    params.accessRef = NULL;
    
    /* These two values are for import. */
    params.keyUsage = NULL;
    params.keyAttributes = NULL;
    CFMutableArrayRef keyUsage = CFArrayCreateMutable(
                                                      kCFAllocatorDefault,
                                                      0,
                                                      &kCFTypeArrayCallBacks
                                                      );
    
    
    CFMutableArrayRef keyAttributes = CFArrayCreateMutable(
                                                           kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks
                                                           );

    params.keyUsage = keyUsage;
    params.keyAttributes = keyAttributes;
    SecExternalFormat externalFormat = kSecFormatOpenSSL;
    int flags = 0;
    
    
    OSStatus oserr = SecItemExport(inPublicKey,
                                   externalFormat, // See SecExternalFormat for details
                                   flags, // See SecItemImportExportFlags for details
                                   &params,
                                   (CFDataRef *)&returnData);//    if (oserr) {
    if (oserr) {
        return nil;
    }
    return CFBridgingRelease(returnData);
    
}
+(NSData *)generatePublicKeyFromPrivateKey:(SecKeyRef)privateKey{
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    
    NSData *publicKeyData=[TCSecurity wrappedPublicKeyFromSecKeyRef:publicKey];
    CFRelease(publicKey);
    return publicKeyData;

    
}
+(SecKeyRef)generatePrivateKeyWithIdentifer:(NSString *)inIdentifer{
    NSData* tag = [inIdentifer dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary* attributes =
    @{ (id)kSecAttrKeyType:               (id)kSecAttrKeyTypeRSA,
       (id)kSecAttrKeySizeInBits:         @2048,
       (id)kSecPrivateKeyAttrs:
           @{ (id)kSecAttrIsPermanent:    @YES,
              (id)kSecAttrApplicationTag: tag
              },
       };

    CFErrorRef error = NULL;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes,
                                                 &error);
    if (!privateKey) {
        
        fprintf(stderr,"error creating private key\n");
        return nil;
    }
    
//    NSData* keyData = (NSData*)CFBridgingRelease(  // ARC takes ownership
//                                                 SecKeyCopyExternalRepresentation(privateKey, &error)
//                                                 );

    
    return privateKey;

}
+(void)addKeyToKeychain:(SecKeyRef)inKey withLabel:(NSString *)inLabel{
    
    
    NSData* tag = [inLabel dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary* addquery = @{ (id)kSecValueRef: (__bridge id)inKey,
                                (id)kSecClass: (id)kSecClassKey,
                                (id)kSecAttrApplicationTag: tag,
                                };
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addquery, NULL);
    if (status != errSecSuccess) {
        
    }
    else                         {
        
    }

}

+ (NSData *)signBytes:(NSData *)inData withPrivateKey:(SecKeyRef)privateKey {
    
    CFErrorRef error;
    /* Create the transform objects */
    SecTransformRef signer = SecSignTransformCreate(privateKey, &error);
    if (error) { CFShow(error); exit(-1); }
    
    SecTransformSetAttribute(
                             signer,
                             kSecTransformInputAttributeName,
                             (CFTypeRef)inData,
                             &error);
    if (error) { CFShow(error); exit(-1); }

    SecTransformSetAttribute(
                             signer,
                             kSecDigestTypeAttribute,
                             kSecDigestSHA2,
                             &error);
    if (error) { CFShow(error); exit(-1); }
    
    SecTransformSetAttribute(
                             signer,
                             kSecDigestLengthAttribute,
                             (__bridge CFNumberRef)@512,
                             &error);
    if (error) { CFShow(error); exit(-1); }


    
   CFDataRef signature  = SecTransformExecute(signer, &error);
    CFRelease(signer);
    if (error) { CFShow(error); exit(-1); }
    
    if (!signature) {
        fprintf(stderr, "Signature is NULL!\n");
        exit(-1);
    }
    return CFBridgingRelease(signature);
    
}


+ (NSData *)sha512:(NSData *)data {
    unsigned char hash[CC_SHA512_DIGEST_LENGTH];
    
    if ( CC_SHA512([data bytes], (unsigned int)[data length], hash) ) {
        NSData *sha512= [NSData dataWithBytes:hash length:CC_SHA512_DIGEST_LENGTH];
        return sha512;
    }
    return nil;
    
}


@end
