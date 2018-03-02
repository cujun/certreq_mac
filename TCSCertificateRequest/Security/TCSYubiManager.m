//
//  TCSYubiManager.m
//  TCSCertificateRequest
//
//  Created by Tim Perfitt on 2/24/18.
//  Copyright © 2018 Twocanoes Software. All rights reserved.
//

#import "TCSYubiManager.h"
#import "ykpiv-version.h"
#import "ykpiv.h"
#import "internal.h"
#import <PCSC/pcsclite.h>
#import <PCSC/winscard.h>
#import <PCSC/wintypes.h>
#import "TCSecurity.h"
#import "ASN1Composite.h"
#import "ASN1Primative.h"
#import "ASN1Utilities.h"
extern  int RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen,
                                         unsigned char *f, int fl);

@interface TCSYubiManager()

@property   (nonatomic,assign) ykpiv_state *state;

@end
@implementation TCSYubiManager

+ (id)sharedManager
{
    static dispatch_once_t p = 0;
    
    __strong static id _sharedObject = nil;
    
    dispatch_once(&p, ^{
        _sharedObject = [[self alloc] init];
    });
    
    return _sharedObject;
}

- (NSData *)signBytes:(NSData *)inData withYubiKeySlot:(NSString *)slot {
    
    int keyLength=2048;
    int signedDataSize=256;
    unsigned char sign_out[keyLength];
    size_t out_len=keyLength;
    int algorithm=YKPIV_ALGO_RSA2048;
    int slotNumber=[self slotFromString:slot];
    
    unsigned char *signinput=(unsigned char*)calloc(keyLength, 1);
    
    NSData *hashed=[TCSecurity sha512:inData];
    
   NSData *wrappedSignature=[TCSecurity wrappedSignature:hashed];
    
    if(RSA_padding_add_PKCS1_type_1(signinput, signedDataSize, (unsigned char *)[wrappedSignature bytes], (int)wrappedSignature.length) == 0) {
        fprintf(stderr, "Failed adding padding.\n");
        return false;
    }
    
    ykpiv_rc rc3;
    
    if((rc3=ykpiv_sign_data(_state,signinput, signedDataSize, sign_out, &out_len, algorithm, slotNumber)) == YKPIV_OK) {
        
        return [NSData dataWithBytes:sign_out length:signedDataSize];
    }
    
    
    return nil;
    
    
}
-(BOOL)installCertificate:(NSData *)inCert intoSlot:(NSString *)inSlot{
    
    ykpiv_rc rc=ykpiv_util_write_cert(self.state, [self slotFromString:inSlot], (uint8_t *)[inCert bytes], inCert.length,YKPIV_CERTINFO_UNCOMPRESSED );
    
    if (rc!=0) return NO;
    return YES;
    
}
-(int)slotFromString:(NSString *)inSlot{
    unsigned int slotNumber;
    NSScanner* scanner = [NSScanner scannerWithString:inSlot];
    [scanner scanHexInt:&slotNumber];
    return slotNumber;
    

}
-(NSData *)generateKeyInSlot:(NSString *)slot{
    
    uint8_t *modulus=NULL;
    uint8_t *exp=NULL;
    size_t modulus_len=0;
    size_t exp_len=0;
    uint8_t *point=NULL;
    size_t point_len=0;
    ykpiv_rc rc;
    int slotNumber=[self slotFromString:slot];


    if((rc=ykpiv_util_generate_key(_state, slotNumber , YKPIV_ALGO_RSA2048 , YKPIV_PINPOLICY_NEVER, YKPIV_TOUCHPOLICY_NEVER, &modulus, &modulus_len, &exp, &exp_len, &point, &point_len))){
        
        fprintf(stderr,"Could not generate key in slot %i. Error %i",slotNumber,rc);
        return nil;
        
    }
    
    NSData *modulusData=[NSData dataWithBytes:modulus length:modulus_len];
    NSData *exponentData=[NSData dataWithBytes:exp length:exp_len];
    
    NSData *wrappedPublicKey=[TCSecurity wrappedPublicKeyFromModulus:modulusData andExponent:exponentData];
        
    return wrappedPublicKey;

}
-(BOOL)authenticateWithManagementKey:(NSString *)inKey{
    
    _state=malloc(sizeof(_state));
    ykpiv_init(&_state, 1);

    if(ykpiv_init(&_state, 1) != YKPIV_OK) {
        fprintf(stderr, "Failed initializing library.\n");
        return NO;
    }
    if(ykpiv_connect(_state, "") != YKPIV_OK) {
        fprintf(stderr, "Failed to connect to reader.\n");
        return NO;
    }
    unsigned char key[256];
    size_t key_len = sizeof(key);
    
    const char *key_ptr=[inKey UTF8String];
    
    if(ykpiv_hex_decode(key_ptr, inKey.length, key, &key_len) != YKPIV_OK) {
        fprintf(stderr, "Failed decoding key!\n");
        return NO;
    }
    ykpiv_rc rc2;
    if((rc2=ykpiv_authenticate(_state, key)) != YKPIV_OK) {
        fprintf(stderr, "Failed authentication with the application.\n");
        return NO;
    }
    
    return YES;
}
-(void)yubitest{
    ykpiv_state *state;
    if(ykpiv_init(&state, 0) != YKPIV_OK) {
        fprintf(stderr, "Failed initializing library.\n");
        return ;
    }
    
    char readers[2048];
    char *reader_ptr;
    size_t len = sizeof(readers);
    ykpiv_rc rc = ykpiv_list_readers(state, readers, &len);
    if(rc != YKPIV_OK) {
        fprintf(stderr, "Failed listing readers.\n");
        return ;
    }
    for(reader_ptr = readers; *reader_ptr != '\0'; reader_ptr += strlen(reader_ptr) + 1) {
        printf("%s\n", reader_ptr);
    }
    return ;
}
-(void)dealloc{
 
    if (_state) free(_state);
    
}
@end
