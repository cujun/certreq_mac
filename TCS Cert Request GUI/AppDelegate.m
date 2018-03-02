    //
//  AppDelegate.m
//  SimpleCSRRequest
//
//  Created by Tim Perfitt on 2/19/18.
//  Copyright © 2018 Twocanoes Software. All rights reserved.
//

#import "AppDelegate.h"
#import "CertificateSigningRequest.h"
#import "TCSCertificateRequest.h"
#import "TCSYubiManager.h"
#import "TCSADCertificateRequest.h"
#define TCSDEVICEKEYCHAIN 0
#define TCSDEVICEYUBIKEY 1

@interface AppDelegate ()

@property (weak) IBOutlet NSWindow *window;
@property (nonatomic, assign) NSInteger certificateDeviceSelected;
@property (nonatomic, assign) BOOL generateCSRButtonEnabled;


@end

@implementation AppDelegate

- (IBAction)csrTypeRadioButtonPressed:(id)sender {
    self.certificateDeviceSelected=[sender tag];
    self.generateCSRButtonEnabled=YES;
    
}
-(NSData *)generateCSRFromYubikey:(id)sender{
    
    if (!self.commonName || [self.commonName isEqualToString:@""]) {
        
        self.commonName=@"TCSCertificate";
    }
    TCSYubiManager *ym=[TCSYubiManager sharedManager];
    [ym authenticateWithManagementKey:
     self.yubikeyManagementKey];
    NSData *publicKey=[ym generateKeyInSlot:self.yubikeySlot];
    if (!publicKey) {
        fprintf(stderr,"public key not generated!\n");
        return nil;
    }


    CertificateSigningRequest *signingRequest=[[CertificateSigningRequest alloc] initWithPublicKey:publicKey commonName:@"test"];
    
    NSData *dataToSign=[signingRequest messageToSign];
    if (!dataToSign) {
        NSLog(@"could not get message to sign");
        return nil;
    }
    NSData *signatureData=[[TCSYubiManager  sharedManager] signBytes:dataToSign withYubiKeySlot:self.yubikeySlot];
   
    if (!signatureData) {
        NSLog(@"could not get signature data");
        return nil;
    }
    signingRequest.signatureData=signatureData;
    
    NSData *csr=[signingRequest certificateSigningRequest];
    
    return csr;

}
-(NSData *)generateCSRFromKeychain:(id)sender{
    
    if (!self.commonName || [self.commonName isEqualToString:@""]) {
        
        self.commonName=@"TCSCertificate";
    }
    SecKeyRef privateKeyRef=[TCSecurity generatePrivateKeyWithIdentifer:@"TCSCertficateSigningRequest"];
    NSData *publicKey=[TCSecurity generatePublicKeyFromPrivateKey:privateKeyRef];

    
    CertificateSigningRequest *signingRequest=[[CertificateSigningRequest alloc] initWithPublicKey:publicKey commonName:@"test"];
    
    NSData *dataToSign=[signingRequest messageToSign];
    if (!dataToSign) {
        NSLog(@"could not get message to sign");
        return nil;
    }

    NSData *signatureData=[TCSecurity signBytes:dataToSign withPrivateKey:privateKeyRef];

    if (!signatureData) {
        NSLog(@"could not get signature data");
        return nil;
    }
    signingRequest.signatureData=signatureData;
    
    NSData *csr=[signingRequest certificateSigningRequest];
    
    return csr;
    
}

- (IBAction)generateCSR:(id)sender {
    NSData *csr=nil;
    if (self.certificateDeviceSelected==TCSDEVICEYUBIKEY) {
        csr=[self generateCSRFromYubikey:self];
    }
    else if (self.certificateDeviceSelected==TCSDEVICEKEYCHAIN) {
        
        csr=[self generateCSRFromKeychain:self];
    }
    else {
        
        return ;
    }
    
    if (!csr) {
        NSAlert *alert = [[NSAlert alloc] init];
        [alert addButtonWithTitle:@"OK"];
        
        [alert setMessageText:@"Certificate Generation Error"];
        [alert setInformativeText:@"Could not create certificate signing request.  Please check log."];
        [alert runModal];
        
        NSLog(@"Could not not generate CSR");
        
        return;
    }
    
    TCSADCertificateRequest *request=[[TCSADCertificateRequest alloc] initWithServerName:@"WIN-FGIVT3J3GI9.twocanoes.com" certificateAuthorityName:@"TCSCA" certificateTemplate:@"User" verbose:NO error:nil];
    
    NSError *err;
    [request submitRequestToActiveDirectoryWithCSR:csr error:&err];
    if (err) {
        NSAlert *alert = [[NSAlert alloc] init];
        [alert addButtonWithTitle:@"OK"];
        
        [alert setMessageText:@"Certificate Generation Error"];
        [alert setInformativeText:[err.userInfo objectForKey:@"Error"]];
        [alert runModal];
        

        
    }
}
//    NSSavePanel *panel = [NSSavePanel savePanel];
//    panel.allowedFileTypes = @[@"csr"];
    
//    [panel beginSheetModalForWindow:self.window completionHandler:^(NSInteger result){
//        if (result == NSModalResponseOK)
//        {
//            NSURL*  theFile = [panel URL];
//            [csr writeToURL:theFile atomically:NO];
//
//        }
//    }];


- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    
}


- (void)applicationWillTerminate:(NSNotification *)aNotification {
}


@end
