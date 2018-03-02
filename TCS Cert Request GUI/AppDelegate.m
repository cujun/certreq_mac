    //
//  AppDelegate.m
//  SimpleCSRRequest
//
//  Created by Tim Perfitt on 2/19/18.
//  Copyright © 2018 Twocanoes Software. All rights reserved.
//

#import "AppDelegate.h"
#import "TCSCertificateRequest.h"
#import "TCSCertAppHelper.h"
#define TCSDEVICEKEYCHAIN 0
#define TCSDEVICEYUBIKEY 1

@interface AppDelegate ()
@property (nonatomic, strong) NSString *certAuthorityDNSName;
@property (nonatomic, strong) NSString *certAuthorityName;
@property (nonatomic, strong) NSString *certAuthorityTemplate;

@property (weak) IBOutlet NSWindow *window;
@property (nonatomic, assign) NSInteger certificateDeviceSelected;
@property (nonatomic, assign) BOOL generateCSRButtonEnabled;


@end

@implementation AppDelegate

- (IBAction)csrTypeRadioButtonPressed:(id)sender {
    self.certificateDeviceSelected=[sender tag];
    self.generateCSRButtonEnabled=YES;
    
}

- (IBAction)generateCSR:(id)sender {
    NSData *csr=nil;
    NSError *err;
    if (self.certificateDeviceSelected==TCSDEVICEYUBIKEY) {
        csr=[TCSCertAppHelper generateCSRFromYubikeyWithManagementKey:_yubikeyManagementKey inSlot:_yubikeySlot commonName:self.commonName error:&err];
    }
    else if (self.certificateDeviceSelected==TCSDEVICEKEYCHAIN) {
        
        csr=[TCSCertAppHelper generateCSRFromKeychainWithCommonName:self.commonName error:&err];
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
    
        TCSADCertificateRequest *request=[[TCSADCertificateRequest alloc] initWithServerName:self.certAuthorityDNSName certificateAuthorityName:self.certAuthorityName certificateTemplate:self.certAuthorityTemplate verbose:NO error:nil];

    
    
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
