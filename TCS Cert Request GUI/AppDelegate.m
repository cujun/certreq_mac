    //
//  AppDelegate.m
//  SimpleCSRRequest
//
//  Created by Tim Perfitt on 2/19/18.
//  Copyright © 2018 Twocanoes Software. All rights reserved.
//

#import "AppDelegate.h"
#import "TCSCertificateRequest.h"
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
