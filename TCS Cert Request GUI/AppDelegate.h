//
//  AppDelegate.h
//  SimpleCSRRequest
//
//  Created by Tim Perfitt on 2/19/18.
//  Copyright © 2018 Twocanoes Software. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface AppDelegate : NSObject <NSApplicationDelegate>

@property (nonatomic, retain) NSString *keychainLabel;
@property (nonatomic, retain) NSString *commonName;
@property (nonatomic, retain) NSString *yubikeySlot;
@property (nonatomic, retain) NSString *yubikeyManagementKey;


@end


