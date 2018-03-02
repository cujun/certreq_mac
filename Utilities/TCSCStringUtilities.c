//
//  TCSCStringUtilities.c
//  TCSCertificateRequest
//
//  Created by Tim Perfitt on 2/27/18.
//  Copyright © 2018 Twocanoes Software. All rights reserved.
//

#include "TCSCStringUtilities.h"
#import <CoreFoundation/CoreFoundation.h>
void c_to_utf16(char *in,char *out,int *outlength) {
    CFStringRef cfstring=CFStringCreateWithCString (
                                                    NULL,
                                                    in,
                                                    kCFStringEncodingASCII
                                                    );
    
    CFDataRef string_data=CFStringCreateExternalRepresentation (
                                                                NULL,
                                                                cfstring,
                                                                kCFStringEncodingUTF16LE,
                                                                '?'
                                                                );
    
    
    CFDataGetBytes ( string_data,
                    CFRangeMake(0,CFDataGetLength(string_data)),
                    (unsigned char *)out
                    );
    
    
    
    
    *outlength=(int)CFDataGetLength(string_data);
    CFRelease(string_data);
    CFRelease(cfstring);
    
}
