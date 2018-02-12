//
//  TCSCertificateSigningRequest.h
//  SignHelp
//
//  Created by Tim Perfitt on 2/11/18.
//  Copyright © 2018 Twocanoes Software. All rights reserved.
//

#ifndef TCSCertificateSigningRequest_h
#define TCSCertificateSigningRequest_h

#include <stdio.h>

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>

typedef int algorithm_type ;
typedef int key_size ;
typedef int key_usage;
typedef int algorithm;


//enum algorithm_type {
//    algorithm_type_RSA,
//    algorithm_type_DSA,
//    algorithm_type_FEE,
//    algorithm_type_ECDSA
//
//};
enum algorithm_type {
    algorithm_type_RSA,
    
};


enum key_size {
    key_size_1024,
    key_size_2048
    
};

enum key_usage{
    key_usage_sign,
    key_usage_signing_encrypting,
    key_usage_derive_sign
};

enum algorithm{
    algorithm_sha1,
    algorithm_sha256,
    algorithm_sha348,
    algorithm_sha512
};

int generate_csr( char *csr,unsigned int *csr_size,char * in_label,algorithm_type in_algorithm_type, key_size in_key_size,key_usage in_key_usage,algorithm in_algorithm,char * in_challenge_string,char *in_common_name, char * in_country, char * in_organization, char *in_organization_unit, char *in_state,char *in_email);
#endif /* TCSCertificateSigningRequest_h */
