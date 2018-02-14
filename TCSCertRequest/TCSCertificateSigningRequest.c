//
//  TCSCertificateSigningRequest.c
//  SignHelp
//
//  Created by Tim Perfitt on 2/11/18.
//  Copyright © 2018 Twocanoes Software. All rights reserved.
//

#include "TCSCertificateSigningRequest.h"


int generate_csr(char *csr,unsigned int *csr_size,char * in_label,char *keychain_path,algorithm_type in_algorithm_type, key_size in_key_size,key_usage in_key_usage,algorithm in_algorithm,char * in_challenge_string,char *in_common_name, char * in_country, char * in_organization, char *in_organization_unit, char *in_state,char *in_email){
    
    
    char label[255];
    char algorithm_type[2];
    char key_size[5];
    char key_usage[2];
    char algorithm[2];
    char challenge_string[255];
    char common_name[255];
    char country[3];
    char organization[255];
    char organization_unit[255];
    char state[3];
    char email[255];
    
    if (!in_label || strlen(in_label)==0) {
        strncpy(label, "", 0);
        
    }
    else {
        strncpy(label, in_label, 255);
        
    }
    
    
    switch (in_algorithm_type) {
        case algorithm_type_RSA:
            strlcpy(algorithm_type, "r", 2);
            break;
            //        case algorithm_type_DSA:
            //            strlcpy(algorithm_type, "d", 2);
            //
            //            break;
            //        case algorithm_type_FEE:
            //            strlcpy(algorithm_type, "f", 2);
            //
            //            break;
            //        case algorithm_type_ECDSA:
            //
            //            strlcpy(algorithm_type, "e", 2);
            //            break;
        default:
            break;
    }
    
    switch (in_key_size) {
        case key_size_1024:
            strlcpy(key_size, "1024", 5);
            break;
        case key_size_2048:
            strlcpy(key_size, "2048", 5);
            break;
            
        default:
            break;
    }
    
    
    switch (in_key_usage) {
        case key_usage_sign:
            strlcpy(key_usage, "s", 2);
            break;
        case key_usage_signing_encrypting:
            strlcpy(key_usage, "b", 2);
            
            break;
        case key_usage_derive_sign:
            strlcpy(key_usage, "d", 2);
            
            break;
            
        default:
            break;
    }
    
    switch (in_algorithm) {
        case algorithm_sha1:
            strlcpy(algorithm, "s", 2);
            break;
        case algorithm_sha256:
            strlcpy(algorithm, "2", 2);
            break;
        case algorithm_sha348:
            strlcpy(algorithm, "3", 2);
            break;
        case algorithm_sha512:
            strlcpy(algorithm, "5", 2);
            break;
            
        default:
            break;
    }
    
    if (!in_challenge_string) strlcpy(challenge_string, "", 1);
    else strlcpy(challenge_string,in_challenge_string,255);
    
    if (!in_common_name) strlcpy(common_name, "", 1);
    else strlcpy(common_name,in_common_name,255);
    
    if (!in_country) strlcpy(country, "", 1);
    else strlcpy(country,in_country,3);
    
    
    if (!in_organization) strlcpy(organization, "", 1);
    else strlcpy(organization,in_organization,255);
    
    if (!in_organization_unit) strlcpy(organization_unit, "", 1);
    else strlcpy(organization_unit,in_organization_unit,255);
    
    if (!in_state) strlcpy(state, "", 1);
    else strlcpy(state,in_state,3);
    
    if (!in_email) strlcpy(email, "", 1);
    else strlcpy(email,in_email,255);
    
    
    char command_string[2048];
    
    snprintf(command_string, 2048,"%s\n%s\n%s\ny\n%s\n%s\ny\n%s\n%s\n%s\n%s\n%s\n%s\n%s\ny\n",
             label,
             algorithm_type,
             key_size,
             key_usage,
             algorithm,
             challenge_string,
             common_name,
             country,
             organization,
             organization_unit,
             state,
             email);
    
    pid_t child_pid;
    int fd[2];
    pipe(fd);
    
    char *args[6];
    char template[] = "/tmp/tmpdir.XXXXXX";
    char *tmp_dirname = mkdtemp (template);
    char temp_file[2048];
    sprintf(temp_file, "%s/signing_request.csr",tmp_dirname);
    
    args[0]="/usr/bin/certtool";
    args[1]="r";
    args[2]=temp_file;
    args[3]="d";
    if (keychain_path) {
        args[4]=malloc(PATH_MAX);
        sprintf(args[4],"k=%s",keychain_path);
        args[5]=NULL;
    }
    else {
        args[4]=NULL;
    }

    
    child_pid=fork();
    
    if (child_pid==0) {
        
        
        dup2(fd[0],STDIN_FILENO);
        close(fd[0]);
        close(fd[1]);
        close(STDOUT_FILENO);
        execvp("/usr/bin/certtool", args);
        
        
        printf("invalid command\n");
        return -1;
        
    }
    close(fd[0]);
    FILE *pipe_in;
    pipe_in=fdopen(fd[1], "w");
    
    fprintf(pipe_in,"%s",command_string);  //send command
    fflush(pipe_in);
    fclose(pipe_in);
    wait(0);
    
    struct stat st;
    if (stat(temp_file,&st)) {
        
        perror("certificate file error");
    }
    long long size = st.st_size;
    if (size>10*1024) {  //limit to 10k, though should be much smaller
        fprintf(stderr,"bad filesize\n");
        return -1;
    }
    

    FILE *file=fopen(temp_file, "r");
    
    if (file != NULL)
    {
        unsigned long bytesread=fread(csr, 1, size, file);
        if (bytesread!=size){
            fprintf(stderr,"error reading cert\n");
            return -1;
        }
        
    }
    *csr_size=(unsigned int)size;
    
    return 0;
}
