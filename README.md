TCSCertificateRequest is a macOS framework to generate a CSR using native security APIs only.  To use:

1.  Add framework to your project
2.  Add a copy script in Build Phases and copy the framework to your application bundle under Frameworks
3.  Add in the following code to generate a CSR:
~~~~
#import "CertificateSigningRequest.h"
#import "TCSCertificateRequest.h"


SecKeyRef privateKeyRef=[TCSecurity generatePrivateKeyWithIdentifer:@"TCSCertficateSigningRequest"];
NSData *publicKey=[TCSecurity generatePublicKeyFromPrivateKey:privateKeyRef];
NSData *csr=[CertificateSigningRequest createCertificateSigningRequestWithCommonName:@"test" publicKey:publicKey privateKey:privateKeyRef];

~~~~
Current limitations:
The private key is always saved to the user keychain.
The hashing algorithm supported is only SHA512 and only RSA is supported.

