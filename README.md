# README #

tcscertrequest is a command line tool to send a certificate request via RPCs to a Microsoft certificate authority.
compiling requires the dce idl compiler at http://www.dcerpc.org/source/ installed at /usr/local/bin/dceidl 

Note: You do not need to compile the framework with "xcodebuild -configuration Debug -target DCERPC".  tcscertrequest just requires the idl compiler and the framework is included in PrivateFrameworks on macOS.

see blog post at :  https://twocanoes.com/origin-backstory-of-active-directory-certificate-profile-at-apple/

Using the **_tcscertrequest_** Command Line Tool
------------------------------------------------

I was thinking about the DCE/RPC configuration profile  project recently,and wondered if macOS 10.13 could make the same API call to a Windows Server 2016 Certificate Authority.

Using the same process I’d done back in 2011, I compiled the interface and created a new tool called _tcscertrequest_. I set up a Microsoft Certificate Authority and Active Directory. I did not enable the Web CA since it is not required for requesting certificates over DCE/RPC.

To use the _tcscertrequest_ tool, a certificate signing request is needed, as well as the DNS name of the MS Certificate Authority, the name of the Certificate Authority, and the name of the template in the Microsoft Certificate Authority.

A template is a collection of settings that tells the MS CA what information to include in the certificate and who is allowed to submit the request. The Microsoft CA has preconfigured templates, and the ones most commonly used are User and Computer.  The User template is commonly used for certificate-based authentication via Smart Cards and websites. The Computer template is commonly used for 802.1X certificate-based authentication and other services that the computer authenticates to.  Here is what the templates look like in the Microsoft Certificate Authority:

![](https://xdl4wtzciw-flywheel.netdna-ssl.com/wp-content/uploads/2018/02/authcert-1024x471.png)

The most common templates are _Computer_ or _User_. When a request is submitted to the Certificate Authority, the request specifies a template that the CA uses to determine what information to populate in the certificate that is generated. The template also specifies what type of user is allowed to use that template to generate a certificate. A Computer template usually requires a kerberos ticket from the machine credentials, and the User template usually requires a kerberos ticket from an Active Directory User.

The syntax to use when the _tcscertrequest_ tool is called is:

tcscertrequest -r <csr path> -s <server dns name> -c <name of ca> \
-w <output file path> -t <template name>

tcscertrequest -r <csr path> -s <server dns name> -c <name of ca> -w <output file path> -t <template name>  
  
The best way to illustrate how to use the _tcscertrequest_ tool is with some examples. I’ll show two examples below: One with machine credentials and one with a user credentials. You don’t need to be bound to Active Directory to use this tool, but binding does make it easy to get kerberos tickets. For these examples, the test Mac will be bound to Active Directory.

### Example 1: Computer Certificate

The first example shows how to get a computer certificate. The first step is to get a kerberos ticket with the machine credentials (in this example, the Mac is named _MachPower_):

MachPower:~ tperfitt$ sudo kinit -k machpower$

Now the kerberos ticket can be viewed using the klist command to see that a Kerberos Ticket Granting Ticket (TGT) has been issued:

MachPower:~ tperfitt$ klist

Credentials cache: API:3FB02FDF-608F-4548-AFEC-85BFFBF4E073
Principal: machpower$@TWOCANOES.COM
Issued                Expires               Principal
Jan 27 22:53:33 2018  Jan 28 08:53:33 2018  krbtgt/TWOCANOES.COM@TWOCANOES.COM

Next, a certificate signing request is needed. There are many ways to do this on the Mac, but a simple way is to use the OpenSSL command line tool. The Computer template requires that the common name, or CN, match the computer name in the certificate, so that must be included in the signing request using the “subj” command line argument. The format of the CSR is expected to be DER (binary version). The CSR doesn’t need to be encrypted with a password, so the “nodes” option will be specified. Finally, the options to save the certificate in a file called twocanoes.csr and the private key to a file named twocanoes.key will be given.

Here is what the final command looks like:

MachPower:~ tperfitt$ openssl req -nodes -newkey rsa:2048 \
-keyout twocanoes.key -out twocanoes.csr -subj '/CN=machpower' -outform der
Generating a 2048 bit RSA private key
.................+++
.............+++
writing new private key to 'twocanoes.key' 

Now that the kerberos credentials have been received and a signing request has been generated, the CSR can be submitted to the Windows Certificate Authority. As mentioned earlier, the Common Name of the Certificate Authority (tcsca in this example) must be given along with the Certificate Authority Server DNS name (win-fgivt3j3gi9.twocanoes.com in this example).

Here is the final command:

MachPower:~ tperfitt$ ./tcscertrequest  -r twocanoes.csr  \
-c tcsca -s win-fgivt3j3gi9.twocanoes.com -w machine.cer -t Machine
Certificate issued.
Certificate saved to machine.cer. 

Success! The machine certificate has now been generated and can be viewed with Quicklook:

![](https://xdl4wtzciw-flywheel.netdna-ssl.com/wp-content/uploads/2018/01/PastedGraphic-1-707x1024.png)

In the Windows Certificate Authority, it shows the issued certificate:

![](https://xdl4wtzciw-flywheel.netdna-ssl.com/wp-content/uploads/2018/01/PastedGraphic-2-1024x446.png)

### Example 2: User Certificate

The second example shows the same process, but with user information and credentials.

First, a Kerberos ticket is requested for an Active Directory user. In this example, the Active Directory user is _Administrator_:

MachPower:~ tperfitt$ kinit Administrator
Administrator@TWOCANOES.COM's password: 

After authenticating, a kerberos TGT has been issued:

MachPower:~ tperfitt$ klist
 Credentials cache: API:EA1EADF6-195E-4503-A92D-8FA11A8FA327
 Principal: Administrator@TWOCANOES.COM
 Issued                Expires               Principal
 Jan 27 22:57:16 2018  Jan 28 08:57:13 2018  krbtgt/TWOCANOES.COM@TWOCANOES.COM

A certificate signing request is generated using the OpenSSL command line tool, with options to save the key as Administrator.key, the CSR as Administrator.csr, use a Common Name of Administrator, and output in DER format:

MachPower:~ tperfitt$ openssl req -nodes -newkey rsa:2048 \
-keyout Administrator.key -out Administrator.csr \
-subj '/CN=Administrator' -outform der
Generating a 2048 bit RSA private key
..............................+++
...........+++
writing new private key to 'Administrator.key'

The new certificate signing request can be submitted to the CA for signing using the CA common name of tcsca, the DNS name of the Microsoft Certificate Authority, and the User template.

MachPower:~ tperfitt$ ./tcscertrequest  -r Administrator.csr  -c tcsca -s [win-fgivt3j3gi9.twocanoes.com](http://win-fgivt3j3gi9.twocanoes.com/) -w Administrator.cer -t UserCertificate issued.  
Certificate saved to Administrator.cer.

The user certificate is now issued and the Administrator certificate can be viewed with Quicklook:

![](https://xdl4wtzciw-flywheel.netdna-ssl.com/wp-content/uploads/2018/01/PastedGraphic-3-707x1024.png)

In the Microsoft CA, the successful request can be viewed under Issued Certificates:

![](https://xdl4wtzciw-flywheel.netdna-ssl.com/wp-content/uploads/2018/02/authcert-1024x471.png)

### Conclusion

So the tool works equally well for computer and user certificates in a standard AD environments without the web CA because it is using DCE/RPC. 

### Where to find the tcscertrequest Command Line Tool

The git repository for _tcscertrequest_ command line tool for macOS can be downloaded [here](https://bitbucket.org/twocanoes/tcscertrequest/overview).

### Building a better tcscertrequest Tool

There are a bunch of improvements that could be done to the _tcscertrequest_ tool, such as:

1.  Include certificate signing request generation
2.  Do the certificate signing request in keychain with a non-exportable key in keychain
3.  Do the certificate signing request via the secure element on TouchBar Macs / iMac Pro
4.  Associate the certificate with a WiFi config for 802.1x
5.  Look up information in Active Directory (DNS name of CA, etc)

Let me know if further development of this tool is of interest to you. Ping me on twitter @tperfitt, the macadmins slack @tperfitt, or send us an message via our contact form on Twocanoes.