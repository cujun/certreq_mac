# README #

tcscertrequest is a command line tool to send a certificate request via RPCs to a Microsoft certificate authority.
compiling requires the dce idl compiler at http://www.dcerpc.org/source/ installed at /usr/local/bin/dceidl 

Note: You do not need to compile the framework with "xcodebuild -configuration Debug -target DCERPC".  tcscertrequest just requires the idl compiler and the framework is included in PrivateFrameworks on macOS.

see blog post at :  https://twocanoes.com/origin-backstory-of-active-directory-certificate-profile-at-apple/
