package smartcard

type SmartCardUser struct {
	Name     string
	URL      string
	Login    string
	Language string
	Sex      string
}

// Reader ...........: Yubico Yubikey 4 OTP U2F CCID
// Application ID ...: D2760001240102010006067061180000
// Version ..........: 2.1
// Manufacturer .....: Yubico
// Serial number ....: 06706118
// Name of cardholder: Jason Scott Murray
// Language prefs ...: en
// Sex ..............: male
// URL of public key : https://pgp.mit.edu/pks/lookup?op=get&search=0xA931039A241EBC2A
// Login data .......: chaosaffe
// Signature PIN ....: not forced
// Key attributes ...: rsa4096 rsa4096 rsa4096
// Max. PIN lengths .: 127 127 127
// PIN retry counter : 3 3 3
// Signature counter : 5
// Signature key ....: 880E 774A 71B6 B365 81DF  7739 A931 039A 241E BC2A
//       created ....: 2018-06-10 16:38:50
// Encryption key....: EB35 0AAC 3378 642D 8260  3989 FBB0 216B F775 7E55
//       created ....: 2018-06-10 16:49:50
// Authentication key: 0309 910F 70B2 DB55 33EF  1356 9127 A5F5 1163 250F
//       created ....: 2018-06-10 17:00:41
// General key info..: pub  rsa4096/A931039A241EBC2A 2018-06-10 Jason Scott Murray (chaosaffe) <jason@chaosaffe.io>
// sec>  rsa4096/A931039A241EBC2A  created: 2018-06-10  expires: 2028-06-07
//                                 card-no: 0006 06706118
// ssb>  rsa4096/FBB0216BF7757E55  created: 2018-06-10  expires: 2019-06-10
//                                 card-no: 0006 06706118
// ssb>  rsa4096/9127A5F51163250F  created: 2018-06-10  expires: 2019-06-10
//                                 card-no: 0006 06706118
