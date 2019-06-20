# TLS Padding Oracles 

The TLS protocol provides encryption, data integrity, and authentication on the modern Internet. Despite the protocol’s importance, currently-deployed TLS versions use obsolete cryptographic algorithms which have been broken using various attacks. One prominent class of such attacks is CBC padding oracle attacks. These attacks allow an adversary to decrypt TLS traffic by observing different server behaviors which depend on the validity of CBC padding.

We evaluated the Alexa Top Million Websites for CBC padding oracle vulnerabilities in TLS implementations and revealed vulnerabilities in 1.83% of them, detecting nearly 100 different vulnerabilities. These padding oracles stem from subtle differences in server behavior, such as responding with different TLS alerts, or with different TCP header flags.
We suspect the subtlety of different server responses is the reason these padding oracles were not detected previously.

## Full Technical Paper

Robert Merget, Juraj Somorovsky, Nimrod Aviram, Craig Young, Janis Fliegenschmidt, Jörg Schwenk, Yuval Shavitt: *Scalable Scanning and Automatic Classification of TLS Padding Oracle Vulnerabilities.* USENIX Security 2019

The full paper will be presented at USENIX Security in August 2019.

See the preliminary version [here](TlsPaddingOracleScanning.pdf).


## Who Is Affected?

Since the identification of different vendors is fairly difficult and requires the cooperation of the scanned websites, a lot of our vulnerabilities are not attributed yet. On this Github page, we collect the current status of the responsible disclosure process and give an overview of the revealed vulnerabilities. 

The currently identified and fixed vulnerabilities are:

* OpenSSL. CVE-2019-1559. [OpenSSL Security Advisory: 0-byte record padding oracle](https://www.openssl.org/news/secadv/20190226.txt)
* Citrix. CVE-2019-6485. [TLS Padding Oracle Vulnerability in Citrix Application Delivery Controller (ADC) and NetScaler Gateway](https://support.citrix.com/article/CTX240139).
* F5. CVE-2019-6593. [TMM TLS virtual server vulnerability CVE-2019-6593](https://support.f5.com/csp/article/K10065173).
* SonicWall SonicOs. CVE-2019-7477. [SonicOS & SonicOSv CBC Cipher TLS Padding Vulnerability](https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2019-0003). 

The disclosure process is still running with a handful of vendors. Some of them consider to disable or even completely remove CBC cipher suites from their products.

## Recommendations for TLS Implementations Developers
If you are developing a TLS implementation, this is obviously a good reminder to review your CBC code and make sure it does not expose a padding oracle; obviously, this is easier said than done.
**We therefore invite developers of TLS implementations to contact us in this matter.** We will evaluate your implementation and if you are vulnerable, work with you to understand the nature of the vulnerability ([contact](https://www.nds.ruhr-uni-bochum.de/chair/people/merget/)). (To be clear, we will do this free of charge).

We will link the final version of our scanning tool detecting these vulnerabilities in the next days. 

## Background

### Cipher Block Chaining (CBC) mode of operation
The CBC mode of operation allows one to encrypt plaintexts of arbitrary length with block ciphers like AES or 3DES. In CBC mode, each  plaintext  block  is  XOR’ed  to  the  previous  ciphertext block before being encrypted by the block cipher. We simply refer to [Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC) for more information.

Padding oracle attacks exploit the CBC  malleability. The problem of CBC is that it allows  an  attacker to perform meaningful plaintext modifications without knowing the symmetric key. More concretely, it allows an attacker to flip a specific plaintext bit by flipping a bit in the previous ciphtertext block. This CBC property has already been exploited in many attacks, for example, most recently in the [Efail attack](https://efail.de/).

### CBC and its usage in the TLS record layer
In order to protect messages (records) exchanged between TLS peers, it is possible to use different cryptographic primitives. One of them is a MAC combined with AES in CBC mode of operation. Unfortunately, TLS decided to use the MAC-then-PAD-then-Encrypt mechanism, which means that the encryptor first computes a MAC over the plaintext, then pads the message to achieve a multiple of block length, and finally uses AES-CBC to encrypt the ciphertext.

For example, if we want to encrypt five bytes of data and use HMAC-SHA (with 20 bytes long output), we end up with two blocks. The second block needs to be padded with 7 bytes 0x06.
![Validly formatted MAC and padding](https://github.com/RUB-NDS/TLS-Padding-Oracles/blob/master/img/valid-mac-padding.png)

### Padding oracle attacks
In 2002, Vaudenay showed that revealing padding failures after message decryption could have severe consequences for the security of the application. Since the CBC malleability allows an attacker to flip arbitrary message bytes, the attacker is also able to modify specific padding bytes. If the application decrypts the modified message and reports problems related to padding validity, the attacker is able to learn the underlying plaintext. We refer to [this explanation by Erlend Oftedal](https://www.youtube.com/watch?v=VQRHSecu_aw&feature=youtu.be&t=1033) for more details.

In TLS, the attack is a bit more complex because the targeted TLS connection is always closed once invalid padding is triggered. Nevertheless, the vulnerability is practically exploitable in [BEAST](https://nerdoholic.org/uploads/dergln/beast_part2/ssl_jun21.pdf) scenarios and allows the attacker to decrypt repeated secrets like session cookies. 

Therefore, it is very important that the TLS implementations do not reveal any information about padding validity. This includes different TLS alerts, connection states, or even timing behavior.

## Vulnerability Details

### OpenSSL (CVE-2019-1559)
With  the  help  of  the  Amazon  security  team,  we  identified  a  vulnerability which was mostly found on Amazon servers and  Amazon  Web  Services  (AWS).  Hosts  affected  by  this vulnerability  immediately  respond  to  most  records  with BAD_RECORD_MAC and CLOSE_NOTIFY alerts, and then close the connection. However, if  the  hosts  encounter  a  zero-length record with valid padding and a MAC present, they do not immediately close the TCP connection, regardless of the validity of the MAC. Instead, they keep the connection alive for  more  than  4  seconds  after  sending  the CLOSE_NOTIFY alert.  This difference in behavior is easily observable over the network.  Note that the MAC value does not need to be correct for triggering this timeout,  it is sufficient to create valid padding which causes the decrypted data to be of zero length. 

Further  investigations  revealed  that  the  Amazon  servers were running an implementation which uses the OpenSSL 1.0.2 API. In some cases, the function calls to the API return different error codes depending on whether a MAC or padding error occurred.  The Amazon application then takes different code paths based on these error codes, and the different  paths  result  in  an  observable  difference  in  the  TCP layer. The vulnerable behavior only occurs when AES-NI is not used.

### Citrix (CVE-2019-6485)
The vulnerable Citrix implementations first check the last padding byte and then verify the MAC. If the MAC is invalid, the server closes the connection.   This  is  done  with  either  a  connection  timeout  or  an RST,  depending  on  the  validity  of  the  remaining  padding bytes. However,  if the MAC is valid, the server checks whether all  other  remaining  padding  bytes  are  correct. If  they  are not,  the  server  responds  with  a BAD_RECORD_MAC and an RST (if they are valid, the record is well-formed and is accepted). This behavior can be exploited with an attack similar to POODLE. 

## FAQ

### Can these vulnerabilities be exploited?
Yes, but exploitation is fairly difficult. If you use one of the above implementations, you should still make sure you have patched.

To be more specific, the attack can be exploited in [BEAST](https://nerdoholic.org/uploads/dergln/beast_part2/ssl_jun21.pdf) scenarios. There are two prerequisites for the attack. First, the attacker must be able to run a script in the victim's browser which sends requests to a vulnerable website. This can be achieved tempting the victim to visit a malicious website. Second, the attacker must be able to modify requests sent by the browser and observe the server behavior. The second prerequisite is much harder to achieve, because the attacker must be an active Man-in-the-Middle.

### Have these vulnerabilities actually been exploited?
We have no reason to believe these vulnerabilities have been exploited in the wild so far.

### I used a vulnerable implementation. Do I need to revoke my certificate?
No, this attack does not recover the server's private key. 

### Do I need to update my browser?
No. These are server-side vulnerabilities, and can only be fixed by deploying a fix on the server.

### How many implementations are vulnerable?
Our Alexa scans identified more than 90 different server behaviors triggered in our padding oracle scans. Some of them will probably be caused by outdated servers. However, we assume many of the newest servers will need fixes.

### How is this related to previous research?
In 2002, Vaudenay presented an
[attack](https://link.springer.com/content/pdf/10.1007/3-540-46035-7_35.pdf)
which targets messages encrypted with the CBC mode of operation. The attack exploits the malleability of the CBC mode, which allows altering the ciphertext such that specific cleartext bits are flipped, without knowledge of the encryption key. The attack requires a server that decrypts a message and responds with 1 or 0 based on the message validity. This behavior essentially provides the attacker with a cryptographic oracle which can be used to mount an adaptive chosen-ciphertext attack. The attacker exploits this behavior to decrypt messages by executing adaptive queries. Vaudenay exploited a specific form of vulnerable behavior, where implementations validate the CBC padding structure and respond with 1 or 0 accordingly.

This class of attacks has been termed padding oracle attacks. Different types of CBC padding oracles have been used to break the confidentiality of TLS connections. These include
[Lucky Thirteen](http://www.isg.rhul.ac.uk/tls/TLStiming.pdf),
[Lucky Microseconds](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.738.4741&rep=rep1&type=pdf),
[Lucky 13 Strikes Back](http://v.wpi.edu/wp-content/uploads/Papers/Publications/asiaccs2015_lucky.pdf),
and [Ronen et al](https://eprint.iacr.org/2018/747.pdf).

Another important attack is [POODLE](https://www.openssl.org/~bodo/ssl-poodle.pdf) (Padding Oracle On Downgraded Legacy Encryption) which targets SSLv3 and its specific padding scheme. In SSLv3 only the last padding byte is checked. Möller, Duong and Kotowicz exploited this behavior and showed that for implementation it is necessary to correctly verify *all* padding bytes. Similar behaviors were found in several TLS implementations.

### How is it possible that such an old vulnerability is still present in 2019?
Writing this code correctly is very hard, even for experts.
For example, in one instance experts have introduced
[a severe form of this vulnerability](https://www.nds.ruhr-uni-bochum.de/media/nds/veroeffentlichungen/2016/10/19/tls-attacker-ccs16.pdf)
while attempting to patch the code to eliminate it.

Identifying these vulnerabilities is also hard since some of them only manifest under a combination of specific conditions. For example, the OpenSSL vulnerability only manifests in OpenSSL version 1.0.2, only for non-stitched [1] cipher suites, when AES-NI is not used.
It also requires subtle interactions between external code that calls the OpenSSL API, and the OpenSSL code itself.

We take this opportunity to suggest deprecating CBC cipher suites in TLS altogether.

[1]: Stitched ciphersuites is an OpenSSL term for optimised implementations of certain commonly used ciphersuites.
See [here](https://software.intel.com/en-us/articles/improving-openssl-performance) for more details.

### Why are you not submitting your findings via BugBounty websites?

We tried to get in contact with security teams via common BugBounty sites but had very bad experiences. Man-in-the-Middle attacks are usually out of scope for most website owners, and security teams did not know how to deal with this kind of issue. We lost a lot of "Points" on Hackerone and BugCrowd for reporting such issues (with the intention to learn the vendor) and learned absolutely nothing by doing this. All in all a very frustrating experience. We hope that our new approach of disclosure is more useful to get in contact with developers and vendors.

### Can this attack be used against Bitcoin?
No. This attack is based on the vulnerability present in the Cipher Block Chaining (CBC) mode of operation. Bitcoin does not use CBC. However, if you are a blockchain designer, we strongly recommend you to evaluate the security of your block chaining technology and, especially, its padding scheme.

### Do you have a name or a logo for this vulnerability?
No. Sorry, not this time.
