# Web eID: electronic identity cards on the Web

## Table of Contents

* [Introduction](#introduction)
  + [Use cases](#use-cases)
    - [Authentication](#authentication)
    - [Signing documents](#signing-documents)
  + [Requirements notation and conventions](#requirements-notation-and-conventions)
  + [Glossary](#glossary)
* [Design choices](#design-choices)
  + [Overview of the current Open eID implementation](#overview-of-the-current-open-eid-implementation)
  + [Problems of the current implementation](#problems-of-the-current-implementation)
  + [Principles of the new technical design](#principles-of-the-new-technical-design)
* [Requirements for the new solution](#requirements-for-the-new-solution)
  + [Support for other security tokens besides smart cards](#support-for-other-security-tokens-besides-smart-cards)
* [New solution architecture](#new-solution-architecture)
  + [Technical overview of authentication and digital signing](#technical-overview-of-authentication-and-digital-signing)
    - [Authentication](#authentication-1)
      * [Authentication and WebAuthn](#authentication-and-webauthn)
      * [Authenticated identity](#authenticated-identity)
      * [Authentication and TLS Token Binding](#authentication-and-tls-token-binding)
      * [Protection against man-in-the-middle attacks during authentication with origin validation and TLS Token Binding](#protection-against-man-in-the-middle-attacks-during-authentication-with-origin-validation-and-tls-token-binding)
    - [Digital signing](#digital-signing)
  + [JavaScript library](#javascript-library)
    - [General](#general)
      * [Timeouts](#timeouts)
      * [`isAvailable`](#isavailable)
    - [PKI operations](#pki-operations)
      * [`authenticate`](#authenticate)
      * [`getCertificate`](#getcertificate)
      * [`sign`](#sign)
  + [OpenID X509 ID Token specification](#openid-x509-id-token-specification)
    - [Requesting an OpenID X509 ID Token](#requesting-an-openid-x509-id-token)
    - [Token format](#token-format)
      * [Header](#header)
      * [Payload](#payload)
  + [Browser extensions](#browser-extensions)
    - [Chrome, Firefox and Opera](#chrome-firefox-and-opera)
    - [Edge](#edge)
    - [Safari](#safari)
    - [Internet Explorer](#internet-explorer)
  + [Native application](#native-application)
    - [Native application messaging API](#native-application-messaging-api)
      * [General](#general-1)
      * [PKI operations](#pki-operations-1)
  + [libpcsc-cpp: PC/SC library](#libpcsc-cpp-pcsc-library)
  + [libeid: eID token library](#libeid-eid-token-library)
    - [Extensibility](#extensibility)
  + [libui: user interface library](#libui-user-interface-library)
* [References](#references)

## Introduction

The **Web eID** project enables usage of European Union electronic identity (eID) smart cards for secure authentication and digital signing of documents on the web using public-key cryptography.

The project builds on the success of the [Estonian ID card](https://e-estonia.com/solutions/e-identity/) (EstEID) and the [Open Electronic Identity](https://github.com/open-eid) (Open eID) project that has been in operation since 2002. Most of Estonia's 1.3 million citizens have an ID card which provides digital access to all of Estonia’s secure e-services, releasing them from tedious red tape and making daily tasks faster and more comfortable while banking, signing documents, doing business or obtaining a digital medical prescription online. As of December 2018, however, the current Open eID implementation is facing certain technical challenges on the web browser platform due to its technical design that the Web eID project aims to overcome.

The Web eID solution consists of a JavaScript library, browser extension and a native application that together coordinate communication between the browser, website and the smart card to perform cryptographic operations.

The solution is cross-platform and works in all modern browsers in Windows, Mac OS X and Linux.

This document defines the functionality and technical design of the Web eID solution.

### Use cases

The solution supports two main use cases - authentication and digital signing of documents.

#### Authentication

The user opens a website that requires authentication with an eID card, connects a card reader, inserts his/her smart card to the card reader and initiates signing in. The application asks the user for permission to send authentication certificate to the website and prompts to enter his/her authentication PIN. The user enters the authentication PIN and confirms. The website verifies the authentication data, notifies the user of successful login and displays the signed-in page.

#### Signing documents

The user opens a website that supports digital signing of documents, connects a card reader, inserts his/her smart card to the card reader and initiates digital signing. The application asks the user for permission to send digital signature certificate to the website and prompts to enter his/her digital signature PIN. The user enters the digital signature PIN and confirms. The website verifies the signature data, notifies the user of successful signing and displays the signed document.

### Requirements notation and conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.txt).

### Glossary

The following terms and abbreviations are used in this document:

- **APDU**, *application protocol data unit*, the communication unit between a smart card reader and a smart card
- **CNG**, *Cryptography API: Next Generation*, the pluggable Windows Cryptography API introduced in Windows Vista
- **CDSA**, *Common Data Security Architecture*, an open software standard implemented in Mac OS X for a security infrastructure that provides a wide array of security services, including fine-grained access permissions, authentication of users, encryption, and secure data storage
- **eID**, *electronic identification*, a digital solution for proof of identity of citizens or organizations
- **OCSP**, *Online Certificate Status Protocol*, an Internet protocol used for obtaining the revocation status of a X.509 digital certificate
- **OpenID Connect**, a simple identity layer on top of the OAuth 2.0 protocol
- **PC/SC**, *Personal Computer/Smart Card*, a specification for smart card integration into computing environments
- **PKCS#11**, one of the *Public-Key Cryptography Standards*, defines a platform-independent API to cryptographic tokens, such as hardware security modules and smart cards
- **TLS**, *Transport Layer Security*, a cryptographic protocol for secure Internet communication
- **TLS CCA**, *TLS Client Certificate Authentication*, a TLS protocol variant where the client (browser) uses a certificate to authenticate itself during the TLS handshake
- **TLS Token Binding**, a set of draft IETF RFC proposals for a TLS extension that aims to increase TLS security by using cryptographic certificates on both ends of the TLS connection
- **Tokend**, a software module for bridging a cryptographic device (like a smart card) and the Common Data Security Architecture (CDSA) architecture in Mac OS X
- **WebAuthn**, *Web Authentication*, an API enabling the creation and use of public key-based credentials by web applications, for the purpose of strongly authenticating users
- **WebExtensions**, a new cross-browser system for developing browser extensions

## Design choices

### Overview of the current Open eID implementation

The current Open eID implementation for using eID smart cards on the web is deeply integrated with the operating system cryptographic APIs and native browser APIs. It provides a driver for the Cryptography API: Next Generation (CNG) in Windows, CDSA/Tokend plug-in in OS X and PKCS#11 driver in Linux for cryptographic operations with EstEID cards. Firefox uses PKCS#11 on all platforms. Authentication is implemented in the browser TLS session establishment layer with browser and operating system native components, using [TLS Client Certificate Authentication (CCA)](https://en.wikipedia.org/wiki/Transport_Layer_Security#Client-authenticated_TLS_handshake).

The following diagrams provide an overview of Open eID web components.

![Authentication components](http://open-eid.github.io/index_files/web_auth.png)  
Figure 1: Open eID authentication components

![Signing components](http://open-eid.github.io/index_files/web_sign.png)  
Figure 2: Open eID digital signing components

The benefit of the deep integration is support for a wide range of use cases outside the web browser, e.g. secure login to the operating system with eID cards. However, there are significant downsides for the web browser platform due to that.

### Problems of the current implementation

Due to the complexity of the solution, there have been numerous browser and operating system API stability issues throughout the years where users either cannot use their eID card with the web browser or have to restart the browser or the operating system to restore function. Due to that, when alternatives to using eID smart cards with the browser became available on mobile devices ([Mobile-ID](https://e-estonia.com/solutions/e-identity/mobile-id/) and [Smart-ID](https://e-estonia.com/solutions/e-identity/smart-id)), usage started to decline.

Here is the listing of the most prominent problems of the current implementation:

- Dependence on complex, changing operating system and browser APIs creates fragility and high maintenance cost when the APIs change.
- Different browsers use different cryptographic APIs in different operating systems (CNG, CDSA/Tokend, PKCS#11).
- Authentication and signing use different mechanisms that creates additional fragility - authentication may work but signing not, which is especially confusing and frustrating for users.
- Authentication PIN caching - without this authentication in TLS session establishment layer using TLS CCA would be infeasible as one would need to re-type the PIN for every browser request (including for media), but PIN caching creates security and usability problems.
- Need to restart the browser after logout from sites with high security requirements due to authentication PIN caching.

### Principles of the new technical design

The new technical design aims to overcome the problems listed above.

The principles of the new design are:

- Focus on web use cases and the web browser platform.
- Decoupling from the browser internals. Use [WebExtensions](https://wiki.mozilla.org/WebExtensions), a new cross-browser system for developing browser extensions.
- Decoupling from the operating system internals. Use the PC/SC API to communicate with eID cards directly. PC/SC API is user space, lower-level than the operating system cryptographic APIs, stable and cross-platform.
- Implement authentication according to the principles of the [Web Authentication API](https://www.w3.org/TR/webauthn/). Don't implement authentication in the browser TLS session establishment layer using TLS CCA.
- Require HTTPS and reject requests from non-secure contexts.
- No PIN caching and no need to restart the browser after logout.
- Use the same mechanism for authentication and signing.
- Support most common European eID smart cards.

The following diagram provides an overview of the new Web eID solution components:

![Web eID components](diagrams/Web-eID-Component-Model.png)  
Figure 3: Web eID components

## Requirements for the new solution

Besides the requirements listed above, the new solution satisfies the following requirements:

1. Support authentication and digital signing with Estonian, Latvian, Lithuanian, Finnish eID smart cards in phase 1 and [**TODO:** who else? Austria, **Belgium**, Germany, Italy, Liechtenstein, Portugal, Spain, Serbia, Croatia, Czech Republic, Slovakia, see overview [here](https://ec.europa.eu/cefdigital/wiki/display/CEFDIGITAL/Country+Overview+-+eID)] and Yubikey in phase 2.
1. Support recent versions of common operating systems, Windows, Mac OS X, Linux, and browsers, Chrome, Firefox, Safari, Opera, Edge, Internet Explorer.
1. Support easy installation and immediate launch through the browser without requiring restart of the operating system or browser after installation. Note that the Web eID native application needs to be installed separately from the browser extension.
1. Does not require any other third party software besides the operating system standard PC/SC stack and standard card reader driver.
1. Resilient, responsive, non-blocking, message driven internal design that supports unexpected events like card or reader removal or insertion during all operations.
1. Does not interfere with other eID software components in the browser or operating system. Web eID browser extension will work in parallel with the Open eID browser extension.
1. Authentication success implies signing success unless the signing PIN is blocked.

### Support for other security tokens besides smart cards

The solution is designed to be extensible so that it can support other security tokens that support public-key encryption besides smart cards, for example Yubikey. Thus in the following, the term "smart card" also refers to other security tokens that support public-key encryption.

## New solution architecture

The following diagram provides an overview of the internal design of the new solution:

![Web eID internal design](diagrams/Web-eID-internals.png)  
Figure 4: Web eID internal design

- JavaScript library `web-eid.js` is a thin wrapper on top of the messaging interface provided by the Web eID native application via the Web eID browser extension.
- The Web eID browser extension is either a [WebExtensions](https://wiki.mozilla.org/WebExtensions) extension in browsers that support it (Chrome, Firefox, Opera and Edge) or an [app extension](https://developer.apple.com/documentation/safariservices/safari_app_extensions) in Safari or a [browser helper object](https://en.wikipedia.org/wiki/Browser_Helper_Object) in Internet Explorer.
- The browser extension communicates with the Web eID native application installed on the host. The native application is built with Qt and consists of the controller component and `libpcsc-cpp`, `libeid`, `libgui` libraries.
- The controller component is responsible for coordinating interaction between other components and the browser extension. Controller is event-based.
- `libpcsc-cpp` is a pure C++ library for accessing smart cards using the PC/SC API.
- `libeid` is a pure C++ library that encapsulates smart card APDU commands and manages communication with the smart card by using `libpcsc-cpp` services. It also supports fallback to PKCS#11 and CNG in case of unknown smart cards or security tokens.
- `libgui` is a Qt library of cross-platform dialogs that the application uses.

### Technical overview of authentication and digital signing

The authentication and digital signing processes share a common scheme - the Web eID application signs a server-sent datagram with the private key on the smart card and sends the certificate and signature cryptogram back to the server. Server verifies if the certificate is valid and verifies the signature with the public key from the certificate.

In the following sections, _JavaScript application_ is the website's client-side frontend application in the browser that uses the `web-eid.js` library APIs to perform authentication and signing.

_Server application_ is the website's server-side backend application.

#### Authentication

Authentication uses digital signing and is based on the same principles as TLS Client Certificate Authentication (CCA) and Web Authentication (WebAuthn):

- server and client share a cryptographic nonce, a large random number that can be used only once,
- client signs the nonce with the user's private authentication key and sends the signature together with the user's authentication certificate to the server,
- server verifies the signature and certificate sent by the client to authenticate the user.

Web eID authentication uses the same mechanism, but it is implemented in the application layer, not in the transport layer like TLS CCA.

Authentication uses the authentication key and certificate of the eID smart cards, as most cards have separate keys for authentication and digital signing.

Server retrieves user details from the subject field of the authentication certificate.

![Web eID authentication diagram](diagrams/Web-eID-authentication-communication-diagram.png)  
Figure 5: Web eID authentication diagram

The authentication steps are as follows:

1. User initiates signing in.
1. **JavaScript application sends the authentication request to the server application**. The JavaScript application sends the initial authentication request to the server application with a `XMLHttpRequest` or `fetch()` call.
1. **Server application responds with the challenge**. The server application responds with the challenge. The challenge must be a cryptographic nonce, a large random number that can be used only once.
1. **JavaScript application calls webeid.authenticate(challenge)**. The JavaScript application calls the `web-eid.js` API method `authenticate(challenge)`, passing the challenge received from the server as argument. The Web eID JavaScript extension internally launches the Web eID native application and passes the challenge, document origin `location.origin` and, if available, the Token Binding ID as arguments to the `authenticate` command.
1. **Web eID application asks consent and PIN from the user**. The Web eID application displays a dialog to the user with an input field for entering the authentication PIN and a message requesting consent to allow sending the authentication certificate to the server. User consent is required as the authentication certificate contains personal data.
1. **User enters the authentication PIN and gives consent**.
1. **Web eID application exchanges APDUs with the eID card to get the authentication certificate**. The Web eID application uses the PC/SC API to send APDU commands to the smart card to select the authentication certificate file and read its content.
1. **eID card responds with the authentication certificate**. The smart card responds with APDU responses containing the certificate bytes.
1. **Web eID application creates the authentication token and hashes it**. The Web eID application creates the OpenID X509 ID Token (authentication token) according to the [specification below](#openid-x509-id-token-specification), embeds the certificate and challenge, and hashes the result. Origin field is filled with the origin received from the JavaScript extension. If the Token Binding ID was provided, token binding hash field is filled with the SHA-256 hash of the Token Binding ID. The hash algorithm used for hashing the authentication token depends on the capabilities of the card, see details below.
1. **Web eID application exchanges APDUs with the eID card to sign the authentication token hash**. The Web eID application sends APDU commands to the smart card to select the authentication security environment, verify the PIN and to sign the authentication token hash.
1. **eID card responds with the authentication token hash signature**. The smart card encrypts the authentication token hash with the authentication private key on the card to create the signature, and responds with APDU responses containing the signature.
1. **Web eID application returns the signed authentication token to the JavaScript application**. The Web eID application attaches the signature to the authentication token and returns it to the JavaScript application.
1. **JavaScript application sends the signed authentication token to the server application**. The JavaScript application sends the signed authentication token to the server application with a `XMLHttpRequest` or `fetch()` call.
1. **Server application verifies the certificate and authentication token**. The server application performs the following verification steps:
    1. verifies the origin of the authentication token by validating the website address in the `aud` (audience) field of the token,
    1. validates the challenge in the `nonce` field,
    1. if the `tbh` (token binding hash) field is given, verifies that the SHA-256 hash of the Provided Token Binding ID matches the SHA-256 hash contained in the `tbh` field,
    1. validates the subject of the authentication certificate,
    1. validates the chain of trust of the authentication certificate,
    1. verifies the token signature using a standard JWT signature verification library, passing in the token and the public key from the authentication certificate. JWT signature verification library internally hashes the authentication token, decrypts the signature with the public key and compares if the result is equal to the hash.
1. **Server application sends the authentication certificate revocation status request to the OCSP service**. Server verifies the revocation status of the certificate embedded inside the authentication token with [Online Certificate Status Protocol](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol).
1. **OCSP service responds that certificate status is good**.
1. **Server application responds that user is authenticated**. If verification succeeds, the user is authenticated. The server application responds accordingly, for example by setting the HTTP session cookie in the response. Server retrieves user details from the subject field of the authentication certificate.

##### Authentication and WebAuthn

As mentioned above, the Web eID authentication subsystem is similar in principle, purpose and most of the steps to the WebAuthn specification. Like in WebAuthn, a server-generated challenge is encrypted with authentication private key, authentication takes place in the JavaScript application layer using `XMLHttpRequest` or `fetch()` calls for communicating with the server, origin validation is an integral part of the security model and TLS Token Binding is supported.

However, WebAuthn has a different design with separate loosely coupled authenticator components that work on a different level of abstraction, and Web eID authentication token format is different. Web eID authentication token format is based on the [OpenID Connect ID Token specification](http://openid.net/specs/openid-connect-core-1_0.html#IDToken) to support authenticated identity and integration with OpenID Connect, see _OpenID X509 ID Token specification_ below for more details.

##### Authenticated identity

The server application can retrieve user details from the authentication certificate to access secure authenticated identity of an individual. The authenticity of the identity information is guaranteed via the state issued digital identity card and official public eID infrastructure.

##### Authentication and TLS Token Binding

[Token Binding](https://en.wikipedia.org/wiki/Token_Binding) is a set of draft IETF RFC proposals for a TLS extension that aims to increase TLS security by using cryptographic certificates on both ends of the TLS connection. Bound tokens are established by the browser that generates a private-public key pair per target server, providing the public key to the server, and thereafter proving possession of the corresponding private key on every TLS connection to the server.

Use of Token Binding protects the authentication flow from man-in-the-middle and token export and replay attacks. With token binding, man-in-the-middle attacks cannot forward requests or replay credentials because they cannot prove they have the key bound to the token, as the key is securely stored in the user's device.

A TSL terminating reverse proxy may be in use in front of the server application. There is a draft proposal [*HTTPS Token Binding with TLS Terminating Reverse Proxies*](https://tools.ietf.org/html/draft-ietf-tokbind-ttrp-07) to support forwarding token binding information through the proxy to the backend server. The proposal defines HTTP header fields that enable a TLS terminating reverse proxy to convey information to a backend server about the validated Token Binding Message received from a client, which enables that backend server to bind, or verify the binding of, cookies and other security tokens to the client's Token Binding key.  This facilitates the reverse proxy and backend server functioning together as though they are a single logical server side deployment of HTTPS Token Binding.

However, Token Binding is not yet widely supported by browsers and proxy usage may still be problematic; the server application can see if token binding is missing but it is not obvious if that is malicious or a proxy has stripped off the token binding.

Thus, Token Binding is an optional, complementary security measure until it becomes more widely supported by browsers and proxies.

The Web eID OpenID X509 ID Token data structures for using Token Binding are specified in _OpenID X509 ID Token specification_ below.

##### Protection against man-in-the-middle attacks during authentication with origin validation and TLS Token Binding

The security properties of the Web eID authentication subsystem are provided by ensuring that all authentication tokens are scoped to a particular origin, and cannot be replayed against a different origin, by incorporating the origin in the authentication token returned from the `webeid.authenticate()` call. Specifically, the full document origin [`location.origin`](https://developer.mozilla.org/en-US/docs/Web/API/Location) of the requester is included, and signed over, in the `aud` field of the authentication token. Since this is an integral part of the security model, the Web eID extension and native application only allow HTTPS origins.

Origin validation protects the authentication flow from man-in-the-middle and authentication token export and replay attacks. With origin validation, man-in-the-middle attacks cannot forward requests or replay the authentication token because they cannot forge the origin in HTTPS context. To perform a man-in-the-middle attack, the attacker must use [DNS spoofing](https://en.wikipedia.org/wiki/DNS_spoofing) so that the origin host name is resolved to the attacker's server IP address and have a valid TLS certificate for the origin installed in the server. The draft [Certificate Transparancy](https://en.wikipedia.org/wiki/Certificate_Transparency) standard may eventually eliminate misuse of TLS certificates by providing an open framework for monitoring and auditing TLS certificates in real time.

![Man-in-the-middle attack, broken](diagrams/Man-in-the-middle-attack-broken.png)
![Man-in-the-middle attack, fixed](diagrams/Man-in-the-middle-attack-fixed.png)  
Figure 6: Man-in-the-middle attack and mitigation with origin validation

Figure 6.1 demonstrates how an attacker who deceives the user to visit a deceptive website that impersonates a legitimate website can gain unauthorized access to the legitimate website with user credentials by intercepting the authentication data, in case only the challenge is signed over without including the origin. Figure 6.2 demonstrates how including origin in the authentication token, signing the authentication token and performing origin validation at server side help to mitigate this attack.

As described in the previous section, use of Token Binding provides additional protection of the authentication flow from man-in-the-middle attacks, but as Token Binding is not yet widely supported by browsers and proxy usage is also problematic, Token Binding is an optional, additional security measure against man-in-the-middle attacks that complements origin validation.

#### Digital signing

The digital signature of a document is created by encrypting the document hash using the signing key on the eID smart card. The signature is usually embedded into a signature container.

The Web eID digital signing subsystem and API is more similar to the existing Open eID design than the authentication subsystem, but it uses PC/SC instead of PKCS#11 or CNG.

![Web eID digital signing diagram](diagrams/Web-eID-signing-communication-diagram.png)  
Figure 7: Web eID digital signing diagram

The digital signing steps are as follows:

1. User initiates digital signing of a document.
1. **JavaScript application calls webeid.getCertificate()**. The JavaScript application calls the `web-eid.js` API method `getCertificate()`. The Web eID JavaScript extension internally launches the Web eID native application and sends the `certificate` command.
1. **Web eID application asks consent from the user**. The Web eID application displays a dialog to the user with a message requesting consent to allow sending the signing certificate to the server. User consent is required as the signing certificate contains personal data.
1. **User gives consent**.
1. **Web eID application exchanges APDUs with the eID card to get the signing certificate**. The Web eID application uses the PC/SC API to send APDU commands to the smart card to select the signing certificate file and read its content.
1. **eID card responds with the signing certificate**. The smart card responds with APDU responses containing the certificate bytes.
1. **Web eID application returns the signing certificate to the JavaScript application**.
1. **JavaScript application sends the signing request to the server application with the signing certificate**. The JavaScript application sends the signing request to the server application with a `XMLHttpRequest` or `fetch()` call, passing the certificate as argument.
1. **Server application creates the digital signature container of the document and calculates the hash to be signed**. Server application creates the digital signature container compliant to ETSI TS 102 918 standard [Associated Signature Containers (ASiC)](http://www.etsi.org/deliver/etsi_ts/102900_102999/102918/01.03.01_60/ts_102918v010301p.pdf), possibly using the [DigiDoc4j](http://open-eid.github.io/digidoc4j/) library, adds the document as data file to the container and calculates the hash to be signed.
1. **Server application returns the hash to be signed to the JavaScript application**.
1. **JavaScript application calls webeid.sign(certificate, hash)**. The JavaScript application calls the `web-eid.js` API method `sign(certificate, hash)`, passing the signing certificate and the hash to be signed received from the server as arguments. The Web eID JavaScript extension internally sends the `sign` command to the Web eID native application, forwarding the signing certificate and the hash as arguments.
1. **Web eID application asks the user to input the signing PIN**. The Web eID application displays a dialog to the user with an input field for entering the signing PIN and a message describing the data to be signed.
1. **User enters the signing PIN**.
1. **Web eID application exchanges APDUs with the eID card to sign the hash**. The Web eID application sends APDU commands to the smart card to select the signing security environment, verify the PIN and to sign the hash.
1. **eID card responds with the signature**. The smart card encrypts the hash with the signing private key on the card to create the signature, and responds with APDU responses containing the signature.
1. **Web eID application returns the signature to the JavaScript application**.
1. **JavaScript application sends the signature to the server application**.
1. **Server application adds the signature to the digital signature container and validates it**.
1. **Server application sends the signing certificate revocation status request to the OCSP service**.
1. **OCSP service responds that certificate status is good**.
1. **Server application responds that signing is successful**.

### JavaScript library

 `web-eid.js` is a thin wrapper on top of the messaging interface provided by the Web eID application via the Web eID browser extension.

It gives access to the Web eID solution features by providing an asynchronous, [Promise](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Promise)-based interface and listening to incoming messages and turning them into resolved Promises.

Principles:

- All calls are asynchronous in nature and return a Promise.
- While asynchronous, the API is still sequential - only one call can be serviced by a smart card reader at a time. If a call can not be serviced because another call is underway, the promise shall be rejected.
- The `message` property of a rejected promise (an [Error](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Error)) shall contain a symbolic error code that can be parsed.
- Conformance to [W3C Promises Guide](https://www.w3.org/2001/tag/doc/promises-guide) is intended.

#### General

##### Timeouts

By default the execution time of a call depends on the underlying hardware and timeout is infinite. A timeout can be set for some calls, so that the operations that depend on user action would fail sooner (e.g. do not wait forever but fail in 2 minutes, if the user does not connect a card reader and insert a card in time) or set to `0` to get an instant error code. Please note that not all calls are cancelable on all platforms, due to underlying platform limitations.

##### `isAvailable`

```javascript
webeid.isAvailable(object options)
```

| parameter  | type        |                                 |
|------------|-------------|---------------------------------|
| `options`  | object      | additional options (_optional_) |

| `options` |                                                 |
|-----------|-------------------------------------------------|
| `timeout` | timeout in seconds or `Infinity`. Default is `0`|

- does the discovery of the native application and MUST be called before any other calls; safe to call several times
- resolves to `false` if the native application is not available or to a string that describes the connection type of the application (`webextension`)
- if `false`, the recommended action is to display a notice with a link to where the Web eID application installer can be downloaded
- if called with `timeout = Infinity`, the recommended action is to display a dynamic notice during the call that asks the user to install or start the native application
- recommended use: guard function before dynamically showing login button; general client availability check before calling rest of the API etc.

#### PKI operations

If a PKI call fails, the Promise shall be rejected with an `Error` object that has a symbolic error code in the `message` string property.

##### `authenticate`

```javascript
webeid.authenticate(string nonce, object options)
```

| parameter  | type        |                                      |
|------------|-------------|--------------------------------------|
| `nonce`    | string      | challenge nonce for the session (**required**) |
| `options`  | object      | additional options (_optional_)      |


| `options` |                                                        |
|-----------|--------------------------------------------------------|
| `timeout` | timeout in seconds or `Infinity`. Default is `Infinity`|

- resolves to a `string` containing the OpenID X509 ID Token as specified below
- possible reasons for rejection: timeout or user cancels authentication, no certificates available, some other technical error
- used certificate is available in the `x5c` header field of the ID token
- expected behavior: user is instructed though the process of attaching a reader and a card, if necessary
- possible changes: resolving to `undefined` when no certificates are available.

##### `getCertificate`

```javascript
webeid.getCertificate(object options)
```

| parameter  | type        |                                 |
|------------|-------------|---------------------------------|
| `options`  | object      | additional options (_optional_) |

| `options` |                                                        |
|-----------|--------------------------------------------------------|
| `filter`  | type of certificate to return. Default is `sign`       |
| `timeout` | timeout in seconds or `Infinity`. Default is `Infinity`|

- resolves to an `ArrayBuffer` with the certificate
- intended to be used with the following `webeid.sign()` operation
- expected behavior: user is instructed though the process of attaching a reader and a card, if necessary
- possible reasons for rejection: user cancels certificate selection, no certificates available, some other technical error
- possible changes: resolving to `undefined` when no certificates available.

##### `sign`

```javascript
webeid.sign(ArrayBuffer certificate, ArrayBuffer hash, object options)
```

| parameter     | type        |                                   |
|---------------|-------------|-----------------------------------|
| `certificate` | ArrayBuffer | certificate to use (**required**) |
| `hash`        | ArrayBuffer | hash to sign (**required**)       |
| `options`     | object      | additional options (_optional_)   |


| `options`  |                                                        |
|------------|--------------------------------------------------------|
| `hashalgo` | hash algorithm type (`"SHA-256"` etc). (**required**)  |
| `timeout`  | timeout in seconds or `Infinity`. Default is `Infinity`|


- resolves to an `ArrayBuffer` containing the signature of the `hash` parameter (`ArrayBuffer`) generated with the private key belonging to the `certificate` (`ArrayBuffer`). Hash type is specified in `options.hashalgo` (`string`) and is one of "SHA-256", "SHA-384", "SHA-512"
- possible reasons for rejection: user cancels/refuses signing, user PIN is blocked, some other technical error
- possible changes: support for "last round on card" hashing.

### OpenID X509 ID Token specification

This specification defines the OpenID X509 ID Token format used by the Web eID solution during authentication.

The format is based upon the well established [OpenID Connect ID Token specification](http://openid.net/specs/openid-connect-core-1_0.html#IDToken) and the [OpenID Connect Token Bound Authentication](https://openid.net/specs/openid-connect-token-bound-authentication-1_0.html) extension to it that enables applying Token Binding to the OpenID Connect ID Token.

#### Requesting an OpenID X509 ID Token

The OpenID X509 ID Token is returned from the following JavaScript API call:

```js
webeid.authenticate('NONCEVALUE'); // returns a Promise
                                   // that resolves to an ID token
```

* The challenge nonce MUST be generated by the backend application and MUST contain at least 256 bits of entropy.
* The consuming backend application MUST check that the nonce in the returned claim equals the nonce of the authentication request and that the `aud` field matches the origin of the site.
* Browser implementation MUST reject nonces shorter than 256 bits.
* Browser implementation MUST reject origins that are not secure.
* The session and expiry management used for the nonce in the consuming backend application MUST conform to the recommendations of the [OWASP Session Management Cheat Sheet](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet).

#### Token format

The token format is based on [OpenID Connect ID Token](http://openid.net/specs/openid-connect-core-1_0.html#IDToken) with refinements in header fields and allowed semantics of the token fields. All fields required by ID Token are present for compatibility, but the interpretation of the fields differs.

The main value of the token is the combination of `x5c`, `aud`, `nonce`, `tbh` fields and the signature; `iat`, `exp`, `iss` and `sub` provide additional filtering capabilities and are only present for compatibility with OpenID ID Token

The following sections contain the header and payload parts of an example token with descriptions of the token fields.

##### Header

```json
{
 "typ": "JWT",
 "alg": "RS256",
 "x5c": ["MIIFozCCA4ugAwIBAgIQHFpdK-zCQsFW4scOqWZOaDANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxFzAVBgNVBAMMDkVTVEVJRC1TSyAyMDE1MB4XDTE2MDMxMTEzMjQzMFoXDTE3MTEyMzIxNTk1OVowgZMxCzAJBgNVBAYTAkVFMQ8wDQYDVQQKDAZFU1RFSUQxFzAVBgNVBAsMDmF1dGhlbnRpY2F0aW9uMSIwIAYDVQQDDBlQQUxKQUssTUFSVElOLDM4MjA3MTYyNzIyMQ8wDQYDVQQEDAZQQUxKQUsxDzANBgNVBCoMBk1BUlRJTjEUMBIGA1UEBRMLMzgyMDcxNjI3MjIwggEjMA0GCSqGSIb3DQEBAQUAA4IBEAAwggELAoIBAQCsCGcTOvHb44kbOoIJjbmmtdIL1qLPTxeBHWpCjHKXNVyW7xu84dRKFeAgue4-auN7qJorAy7hELtZ1AHOdAWKCLCL_xFjKJg_TqLkLw_CvxdiAfalXr-wkn5UFfT6tcHSo_Xf6337DPHSgq0n1YSU2m522BXUr87D4Hl0o2UJKfojBVKARNtkAUjfA78NYBrJ_v1z3Y4k3eLJmTpxNaGoWDeOUHemJ-0Dqi_-QtzDye1h0K43KKvU03YqVx6uKCtujPQnyQ6ctduS7Ia2qp6nXxAtHbpS3JpuRnxsoJmdANNofmTxknpaHwNp5ccbzHvjm95eI6a8rvEMlKhnAjeBAgQmoAaro4IBHzCCARswCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBLAwOwYDVR0gBDQwMjAwBgkrBgEEAc4fAQEwIzAhBggrBgEFBQcCARYVaHR0cHM6Ly93d3cuc2suZWUvY3BzMCEGA1UdEQQaMBiBFm1hcnRpbi5wYWxqYWtAZWVzdGkuZWUwHQYDVR0OBBYEFL-lc3l1ixB1ZyPeANAvMc7NHXMZMCAGA1UdJQEB_wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBSzq4i8mdVipIUqCM20HXI7g3JHUTA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vd3d3LnNrLmVlL2NybHMvZXN0ZWlkL2VzdGVpZDIwMTUuY3JsMA0GCSqGSIb3DQEBCwUAA4ICAQBvZ1pGY0v7gMAnFeEirkqG0_En6xUkVI2ctyqLR2OY49qt-X8gNlrfwYtVTKRRMN4FZYJz8C3HsdTyE9iYFKJ1Nzhg_XM1-SBR2FLAivXF2IEDSRt_590VHLb2xEUFJaCGZmubYLFEH4L30-xwTYvziDv4ncfp0kyAKOmW41l8e8SZ3c37ilCPwDy5EL4fRqmL1JiqhtpuzWxcU_sekN-Jv6ei0_9gJL0bBHI3Dpr_S8rzupEYKfKcGztVasLBIkUXrZ2dhIk8NloNgqtCEht4hhINek7i5DY-oRviV7jQEKcGBAxfBFHetcsTw_9_d4TPFEAzGL-FYD-MIJCgRWgss-yEP-S7aAHQ78oyqrdMt94RP1gyA8dGBaOCEAqUNcuoL9h5RmcYKsybOPBXg_19q2AH_sPiDpmWTKg-CPUVRp0pa8iiygPJVbIJa0HxZfn-6l0QoagO8K0iuvitY2RHFldgR2wTvTzM5QCbcCQJwqh5uGywpGDqaKkelyJ_6HLjVrQ_Qjm3odzA8cDxJXHTe2kHOz3wb5A6E6PwqKyELovM9qjoeTmBlwo43CpQF6nB60bU8EuLLSXr7VRFJNvoRO9yFT664LrtMWpf8E7pFWVdj7vvOwcwLbRGkTuyZnyCpIZCErjyJujxmuM5GiDDX0UjEgH9abDTul5ZucVkig"]
}
```

* Remark about `"alg"`: algorithm depends on the capabilities of the card (e.g. MAY be `ES256` or any other algorithm mentioned in [JWA section 3.1](https://tools.ietf.org/html/rfc7518#section-3.1)). A list of REQUIRED algorithms shall be specified.
* Remark about `"x5c"`: according to [JWS section 4.1.6](https://tools.ietf.org/html/rfc7515#section-4.1.6). While OpenID Connect Core section 2 tells that "ID Tokens SHOULD NOT use the JWS x5c Header Parameter field", the possibility and need to relay the used certificate in the same message justifies ignoring the suggestion.

##### Payload

```json
{
 "exp": "1479621923",
 "iat": "1479621900",
 "aud": "https://foobar.example.com/",
 "iss": "https://self-issued.me",
 "sub": "EE:38207162722",
 "nonce": "NONCEVALUE",
 "cnf": {
     "tbh": "l1X0aVlpikNqDhaH92VwGgrFdAY0tSackYis1r_-fPo"
  }
}
```

* Remark about `"iss"`: **TO BE SPECIFIED**.
* Remark about `"exp"`: recommended value is 5 minutes. Care must be taken with TZ and clock skew of client machines.
* Remark about `"iat"`: the time of the claim MUST NOT be trusted.
* Remark about `"sub"`: the value is informative and MUST NOT be used for authentication purposes, actual vetted identity is signed by certificate issuer and MUST be extracted from the certificate subject. SHOULD be `base64url(sha256(der(x5c[0])))` or CommonName of the certificate.
* Remark about `"aud"`: the origin of the website that initiated the authentication request. MUST be validated by consumer. UI SHOULD display the full path but MAY only use the origin part (domain).
* Remark about `"tbh"`: MUST be the base64url encoding of the SHA-256 hash of a Token Binding ID or empty in case Token Binding ID is not available.

### Browser extensions

#### Chrome, Firefox and Opera

The Web eID extension for Chrome, Firefox and Opera is built using the [WebExtensions API](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions), a cross-browser system for developing extensions. It is created using web technologies - HTML, CSS, and JavaScript and can take advantage of the same web APIs as JavaScript on a web page, but extensions also have access to their own set of JavaScript APIs, .

The goal of the WebExtensions standard is to make browser extension code much more interoperable across browsers by specifying common extension interfaces and well-defined browser behavior. This will allow extension authors to greatly reduce or eliminate the rework necessary to create extensions that target different browsers.

The extension will communicate with the Web eID native application using [Native messaging](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging). Native messaging enables an extension to exchange messages with a native application installed on the user's computer to enable the extension to access resources that are not accessible through WebExtension APIs, like the PC/SC subsystem in case of Web eID. Messages are exchanged with the native application via standard input-output streams.

The native application is not installed or managed by the browser, it is installed using the underlying operating system's installation facilities.

#### Edge

Microsoft has announced that it [intends to adopt the Chromium open source project](https://blogs.windows.com/windowsexperience/2018/12/06/microsoft-edge-making-the-web-better-through-more-open-source-collaboration/) in the development of the Microsoft Edge browser on the desktop to create better web compatibility and less fragmentation of the web for all web developers.

Microsoft has also expressed intention to support Chrome extensions, so based on the current information, there will be no separate extension for Edge and the Web eID extension for Chrome, Firefox and Opera is assumed to be compatible with Edge.

#### Safari

The Web eID extension for Safari is built as a [Safari app extension](https://developer.apple.com/documentation/safariservices/safari_app_extensions).

Safari app extensions are similar to WebExtensions that communicate with a native application, except that the native application is bundled with the extension. The extension can use a combination of JavaScript, CSS, and native code written in Objective-C or Swift. As extensions are built on the standard app extension model, they are bundled inside an app and distributed through the App Store.

The injected script and the Safari app extension live in different sandboxed environments, each with specific limits on what it can access, so, like WebExtensions, communication between the injected script and the app extension happens with message passing. The two runtime environments share a common format for message passing, and each provides an interface for sending and receiving messages.

The native app extension will wrap the Qt-based Web eID native app libraries and call the Web eID app API functions directly from Swift code.

#### Internet Explorer

The Web eID extension for Internet Explorer is built as a [Browser Helper Object](https://en.wikipedia.org/wiki/Browser_Helper_Object).

A Browser Helper Object is a DLL module designed as a plugin for Internet Explorer to provide added functionality.

The Browser Helper Object DLL module will wrap the Qt-based Web eID native app libraries and call the Web eID app API functions directly from C++ code.

### Native application

The Web eID native application is built with the [Qt](https://www.qt.io/) framework. It consists of the Qt application framework that starts the Qt event loop and a controller component that is responsible for observing card reader and card status, and coordinating communication between other components and the user. 

The controller has an event-driven internal design that supports unexpected events like card or reader removal or insertion during all operations; there is a separate card communication and monitoring thread to assure responsive, non-blocking operations.

The lifetime of the native application is managed by the Web eID browser extension, for example when Native messaging is used, then the application is launched when the extension calls `runtime.connectNative()`, and stopped with the `Port.disconnect()` call or when the `Port` object is garbage collected (e.g. during page reload).

The native application is not installed or managed by the browser, it is installed using the underlying operating system's installation facilities.

The implementations SHOULD follow TLS CCA user experience:

- asking for permission before sending authentication
- MAY keep a mapping of remembered sites (OPTIONAL).

#### Native application messaging API

Messaging API describes the application level messaging protocol between the Web eID browser extension and native application.

##### General

- Messaging API works in request-response pairs over `stdin`/`stdout` or direct method calls to the Web eID app API functions.
- All messages MUST have a message `"id"` field (even though the API is mostly sequential). Not included in snippets below. MUST be echoed verbatim in the response.
- All messages MUST have en explicit `"origin"` field, not included in snippets below.
- Presence of `"error"` field in a response indicates error. Additional information MAY be in `"message"` field.
- `"version"` field SHOULD be present in all responses and MUST be present in the response to an empty message.
- All binary fields are encoded with Base64.
- The native component:
  - Rejects technically incorrect requests with technically correct JSON response indicating `error: "protocol"` together with version.
  - Supports messages up to 8 KiB (8192 bytes).

##### PKI operations

See _JavaScript library_ section above for detailed description.

- request: `{"authenticate: {"nonce": "string", "origin": "string", "tokenbinding": "string"}}`
  - response: `{"token": "string", "type": "JWT"}`
- request: `{"certificate": {}}`
  - response: `{"certificate": "base64", "certfingerprint": "hex"}`
- request: `{"sign": {"certfingerprint": "hex", "hash": "base64", "hashalgo": "string"}}`
  - response: `{"signature": "base64"}`

### libpcsc-cpp: PC/SC library

`libpcsc-cpp` is a C++ library for communicating with smart cards using the PC/SC API.

Microsoft implemented PC/SC in Microsoft Windows 2000/XP and free implementation of PC/SC, PC/SC Lite, is available for Linux and other Unixes; a forked version comes bundled with Mac OS X. The PC/SC API interface, has been stable for more than twenty years and is the foundation of all the higher-level operating system smart card cryptographic APIs that Open eID currently uses.

### libeid: eID token library

`libeid` is a C++ library that encapsulates smart card APDU commands and manages communication with the smart card by using `libpcsc-cpp` services. It also supports fallback to PKCS#11 and CNG in case of unknown security tokens.

The APDU commands for each eID card are embedded inside the library. Therefore, to support a new eID card, implementers need access to the APDU protocol of the card. Not relying on external frameworks like PKCS#11 assures that support for new cards can be added immediately without waiting for external release cycles.

#### Extensibility

`libeid` is designed in extensible manner. If the ATR of the inserted card is unknown, it tries to load a PKCS#11 module for the ATR or use CNG to communicate with the card. However, extensibility is available only if the application is configured to allow this. This allows third parties to use the Web eID solution as a basis for custom solutions and support any security tokens that support public-key encryption.

### libui: user interface library

`libui`, the cross-platform user interface is built with the Qt framework. `libui` contains the dialogs for PIN input and asking consent.

## References

1. ["Key words for use in RFCs to Indicate Requirement Levels (RFC 2119)"](https://www.rfc-editor.org/rfc/rfc2119.txt), *IETF RFC document*
1. ["Estonian ID card (EstEID)"](https://e-estonia.com/solutions/e-identity/), *E-Estonia*
1. ["Open Electronic Identity (Open eID)"](https://github.com/open-eid), *Open eID GitHub project*
1. ["Client-authenticated TLS handshake"](https://en.wikipedia.org/wiki/Transport_Layer_Security#Client-authenticated_TLS_handshake), *Wikipedia*, provides overview of TLS Client Certificate Authentication (CCA)
1. ["Mobile-ID"](https://e-estonia.com/solutions/e-identity/mobile-id/), *E-estonia*
1. ["Smart-ID"](https://e-estonia.com/solutions/e-identity/smart-id), *E-estonia*
1. ["WebExtensions"](https://wiki.mozilla.org/WebExtensions), *MozillaWiki*
1. ["Safari App Extensions"](https://developer.apple.com/documentation/safariservices/safari_app_extensions), *Apple Devloper Documentation*
1. ["Internet Explorer Browser Helper Object"](https://en.wikipedia.org/wiki/Browser_Helper_Object), *Wikipedia*
1. ["Native Messaging"](https://developer.chrome.com/extensions/nativeMessaging#native-messaging-host-protocol), *Google Chrome browser extension developer guide*
1. ["Web Authentication (WebAuthn)"](https://www.w3.org/TR/webauthn/), *W3C Candidate Recommendation*
1. ["Online Certificate Status Protocol (OCSP)"](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol), *Wikipedia*
1. ["HTTPS Token Binding with TLS Terminating Reverse Proxies"](https://tools.ietf.org/html/draft-ietf-tokbind-ttrp-07), *IETF draft proposal*
1. ["Associated Signature Containers (ASiC)"](http://www.etsi.org/deliver/etsi_ts/102900_102999/102918/01.03.01_60/ts_102918v010301p.pdf), *ETSI TS 102 918 standard*
1. ["DigiDoc4j"](http://open-eid.github.io/digidoc4j/), *DigiDoc4j project documentation*
1. ["OpenID Connect ID Token specification"](http://openid.net/specs/openid-connect-core-1_0.html#IDToken), *OpenID Foundation specification*
1. ["OWASP Session Management Cheat Sheet"](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet)
