---
title: 'X.509-Compliant Hybrid Certificates for the Post-Quantum Transition'
tags:
  - Java
  - hybrid certificates
  - X.509
  - post quantum transition
authors:
 - name: Nina Bindel
   orcid: 0000-0001-6677-2474
   affiliation: 1
 - name: Johannes Braun
   orcid: 0000-0001-6491-2250
   affiliation: 1
 - name: Luca Gladiator
   affiliation: 1
 - name: Tobias Stöckert
   affiliation: 1
 - name: Johannes Wirth
   orcid: 0000-0002-5211-2544
   affiliation: 1
affiliations:
 - name: Technische Universität Darmstadt, Germany
   index: 1
date: 09 July 2019
bibliography: paper.bib
---

# Summary

We provide an X.509-standard-compliant Java implementation of hybrid certificates, which enable the parallel usage of two independent cryptographic schemes within public key infrastructures and related applications. This enables a stepwise transition to post-quantum secure and hybrid algorithms without the risk of incompatibility problems. 

# Motivation and statement of need

Public Key Infrastructures (PKIs) support the use of public-key cryptography by handling keys and providing public-key certificates. The most common approach is the use of hierarchical PKIs, where certificates are issued by Certification Authorities (CAs) according to the X.509 standard [@rfc5280]. These certificates bind the key owner's identity (e.g., a name) to their public key and hence, enable the authentication of public keys. This is a basic prerequisite for the use of digital signatures and public key encryption in applications such as e-business or e-government that require secure electronic communication.
The most prominent example is secure Internet communication using the Transport Layer Security (TLS) protocol.

The security of current public-key systems, e.g., RSA and elliptic curve cryptography, depends on the computational difficulty of 
factoring large numbers into their prime factors or computing discrete logarithms. These schemes are called classical in the remainder of this paper.
While the security guarantees of classical schemes are sufficient today, large quantum computers could break almost all public-key algorithms currently used by applying Shor’s algorithm [@Shor], rendering anything protected by them vulnerable to exploitation. Therefore, post-quantum cryptography, i.e., cryptography that is secure even in the presence of quantum computers, is required and needs to be integrated into applications.

To ensure uninterrupted cryptographic security, it is important to begin the transition to post-quantum cryptography today. Post-quantum secure algorithms already exist, e.g., qTESLA [@NISTPQC-R2:qTESLA19], and can be used as substitutes for classical schemes.
However, to facilitate the transition, the cryptographic infrastructure also must be adapted. One approach for a secure and smooth transition is the use of 
hybrids: multiple algorithms in parallel that are combined such that the hybrid scheme is secure as long as at least one of the parallely used algorithms is secure. 
For the post-quantum transition, a classical scheme is combined with a post-quantum scheme. This has two clear advantages compared to a direct switch to post-quantum secure algorithms: "hedging our bets" when the security of newer algorithms is not yet certain but the security of older primitives is already in question; and achieving security and functionality in both a post-quantum-aware and a backwards-compatible way with not-yet-upgraded software.

Our implementation has many applications in regard to evaluation and testing of new cryptographic schemes. It enables (post-quantum) cryptography researchers and IT security practitioners to extensively test newly designed schemes in real world environments and to demonstrate the practicality of their schemes. It allows insights regarding competitiveness and gives valuable hints in regard to optimization and parameter setting. For example, a prior mock-up implementation was used by Bindel et al. [@10.1007/978-3-319-59879-6_22] for a first evaluation of the hybrid certificate approach in conjunction with the qTESLA scheme. Our software allows a more thorough evaluation of such schemes.

# Hybrid certificates

Hybrid certificates [@10.1007/978-3-319-59879-6_22] are the basis for the use of hybrid cryptography. They are signed in parallel with two different signature schemes and additionally bind two independent public keys—one classical and one post-quantum key—to one identity. 
Thereby, the authentication of the public keys contained in the certificate is protected with the combined security of both signature schemes. Moreover, the secure parallel usage of two different schemes for authentication and key exchange purposes is enabled. 

We realize these hybrid certificates fully compliant to the X.509 standard [@rfc5280]. The standard signature and public-key fields of the X.509 certificate are used for one of the signature schemes. For the post-quantum transition, the standard fields are used for the classical scheme. This allows compatibility with clients that do not support hybrid signatures. The second signature scheme, using qTESLA as an example, is integrated using two non-critical X.509 extensions. One of the extensions contains the public key associated with the second scheme, while the other contains the second signature on the certified data. To fully support legacy entities in a controlled manner, the extension containing the second public key may optionally be left out. This explicitly states that the certified entity does not support post-quantum schemes yet, while the certificate contents themselves are still protected in a hybrid fashion.

# Implementation and features 

We provide a Java implementation for BouncyCastle [@bouncyCastle] available at [https://github.com/CROSSINGTUD/bc-hybrid-certificates](https://github.com/CROSSINGTUD/bc-hybrid-certificates "Hybrid Certificates - Java, Bouncy Castle integration") [@BCHybridCert] that comprises generation procedures required to issue standard compliant hybrid certificates as well as path validation procedures for certification chains. Note that non-upgraded software evaluates hybrid certificates just as classical X.509 certificates. Therefore, full backwards-compatibility is provided, while falling back on the security of the classical signature scheme in these cases. Further technical details on the definition of the extensions, certificate generation, and path validation procedures can be found in the technical documentation [@tecDocu].

The submitted Java implementation is independent, but fully compatible with a C implementation for the OQS OpenSSL fork [@OpenQuantumSafe], which integrates LIBOQS [@OpenQuantumSafe], a C library for quantum-safe cryptographic algorithms, into OpenSSL. The C version also implements hybrid certificates and can be accessed at [https://github.com/CROSSINGTUD/openssl-hybrid-certificates](https://github.com/CROSSINGTUD/openssl-hybrid-certificates "Hybrid Certificates - C, OpenSSL integration") [@opensslHybridCert].

Our implementation enables a stepwise transition to post-quantum secure and hybrid algorithms in compliance with existing standards and software.  
Hence, our software enables first uses and experiments with such algorithms in (parts of) real-life applications and systems without the risk of incompatibility problems due to unforeseen dependencies. 
These experiments in turn allow to identify limits and potential obstacles requiring adaptations for a smooth and secure transition.


# Acknowledgments
This work has been co-funded by the DFG as part of project P1 within the CRC 1119 CROSSING.

# References
