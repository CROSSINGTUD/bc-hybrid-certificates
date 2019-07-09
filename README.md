# Statement of Need

Public Key Infrastructures (PKIs) support the use of public-key cryptography by handling keys and providing public-key certificates. The most common approach is the use of hierarchical PKIs, where certificates are issued by Certification Authorities (CAs) according to the X.509 standard. These certificates bind the key owner's identity (e.g. a name) to their public key and hence, enable the authentication of public keys. This is a basic prerequisite for the use of digital signatures and public key encryption in applications such as e-business or e-government that require secure electronic communication. The most prominent example is secure Internet communication using the Transport Layer Security (TLS) protocol.

The security of current public-key systems, e.g., RSA and elliptic curve cryptography, depends on the computational difficulty of factoring large numbers into their prime factors or computing discrete logarithms. These schemes are called classical in the remainder. While the security guarantees of classical schemes are sufficient today, large quantum computers could break almost all public-key algorithms currently used by applying Shor’s algorithm, rendering anything protected by them vulnerable to exploitation. Therefore, post-quantum cryptography, i.e. cryptography that is secure even in the presence of quantum computers, is required and needs to be integrated into applications.

To ensure uninterrupted cryptographic security, it is important to begin the transition to post-quantum cryptography today. Post-quantum secure algorithms already exist, e.g., qTESLA, and can be used as substitutes for classical schemes. However, to facilitate the transition, also the cryptographic infrastructure must be adapted. One approach for a secure and smooth transition is the use of hybrids--multiple algorithms in parallel that are combined such that the hybrid scheme is secure as long as at least one of the parallely used algorithms is secure. For the post-quantum transition a classical scheme is combined with a post-quantum scheme. This has two clear advantages compared to a direct switch to post-quantum secure algorithms: "hedging our bets" when the security of newer algorithms is not yet certain but the security of older primitives is already in question; and to achieve security and functionality both in post-quantum-aware and in a backwards-compatible way with not-yet-upgraded software.

# Installation

A local gradle wrapper is provided which can be used for different tasks
  - `gradlew jar` packages the library into a `.jar` file which can be added to another project. You also need to add the two `.jar` files in the `libs/` directory to this project.
  - `gradlew javadoc` creates the JavaDoc for the library
  - `gradlew test` runs the tests

# Example Usage

You can find tests in `src/test/java` which show multiple usage examples.

# API Documentation

As stated above you can use gradle to generate the JavaDocs: `gradlew javadoc`

# Community Guidelines

If you want to contribute, report issues or have questions you can use the issue tracker of this repository.
Alternatively you can contact Johannes Braun ([jbraun@cdc.informatik.tu-darmstadt.de](mailto:jbraun@cdc.informatik.tu-darmstadt.de))
