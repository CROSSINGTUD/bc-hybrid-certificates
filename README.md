# Statement of Need

Large quantum computers could break almost all public-key algorithms currently used, e.g., RSA and elliptic curve cryptography. As the construction of large quantum computers is approaching, it is important to begin the transition to post-quantum cryptography today, to ensure uninterrupted cryptographic security. 

With this project we provide an X.509 standard compliant Java implementation of hybrid certificates, which enable the parallel usage of two independent cryptographic schemes within public key infrastructures and related applications. This enables a stepwise transition to post-quantum secure and hybrid algorithms.

The target audience of this software are cryptographers as well as IT security experts and practitioners aiming at a smooth and secure transition to post-quantum cryptography at an early stage. Hybrid certificates support first uses and experiments with post-quantum secure and hybrid algorithms in (parts of) real-life applications and systems without the risk of incompatibility problems due to unforeseen dependencies.

# Further reading and alternative implementations
  - For a more detailed description and further references please refer to the [short paper](paper.md). 
	- Additional technical details such as definition of extensions, certificate structure, OIDs, certificate generation, and path validation procedures can be found in the [technical documentation] (https://github.com/CROSSINGTUD/openssl-hybrid-certificates/blob/OQS-OpenSSL_1_1_1-stable/HybridCert_technical_documentation.pdf).
  - We also provide a fully compatible C implementation of hybrid certificates which can be found here: [https://github.com/CROSSINGTUD/openssl-hybrid-certificates](https://github.com/CROSSINGTUD/openssl-hybrid-certificates "Hybrid Certificates - C, OpenSSL integration")


# Installation

A local gradle wrapper is provided and supports the following tasks:
  - `gradlew jar` packages the library into a `.jar` file which can be added to another project. You also need to add the two `.jar` files in the `libs/` directory to this project.
  - `gradlew javadoc` creates the JavaDoc for the library
  - `gradlew test` runs the tests

# Example usage

Unit tests showing multiple usage examples can be found in `src/test/java`.

# API documentation

The API documentation is provided as Javadoc.
You can use gradle to generate the HTML Javadoc files: `gradlew javadoc`

# Community guidelines

If you want to contribute, report issues or have questions you can use the issue tracker of this repository.
Alternatively please contact Johannes Braun ([jbraun@cdc.informatik.tu-darmstadt.de](mailto:jbraun@cdc.informatik.tu-darmstadt.de))
