# Auth Protocol — Version History & Benchmark Analysis

This documentation branch provides a centralized reference for the evolution of the Auth protocol across three iterative versions. It tracks cryptographic backend transitions, security enhancements, and comparative performance benchmarks.

---

## Repository Structure

```text
Documentation/Comparison/
├── media/
│   └── Comparision(May 20).png  # Latency & Stability visualization
├── README.md                    # This master overview
├── Version_1/
│   └── README.md                # V1: RSA-2048 OAEP baseline
├── Version_2/
│   └── README.md                # V2: Protocol hardening (Split-knowledge)
└── Version_3/
    └── README.md                # V3: Post-quantum upgrade (ML-KEM-768)

```

---

## Version Chronology

| Version | Focus | Cryptographic Primitive |
| --- | --- | --- |
| **V1** | Baseline | RSA-2048 OAEP |
| **V2** | Hardening | RSA-2048 OAEP + Server Nonce (R) |
| **V3** | PQC Migration | ML-KEM-768 + AES-256-GCM (FIPS 203) |

---

## Performance Comparison (n=5 runs)

### Authentication Speedup

V3 significantly outperforms previous versions due to the efficiency of lattice-based decapsulation over modular exponentiation.

### Stability & Tail Latency

V3 exhibits a tighter p99 distribution, providing more predictable authentication times under load.

---

## Key Security Enhancements

* **V2 Split-Knowledge:** Introduced server-side nonce `R` to mask secrets. Requires simultaneous compromise of device and server to mount offline dictionary attacks.
* **V3 Post-Quantum Security:** Replaced RSA with ML-KEM-768. Protects against "harvest-now, decrypt-later" attacks by providing IND-CCA2 security resistant to Shor’s algorithm.

---

## Accessing Detailed Documentation

Refer to the specific version directories for full technical specifications:

* **[Version 1 Details](https://github.com/s-uryansh/Auth/blob/main/Version_1/README.md)**: Original protocol specification and baseline metrics.
* **[Version 2 Details](https://github.com/s-uryansh/Auth/blob/main/Version_2/README.md)**: Implementation details on `B⊕R` masking and split-knowledge rationale.
* **[Version 3 Details](https://github.com/s-uryansh/Auth/blob/main/Version_3/README.md)**: FIPS 203 hybrid KEM/DEM integration and post-quantum security analysis.