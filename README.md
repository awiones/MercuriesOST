<div align="center">
  <img src="public/assets/img/mercuries-logo.jpg" alt="MercuriesOST Logo" width="300"/>
  <h1>MercuriesOST</h1>
  <p><strong>Advanced Open Source Intelligence Tool</strong></p>

  <p>
    <a href="https://github.com/awiones/MercuriesOST/stargazers">
      <img src="https://img.shields.io/github/stars/awiones/MercuriesOST?style=social" alt="GitHub stars" />
    </a>
    <a href="https://github.com/awiones/MercuriesOST/watchers">
      <img src="https://img.shields.io/github/watchers/awiones/MercuriesOST?style=social" alt="GitHub watchers" />
    </a>
    <a href="https://github.com/awiones/MercuriesOST/network/members">
      <img src="https://img.shields.io/github/forks/awiones/MercuriesOST?style=social" alt="GitHub forks" />
    </a>
    <a href="https://github.com/awiones/MercuriesOST/issues">
      <img src="https://img.shields.io/github/issues/awiones/MercuriesOST" alt="GitHub issues" />
    </a>
    <a href="https://golang.org/">
      <img src="https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white" alt="Go Version" />
    </a>
    <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License" />
    <a href="CONTRIBUTING.md">
      <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome" />
    </a>
  </p>
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License" />
</div>

---

## 🔍 What is MercuriesOST?

**MercuriesOST** is a powerful Open Source Intelligence (OSINT) tool designed to gather, analyze, and visualize information across the web. Built with **Go**, it excels at discovering digital footprints efficiently.

> _"Knowledge is power, information is liberty."_

---

## ✨ Key Features

### 🕵️ Platform Intelligence

- **[SCAN]** Cross-Platform Reconnaissance – Scan profiles across major social networks, forums, and professional sites.
- **[IDENT]** Identity Correlation Engine – Discover username patterns and variations.

### ⚡ Performance & Usability

- **[PROC]** Optimized Parallel Processing – Dynamic threading for efficiency.
- **[SYS]** Minimal Footprint Design – Lightweight and resource-friendly.
- **[DASH]** Live Analysis Dashboard – Real-time visualization of scan progress.

### 📊 Data Processing

- **[META]** Deep Metadata Extraction – Uncover hidden connection patterns.
- **[LINK]** Relationship Mapping – Auto-visualization of connections.
- **[REPT]** Flexible Export Pipeline – Generate detailed reports in multiple formats.

---

## 🚀 Quick Start

### 🔧 Installation

```bash
# Clone the repository
git clone https://github.com/awion/MercuriesOST.git

# Navigate to project directory
cd MercuriesOST

# Install dependencies
go mod download

# Build the executable
go build -o mercuries
```

### 🎯 Basic Usage

```bash
# Search only social media platforms
./mercuries --social-media "Full Name" -o "custom_results"
```

---

## 📖 Command Reference

| Command          | Description                     | Example                                     |
| ---------------- | ------------------------------- | ------------------------------------------- |
| `--social-media` | Limit search to social profiles | `./mercuries --social-media "John Smith"`   |
| `-o, --output`   | Custom output directory         | `./mercuries -u "username" -o "my_results"` |
| `-v, --verbose`  | Enable detailed logging         | `./mercuries -u "username" --verbose`       |
| `--version`      | Display version information     | `./mercuries --version`                     |
| `--email`        | Email intelligence lookup       | `./mercuries --email "user@example.com"`    |
| `--gid`          | Google ID intelligence lookup   | `./mercuries --gid "123456789012345678901"` |

---

## 🌐 Supported Platforms

<div align="center">
  <img src="https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white" />
  <img src="https://img.shields.io/badge/Instagram-E4405F?style=for-the-badge&logo=instagram&logoColor=white" />
  <img src="https://img.shields.io/badge/Facebook-1877F2?style=for-the-badge&logo=facebook&logoColor=white" />
  <img src="https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white" />
  <img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" />
  <img src="https://img.shields.io/badge/Reddit-FF4500?style=for-the-badge&logo=reddit&logoColor=white" />
  <img src="https://img.shields.io/badge/TikTok-000000?style=for-the-badge&logo=tiktok&logoColor=white" />
</div>

---

## How It Works

```mermaid
graph TD
    A[Input Username/Email] --> B[Profile Enumeration]
    B --> |Generate Variations| C[Username Permutations]
    B --> |Extract| D[Email Analysis]

    C --> E[Platform Detection]
    D --> E

    E --> F[Initialize Concurrent Workers]
    F --> G[Query Social Platforms]
    F --> H[Query Professional Networks]
    F --> I[Query Development Platforms]
    F --> J[Query Data Breaches]

    G --> K[Data Collection & Validation]
    H --> K
    I --> K
    J --> K

    K --> L[Data Enrichment]
    L --> |Extract Metadata| M[Pattern Analysis]
    L --> |Cross Reference| N[Connection Mapping]

    M --> O[Generate Intelligence Report]
    N --> O

    subgraph "New Functionality"
        D --> P[Email Analysis]
        P --> Q[Validate Email Format]
        Q --> R[Extract Username & Domain]
        R --> S[Check Email Service Provider]
        S --> T[Analyze Email Patterns]
        T --> U[Check Data Breaches]
        U --> V[Gather Domain Information]
        V --> W[Find Social Profiles]
        W --> X[Check Online Presence]
        X --> Y[Generate Email Report]

        C --> Z[Google ID Analysis]
        Z --> AA[Check Google Services]
        AA --> AB[Analyze Google Maps Contributions]
        AB --> AC[Check Google Photos]
        AC --> AD[Analyze Google+ Archive]
        AD --> AE[Generate Google ID Report]
    end

    style A fill:#f9d77e,stroke:#f9a11b
    style B fill:#a8e6cf,stroke:#1b998b
    style C fill:#a8e6cf,stroke:#1b998b
    style D fill:#a8e6cf,stroke:#1b998b
    style E fill:#fdffab,stroke:#ffd166
    style F fill:#fdffab,stroke:#ffd166
    style G fill:#ffc3a0,stroke:#ff677d
    style H fill:#ffc3a0,stroke:#ff677d
    style I fill:#ffc3a0,stroke:#ff677d
    style J fill:#ffc3a0,stroke:#ff677d
    style K fill:#ff9aa2,stroke:#ef476f
    style L fill:#c5a3ff,stroke:#8a508f
    style M fill:#c5a3ff,stroke:#8a508f
    style N fill:#c5a3ff,stroke:#8a508f
    style O fill:#dcd6f7,stroke:#6c63ff

    style P fill:#a8e6cf,stroke:#1b998b
    style Q fill:#fdffab,stroke:#ffd166
    style R fill:#ffc3a0,stroke:#ff677d
    style S fill:#ff9aa2,stroke:#ef476f
    style T fill:#c5a3ff,stroke:#8a508f
    style U fill:#dcd6f7,stroke:#6c63ff
    style V fill:#a8e6cf,stroke:#1b998b
    style W fill:#fdffab,stroke:#ffd166
    style X fill:#ffc3a0,stroke:#ff677d
    style Y fill:#ff9aa2,stroke:#ef476f

    style Z fill:#a8e6cf,stroke:#1b998b
    style AA fill:#fdffab,stroke:#ffd166
    style AB fill:#ffc3a0,stroke:#ff677d
    style AC fill:#ff9aa2,stroke:#ef476f
    style AD fill:#c5a3ff,stroke:#8a508f
    style AE fill:#dcd6f7,stroke:#6c63ff

subgraph "Supported Platforms"
    G
    H
    I
    J
end

subgraph "Data Analysis"
    L
    M
    N
end
```

## 👥 Contributing

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Commit** your changes: `git commit -m 'Add some amazing feature'`
4. **Push** to your branch: `git push origin feature/amazing-feature`
5. **Submit** a pull request

For major changes, please open an issue first to discuss.

## ⚠️ Ethical Usage Statement

<div align="center">
  <img src="https://img.shields.io/badge/Educational%20Use%20Only-FF0000?style=for-the-badge" alt="Educational Use Only"/>
</div>

MercuriesOST is provided for **educational and legitimate research purposes only**. Users must:

- Comply with laws and regulations.
- Respect privacy and platform terms of service.
- Use information responsibly and ethically.

The developers assume no liability for misuse.

---

<div align="center">
  Built with ❤️ by <a href="https://github.com/awiones">awiones</a>
</div>
