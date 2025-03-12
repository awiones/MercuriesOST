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

| Command          | Description                      | Example                                     |
| ---------------- | -------------------------------- | ------------------------------------------- |
| `--social-media` | Limit search to social profiles  | `./mercuries --social-media "John Smith"`   |
| `-o, --output`   | Custom output directory          | `./mercuries -u "username" -o "my_results"` |
| `-v, --verbose`  | Enable detailed logging          | `./mercuries -u "username" --verbose`       |
| `--version`      | Display version information      | `./mercuries --version`                     |
| `--email`        | Email intelligence lookup        | `./mercuries --email "user@example.com"`    |
| `--gid`          | Google ID intelligence lookup    | `./mercuries --gid "123456789012345678901"` |
| `--phone`        | Phone number intelligence lookup | `./mercuries --phone "+1234567890"`         |

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
    A[Input Username/Email/Phone] --> B[Profile Enumeration]
    B --> |Generate Variations| C[Username Permutations]
    B --> |Extract| D[Email Analysis]
    B --> |Extract| E[Phone Number Analysis]
    
    C --> F[Platform Detection]
    D --> F
    E --> F
    
    F --> G[Initialize Concurrent Workers]
    G --> H[Query Social Platforms]
    G --> I[Query Professional Networks]
    G --> J[Query Development Platforms]
    G --> K[Query Data Breaches]
    
    H --> L[Data Collection & Validation]
    I --> L
    J --> L
    K --> L
    
    L --> M[Data Enrichment]
    M --> |Extract Metadata| N[Pattern Analysis]
    M --> |Cross Reference| O[Connection Mapping]
    
    N --> P[Generate Intelligence Report]
    O --> P

    subgraph "New Functionality"
        D --> Q[Email Analysis]
        Q --> R[Validate Email Format]
        R --> S[Extract Username & Domain]
        S --> T[Check Email Service Provider]
        T --> U[Analyze Email Patterns]
        U --> V[Check Data Breaches]
        V --> W[Gather Domain Information]
        W --> X[Find Social Profiles]
        X --> Y[Check Online Presence]
        Y --> Z[Generate Email Report]

        E --> AA[Phone Number Analysis]
        AA --> AB[Validate Phone Number]
        AB --> AC[Extract Country & Region]
        AC --> AD[Check Carrier Information]
        AD --> AE[Analyze Risk Assessment]
        AE --> AF[Check Online Presence]
        AF --> AG[Perform Reverse Lookup]
        AG --> AH[Check Messaging Apps]
        AH --> AI[Generate Phone Report]

        C --> AJ[Google ID Analysis]
        AJ --> AK[Check Google Services]
        AK --> AL[Analyze Google Maps Contributions]
        AL --> AM[Check Google Photos]
        AM --> AN[Analyze Google+ Archive]
        AN --> AO[Generate Google ID Report]
    end

    style A fill:#f9d77e,stroke:#f9a11b
    style B fill:#a8e6cf,stroke:#1b998b
    style C fill:#a8e6cf,stroke:#1b998b
    style D fill:#a8e6cf,stroke:#1b998b
    style E fill:#a8e6cf,stroke:#1b998b
    style F fill:#fdffab,stroke:#ffd166
    style G fill:#fdffab,stroke:#ffd166
    style H fill:#ffc3a0,stroke:#ff677d
    style I fill:#ffc3a0,stroke:#ff677d
    style J fill:#ffc3a0,stroke:#ff677d
    style K fill:#ffc3a0,stroke:#ff677d
    style L fill:#ff9aa2,stroke:#ef476f
    style M fill:#c5a3ff,stroke:#8a508f
    style N fill:#c5a3ff,stroke:#8a508f
    style O fill:#c5a3ff,stroke:#8a508f
    style P fill:#dcd6f7,stroke:#6c63ff

    style Q fill:#a8e6cf,stroke:#1b998b
    style R fill:#fdffab,stroke:#ffd166
    style S fill:#ffc3a0,stroke:#ff677d
    style T fill:#ff9aa2,stroke:#ef476f
    style U fill:#c5a3ff,stroke:#8a508f
    style V fill:#dcd6f7,stroke:#6c63ff
    style W fill:#a8e6cf,stroke:#1b998b
    style X fill:#fdffab,stroke:#ffd166
    style Y fill:#ffc3a0,stroke:#ff677d
    style Z fill:#ff9aa2,stroke:#ef476f

    style AA fill:#a8e6cf,stroke:#1b998b
    style AB fill:#fdffab,stroke:#ffd166
    style AC fill:#ffc3a0,stroke:#ff677d
    style AD fill:#ff9aa2,stroke:#ef476f
    style AE fill:#c5a3ff,stroke:#8a508f
    style AF fill:#dcd6f7,stroke:#6c63ff
    style AG fill:#a8e6cf,stroke:#1b998b
    style AH fill:#fdffab,stroke:#ffd166
    style AI fill:#ffc3a0,stroke:#ff677d

    style AJ fill:#a8e6cf,stroke:#1b998b
    style AK fill:#fdffab,stroke:#ffd166
    style AL fill:#ffc3a0,stroke:#ff677d
    style AM fill:#ff9aa2,stroke:#ef476f
    style AN fill:#c5a3ff,stroke:#8a508f
    style AO fill:#dcd6f7,stroke:#6c63ff

subgraph "Supported Platforms"
    H
    I
    J
    K
end

subgraph "Data Analysis"
    M
    N
    O
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
