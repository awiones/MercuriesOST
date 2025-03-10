<div align="center">
  <img src="public/assets/img/mercuries-logo.jpg" alt="MercuriesOST Logo" width="300"/>
  <h1>MercuriesOST</h1>
  <p><strong>Advanced Open Source Intelligence Tool</strong></p>

  [![GitHub stars](https://img.shields.io/github/stars/awiones/MercuriesOST?style=social)](https://github.com/awiones/MercuriesOST/stargazers)
  [![GitHub watchers](https://img.shields.io/github/watchers/awiones/MercuriesOST?style=social)](https://github.com/awiones/MercuriesOST/watchers)
  [![GitHub forks](https://img.shields.io/github/forks/awiones/MercuriesOST?style=social)](https://github.com/awiones/MercuriesOST/network/members)
  [![GitHub issues](https://img.shields.io/github/issues/awiones/MercuriesOST)](https://github.com/awiones/MercuriesOST/issues)
  [![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://golang.org/)
  [![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
  [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
</div>

## 🔍 What is MercuriesOST?

MercuriesOST is a powerful Open Source Intelligence (OSINT) tool designed to gather, analyze, and visualize information from across the web. Built with Go, it excels at discovering digital footprints across major social platforms while respecting rate limits and optimizing system resources.

> *"Knowledge is power, information is liberty"*

## Key Features

### Platform Intelligence
- **[SCAN]** **Cross-Platform Reconnaissance** - Seamlessly scan profiles across major social networks, forums, and professional sites
- **[IDENT]** **Identity Correlation Engine** - Smart algorithms to discover username patterns and variations across platforms

### Performance & Usability
- **[PROC]** **Optimized Parallel Processing** - Intelligent resource allocation with dynamic threading
- **[SYS]** **Minimal Footprint Design** - Engineered for efficiency on all hardware configurations
- **[DASH]** **Live Analysis Dashboard** - Real-time visualization of scan progress and discoveries

### Data Processing
- **[META]** **Deep Metadata Extraction** - Uncover hidden connection patterns and digital footprints
- **[LINK]** **Relationship Mapping** - Automatically visualize connections between discovered profiles
- **[REPT]** **Flexible Export Pipeline** - Generate comprehensive reports in multiple analysis-ready formats

## 🚀 Quick Start

### Installation

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

### Basic Usage

```bash
# Search only social media platforms
./mercuries --social-media "Full Name" -o "custom_results"
```

## 📖 Command Reference

| Command | Description | Example |
|---------|-------------|---------|
| `--social-media` | Limit search to social profiles | `./mercuries --social-media "John Smith"` |
| `-o, --output` | Custom output directory | `./mercuries -u "username" -o "my_results"` |
| `-v, --verbose` | Enable detailed logging | `./mercuries -u "username" --verbose` |
| `--version` | Display version information | `./mercuries --version` |

## 🌐 Supported Platforms

<div align="center" style="display: flex; flex-wrap: wrap; justify-content: center; gap: 10px; margin: 20px 0;">
  <img src="https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white" alt="Twitter"/>
  <img src="https://img.shields.io/badge/Instagram-E4405F?style=for-the-badge&logo=instagram&logoColor=white" alt="Instagram"/>
  <img src="https://img.shields.io/badge/Facebook-1877F2?style=for-the-badge&logo=facebook&logoColor=white" alt="Facebook"/>
  <img src="https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn"/>
  <img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"/>
  <img src="https://img.shields.io/badge/Reddit-FF4500?style=for-the-badge&logo=reddit&logoColor=white" alt="Reddit"/>
  <img src="https://img.shields.io/badge/TikTok-000000?style=for-the-badge&logo=tiktok&logoColor=white" alt="TikTok"/>
</div>

## 💻 System Requirements

- **Go**: Version 1.23+ 
- **Memory**: Minimum 500MB RAM
- **Connectivity**: Internet connection required
- **OS**: Cross-platform (Windows, macOS, Linux)

## ⚙️ Smart Resource Management

MercuriesOST automatically adjusts its operation based on your system resources:

| Feature | Description |
|---------|-------------|
| **Dynamic Scaling** | 3-10 concurrent workers based on available CPU cores |
| **Memory Optimization** | Intelligent allocation with automatic throttling |
| **Rate Limit Protection** | Built-in safeguards for API limitations |
| **Connection Management** | Efficient network resource pooling |


## 🔄 How It Works

<div align="center">

```mermaid
graph TD
    A[Input Username] --> B[Generate Username Variations]
    B --> C[Initialize Concurrent Workers]
    C --> D[Query Social Platforms]
    D --> E[Validate Profiles]
    E --> F[Extract Profile Data]
    F --> G[Generate Intelligence Report]

    style A fill:#f9d77e,stroke:#f9a11b
    style B fill:#a8e6cf,stroke:#1b998b
    style C fill:#fdffab,stroke:#ffd166
    style D fill:#ffc3a0,stroke:#ff677d
    style E fill:#ff9aa2,stroke:#ef476f
    style F fill:#c5a3ff,stroke:#8a508f
    style G fill:#dcd6f7,stroke:#6c63ff

    subgraph "Supported Platforms"
        D1[Twitter]
        D2[Instagram]
        D3[LinkedIn]
        D4[GitHub]
        D5[Facebook]
        D6[Reddit]
        D7[TikTok]
    end

    D --> D1
    D --> D2
    D --> D3
    D --> D4
    D --> D5
    D --> D6
    D --> D7

    subgraph "Profile Data Extraction"
        F1[Full Name]
        F2[Bio]
        F3[Followers]
        F4[Join Date]
        F5[Location]
        F6[Recent Activity]
        F7[Connections]
    end

    F --> F1
    F --> F2
    F --> F3
    F --> F4
    F --> F5
    F --> F6
    F --> F7
```

</div>

## 👥 Contributing

Contributions make the open source community thrive! Here's how you can help:

1. **Fork** the repository
2. **Create** your feature branch: `git checkout -b feature/amazing-feature`
3. **Commit** your changes: `git commit -m 'Add some amazing feature'`
4. **Push** to your branch: `git push origin feature/amazing-feature`
5. **Submit** a pull request

For major changes, please open an issue first to discuss your proposed changes.

## 📜 License

<div align="center">
  This project is licensed under the MIT License - see the [LICENSE](https://github.com/awiones/MercuriesOST/blob/main/LICENSE) file for details.
</div>

## ⚠️ Ethical Usage Statement

<div align="center">
  <img src="https://img.shields.io/badge/Educational%20Use%20Only-FF0000?style=for-the-badge" alt="Educational Use Only"/>
</div>

MercuriesOST is provided for **educational and legitimate research purposes only**. Users must:

- Comply with all applicable laws and regulations
- Respect privacy and platform terms of service
- Use gathered information responsibly and ethically

The developers assume no liability for misuse or damages resulting from the use of this software.

---

<div align="center">
  Built with ❤️ by <a href="https://github.com/awion">awion</a>
</div>
