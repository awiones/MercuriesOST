<div align="center">
  <img src="public/assets/img/mercuries-logo.jpg" alt="MercuriesOST Logo" width="300"/>
  <h1>MercuriesOST</h1>
  <p>Open Source Intelligence Tool</p>
</div>

## Overview

MercuriesOST is a powerful OSINT (Open Source Intelligence) tool designed to gather and analyze information from various social media platforms and online sources. It provides detailed insights while being respectful of rate limits and system resources.

## Features

- 🔍 Multi-platform social media scanning
- 🚀 Concurrent processing with resource optimization
- 💡 Smart username variation generation
- 📊 Detailed profile analysis and insights
- 🎯 Memory-efficient operation
- 📈 Real-time progress tracking
- 💾 Automated result saving

## Installation

```bash
# Clone the repository
git clone https://github.com/awion/MercuriesOST.git

# Navigate to the directory
cd MercuriesOST

# Install dependencies
go mod download
```

## Usage

Basic command structure:

```bash
./mercuries -u "username" [options]
```

### Options

- `-u`: Username to search
- `--social-media`: Search social media profiles
- `-o`: Output directory (default: "results")
- `-verbose`: Enable verbose output
- `-version`: Display version information

### Examples

```bash
# Search for a username across all platforms
./mercuries -u "johndoe" -verbose

# Search with custom output directory
./mercuries --social-media "John Smith" -o "custom_results"
```

## Supported Platforms

- Twitter
- Instagram
- Facebook
- LinkedIn
- GitHub
- Reddit
- TikTok

## System Requirements

- Go 1.23.0 or higher
- Minimum 500MB RAM
- Internet connection

## Configuration

The tool automatically adjusts its resource usage based on your system capabilities:

- Concurrent workers: 3-10 (automatically adjusted)
- Memory management: Auto-scaling
- Rate limiting: Built-in protection

## Output

Results are saved in JSON format containing:

- Profile existence confirmation
- Basic profile information
- Follower counts and engagement metrics
- Profile insights and analysis
- Activity timestamps

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- "Knowledge is power, information is liberty"
- Made with ❤️ by [awion](https://github.com/awion)

## Security

- Respects rate limits
- No data storage of sensitive information
- Follows platform Terms of Service

## Disclaimer

This tool is for educational purposes only. Users are responsible for complying with applicable laws and platform terms of service.
