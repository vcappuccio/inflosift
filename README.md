# InfloSift: Infoblox Support Bundle Analyzer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

InfloSift is a powerful Python-based tool designed to revolutionize the analysis of Infoblox support bundles. By efficiently processing various log types, storing data in SQLite, and leveraging natural language queries via Ollama integration, InfloSift provides deep insights into your Infoblox infrastructure.

![InfloSift Logo](logo.svg)

## 🚀 Features

- **Comprehensive Log Processing**: Parses diverse log types (syslog, ptop, JSON, etc.)
- **Intelligent Data Storage**: Utilizes SQLite for efficient and queryable data management
- **Advanced Metadata Extraction**: Automatically extracts and indexes file metadata and timestamps
- **Natural Language Query Support**: Powered by Ollama for intuitive data exploration
- **Focused Analysis**: Specialized in critical areas such as DHCP failover issues
- **Extensible Architecture**: Easily adaptable for custom log formats and analyses
- **Support Bundle Flattener**: Includes a tool to decompress and organize support bundle contents

## 📋 Requirements

- Python 3.6+
- SQLite3
- Pandas
- Ollama client
- Colorama (for colored console output)

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/vcappuccio/inflosift.git
   cd inflosift
   ```

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Ensure Ollama is installed and running on your system.

## 🖥️ Usage

InfloSift offers two main components:

### 1. Support Bundle Flattener

Decompress and organize your support bundle:

```bash
python support_bundle_flattener.py <source_directory> <destination_directory>
```

### 2. Log Analyzer

Analyze the flattened support bundle:

```bash
python inflosift.py [--directory DIRECTORY] [--query QUERY] [--focus FOCUS]
```

Options:
- `--directory`: Specify the support bundle directory (default: current working directory)
- `--query`: Provide a natural language query for analysis
- `--focus`: Specify the focus area for the query (e.g., "DHCP failover")

### Examples:

1. Flatten a support bundle:
   ```bash
   python support_bundle_flattener.py /path/to/support_bundle /path/to/flattened_bundle
   ```

2. Process flattened support bundle files:
   ```bash
   python inflosift.py --directory /path/to/flattened_bundle
   ```

3. Query for DHCP failover issues:
   ```bash
   python inflosift.py --query "Identify critical DHCP failover events in the last 24 hours" --focus "DHCP failover"
   ```

## 📊 Database Schema

InfloSift creates a SQLite database with the following structure:

| Table          | Description                               |
|----------------|-------------------------------------------|
| files          | File metadata and content hashes          |
| lines          | Individual lines from text files          |
| ptop_data      | Process data from ptop files              |
| smaps_data     | Memory mapping data                       |
| syslog         | Standard syslog entries                   |
| support_syslog | Support-specific syslog entries           |
| infoblox       | Infoblox-specific log entries             |

## 🛠️ Customization and Extension

InfloSift is designed with extensibility in mind. You can easily:

- Add support for new log formats
- Implement custom analysis queries
- Extend the database schema for additional data points

Refer to our [Contribution Guide](CONTRIBUTING.md) for more details on how to extend InfloSift.

## 🔍 Troubleshooting

- Ensure all dependencies are correctly installed
- Verify that Ollama is running and accessible
- Check file permissions for the support bundle and destination directories

For more detailed troubleshooting, refer to our [FAQ](FAQ.md) or [open an issue](https://github.com/vcappuccio/inflosift/issues).

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Contributing

We welcome contributions! Please read our [Contribution Guidelines](CONTRIBUTING.md) before submitting a Pull Request.

## ☕️ Support

If you find InfloSift useful, consider supporting the project:

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/vcapp)



Created with [❤️](https://github.com/vcappuccio) 

---

For more information, bug reports, or feature requests, please [open an issue](https://github.com/vcappuccio/inflosift/issues).