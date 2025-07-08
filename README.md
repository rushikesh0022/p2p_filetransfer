# P2P File Transfer System

A secure peer-to-peer file sharing system built with Python that uses end-to-end encryption to ensure safe file transfers between peers.

## Features

- **Encrypted File Transfers**: All communications and file transfers are encrypted using Fernet symmetric encryption
- **Tracker-Based Discovery**: Central tracker helps peers discover each other and find files
- **Decentralized File Sharing**: Files are shared directly between peers without going through a central server
- **Interactive CLI**: Easy-to-use command-line interface for managing files and transfers
- **Cross-Platform**: Works on Windows, macOS, and Linux

## How It Works

The system consists of two main components:

1. **Tracker**: A central coordination server that helps peers discover each other and find files
2. **Peers**: Individual clients that can share and download files with each other

### Architecture Overview

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    Peer 1   │────▶│   Tracker   │◀────│    Peer 2   │
│             │     │             │     │             │
│ - Shares    │     │ - Peer      │     │ - Downloads │
│   files     │     │   registry  │     │   files     │
│ - Downloads │     │ - File      │     │ - Shares    │
│   files     │     │   search    │     │   files     │
└─────────────┘     └─────────────┘     └─────────────┘
       │                                        │
       └────────── Direct File Transfer ───────┘
```

## Prerequisites

- Python 3.7 or higher
- `cryptography` library

## Installation

1. Clone or download this repository
2. Navigate to the project directory:

   ```bash
   cd p2p_file_transfer
   ```

3. Install the required dependencies:
   ```bash
   pip install cryptography
   ```

## Usage

### Step 1: Start the Tracker

First, start the tracker server that will coordinate peer discovery:

```bash
python p2p.py
```

When prompted:

- Enter an encryption password (remember this - all peers must use the same password)
- Choose `t` for tracker

The tracker will display its IP address and start listening for peer connections.

### Step 2: Start Peers

Open new terminal windows/tabs and start peer clients:

```bash
python p2p.py
```

For each peer:

- Enter the **same encryption password** used for the tracker
- Choose `p` for peer
- Enter the tracker host IP (shown by the tracker, or `localhost` if on same machine)
- Enter a unique port number for each peer (e.g., 8001, 8002, 8003, etc.)

### Step 3: Use the Peer CLI

Once a peer is running, you'll see a `P2P>` prompt. Available commands:

| Command               | Description                                  | Example                 |
| --------------------- | -------------------------------------------- | ----------------------- |
| `add <filename>`      | Share a file from current directory          | `add document.pdf`      |
| `search <filename>`   | Search for a file across all peers           | `search document.pdf`   |
| `download <filename>` | Download a file (search first)               | `download document.pdf` |
| `list`                | Show files you're sharing                    | `list`                  |
| `all_files`           | Show all files shared by all peers           | `all_files`             |
| `peers`               | Show known peers with the last searched file | `peers`                 |
| `help`                | Show available commands                      | `help`                  |
| `quit`                | Exit the application                         | `quit`                  |

## Example Workflow

Here's a complete example of sharing and downloading a file:

### Terminal 1 (Tracker):

```bash
$ python p2p.py
Enter encryption password: mypassword123
Run as (t)racker or (p)eer? t
Tracker listening on 192.168.1.100:9000
```

### Terminal 2 (Peer 1):

```bash
$ python p2p.py
Enter encryption password: mypassword123
Run as (t)racker or (p)eer? p
Enter tracker host (default: localhost): 192.168.1.100
Enter peer port: 8001
Peer listening on 192.168.1.100:8001
Welcome to the P2P File Sharing System. Type 'help' for commands.
P2P> add example.txt
Added example.txt to shared files
P2P> list
example.txt - Size: 1024 bytes
```

### Terminal 3 (Peer 2):

```bash
$ python p2p.py
Enter encryption password: mypassword123
Run as (t)racker or (p)eer? p
Enter tracker host (default: localhost): 192.168.1.100
Enter peer port: 8002
Peer listening on 192.168.1.100:8002
Welcome to the P2P File Sharing System. Type 'help' for commands.
P2P> search example.txt
Peers with example.txt: [{'host': '192.168.1.100', 'port': 8001}]
P2P> download example.txt
Downloaded example.txt from 192.168.1.100:8001
P2P> list
downloaded_example.txt - Size: 1024 bytes
```

## Security Features

- **Password-Based Encryption**: All communications use a shared password to generate encryption keys
- **End-to-End Encryption**: Files are encrypted before transmission and decrypted only by the recipient
- **PBKDF2 Key Derivation**: Uses industry-standard key derivation with 100,000 iterations
- **Fernet Encryption**: Implements authenticated encryption ensuring both confidentiality and integrity

## Network Configuration

- **Default Tracker Port**: 9000
- **Peer Ports**: Choose any available port (8001, 8002, etc.)
- **Local Network**: Works within the same local network
- **Internet**: Can work over the internet if firewall/NAT is properly configured

## Troubleshooting

### Common Issues:

1. **"Failed to register with tracker"**

   - Ensure the tracker is running
   - Check the tracker host IP address
   - Verify firewall settings

2. **"No peers available"**

   - Make sure you've searched for the file first using the `search` command
   - Ensure other peers have added the file using the `add` command

3. **"File not found" during download**

   - Verify the file exists in the sharing peer's directory
   - Check that the file was properly added with the `add` command

4. **Encryption errors**
   - Ensure all peers and the tracker use the exact same password
   - Password is case-sensitive

### Firewall Configuration:

If running across different machines, ensure the following ports are open:

- Tracker port (default: 9000)
- Each peer's chosen port

## File Organization

When files are downloaded, they are saved with the prefix `downloaded_` to avoid overwriting existing files:

- Original file: `document.pdf`
- Downloaded file: `downloaded_document.pdf`

## Limitations

- All peers must use the same encryption password
- Files must exist in the current working directory to be shared
- The tracker must be running for peers to discover each other
- No resume capability for interrupted downloads

## Contributing

Feel free to fork this project and submit pull requests for improvements such as:

- Resume functionality for interrupted downloads
- GUI interface
- File integrity verification (checksums)
- Support for large files (>2GB)
- Bandwidth throttling options

## License

This project is open source and available under the MIT License.
