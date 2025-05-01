# Cryptocurrency Mining Algorithm Optimization using CUDA

![CUDA Logo](https://img.shields.io/badge/CUDA-Supported-brightgreen)
![License](https://img.shields.io/badge/License-MIT-blue)

## 🧠 Project Description
A high-performance Bitcoin-like mining algorithm implemented and optimized for NVIDIA GPUs using CUDA. This project demonstrates the use of GPU parallel processing for accelerating SHA-256 hashing operations — the backbone of cryptocurrency mining.

🚀 Supports **double SHA-256**, mimicking Bitcoin's proof-of-work mechanism.

## 🛠️ Technologies Used
- **CUDA** - For parallel GPU-accelerated computation
- **C++17** - Core language for host and kernel logic
- **SHA-256** - Cryptographic hash function (with double hashing)
- **NVML** - NVIDIA Management Library for power usage monitoring
- **Merkle Tree** - Used for transaction integrity and block hashing

## 🔑 Key Features
- ⚡ GPU-accelerated double SHA-256 hashing
- 🧵 Parallel nonce search using CUDA threads
- 🔍 Merkle root generation from transaction list
- 📊 Performance metrics: hash rate, kernel time, throughput
- 🔌 Power usage estimation via NVML
- ⛓️ Block mining and validation simulation

## 📈 Performance Metrics
On execution, the miner displays:
- ⏱️ Kernel execution time
- 🚀 Throughput in GB/s
- 🔢 Total hashes calculated
- ⚡ Hash rate (in MH/s)
- 🔋 Average GPU power consumption

## 📦 Installation & Usage

### ✅ Prerequisites
- NVIDIA GPU (Compute Capability 3.5+)
- CUDA Toolkit v11.0 or newer
- NVIDIA GPU drivers
- Linux/macOS or WSL on Windows

### 🧱 Build Instructions
```bash
git clone https://github.com/Shrey9810/cuda-miner.git
cd cuda-miner
nvcc btcmine.cu -lnvml -o miner
```

### ▶️ Running the Miner
```bash
./miner transactions.txt
```

### 📄 Example Output
```
Total transactions to be mined: 1010

Mining Block 0 (100 transactions)
Transactions in this block:
- Irene -> Charlie216 (9.07920000 BTC)
- Alice576 -> Grace (6.60000000 BTC)
...

Mining Performance Metrics for Block 0:
------------------------------------
Kernel execution time: 60.46 ms
Throughput: 30.53 GB/s
Total Hashes Calculated: 10485760
Hash Rate: 172612001.20 hashes/sec
Average power: 8.77 W

Block 0 Mined Successfully!
---------------------------
Nonce: 7941
Block Hash: 00001b5978b37dbb4757d9e011cacc6260b183b5c4618d0fe574c6345654fb75

...After all blocks are mined...
Final Blockchain:
=================

Block 0:
  Hash: 00001b5978b37dbb4757d9e011cacc6260b183b5c4618d0fe574c6345654fb75
  Previous Hash: 0000000000000000000000000000000000000000000000000000000000000000
  Target: 0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  Merkle Root: 024a88bbcb4f9a7a90b144d4499dc83a7a28c69d260cbdfde8547871cd807dc2
  Timestamp: 1745136277
  Nonce: 7941

Block 1:
  Hash: 0000404159ae9cadbdba1d826c7d3fc5ef0e6839df9443ea330e209cdb0609cf
  Previous Hash: 00001b5978b37dbb4757d9e011cacc6260b183b5c4618d0fe574c6345654fb75
  Target: 0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  Merkle Root: ff678c18f7e84d43b2c98597f9cb48a050def33bc84fb2f766eab50750003b1f
  Timestamp: 1745136277
  Nonce: 55159
...
```

## 🗂️ Project Structure
```
cuda-miner/
├── btcmine.cu        # Main CUDA mining implementation
├── transactions.txt  # Sample transaction data
├── README.md         # This file
└── LICENSE           # MIT License
```

## 🌱 Future Enhancements
- 🔄 Dynamic difficulty adjustment
- 🌐 Peer-to-peer mining network simulation
- ⛏️ Support for alternative mining algorithms (e.g., Scrypt)
- 💾 Improved GPU memory management
- 💸 Transaction fee & reward system
- 🔐 Wallet address simulation

## 🤝 Contributing
Contributions are welcome!  
Please open an issue or submit a pull request with enhancements or bugfixes.

## 🧑‍💻 Author
**👤 Shreyash Chaudhary**

- GitHub: [@Shrey9810](https://github.com/Shrey9810)
- Email: shreyash9810@gmail.com
- LinkedIn: [Shreyash Chaudhary](https://www.linkedin.com/in/shreyash-chaudhary-8755632a6)

---

> 📝 Licensed under the MIT License. Feel free to fork and build upon this project!
