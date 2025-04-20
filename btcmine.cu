// Compile with: nvcc btcmine.cu -lnvml

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <nvml.h>
#include <cuda_runtime.h>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>

// ---------------------------------------------------------------------------
// Minimal SHA-256 Implementation for Host (used for the merkle root)
// ---------------------------------------------------------------------------
#define SHA256_BLOCK_SIZE 32  // SHA256 outputs 32 bytes

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    unsigned long long bitlen;
    uint32_t state[8];
} SHA256_CTX;

static const uint32_t k_host[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256_transform(SHA256_CTX *ctx, const uint8_t data[])
{
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) |
               (data[j + 2] << 8) | (data[j + 3]);
    for ( ; i < 64; ++i) {
        uint32_t s0 = ((m[i - 15] >> 7) | (m[i - 15] << (32 - 7))) ^
                      ((m[i - 15] >> 18) | (m[i - 15] << (32 - 18))) ^
                      (m[i - 15] >> 3);
        uint32_t s1 = ((m[i - 2] >> 17) | (m[i - 2] << (32 - 17))) ^
                      ((m[i - 2] >> 19) | (m[i - 2] << (32 - 19))) ^
                      (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        uint32_t S1 = ((e >> 6) | (e << (32 - 6))) ^
                      ((e >> 11) | (e << (32 - 11))) ^
                      ((e >> 25) | (e << (32 - 25)));
        uint32_t ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + k_host[i] + m[i];
        uint32_t S0 = ((a >> 2) | (a << (32 - 2))) ^
                      ((a >> 13) | (a << (32 - 13))) ^
                      ((a >> 22) | (a << (32 - 22)));
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len)
{
    for (size_t i = 0; i < len; i++) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[])
{
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0xff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0xff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0xff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
    }
}

void sha256_hash(const uint8_t *data, size_t len, uint8_t hash[SHA256_BLOCK_SIZE])
{
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
}

// ---------------------------------------------------------------------------
// Device SHA-256 Implementation (actual work in the kernel)
// ---------------------------------------------------------------------------

__device__ const uint32_t k_device[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    unsigned long long bitlen;
    uint32_t state[8];
} SHA256_CTX_DEV;

__device__ void sha256_init_device(SHA256_CTX_DEV *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

__device__ void sha256_transform_device(SHA256_CTX_DEV *ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2, m[64];
    int i, j;

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) |
               (data[j + 2] << 8) | (data[j + 3]);
    for ( ; i < 64; ++i) {
        uint32_t s0 = ((m[i - 15] >> 7) | (m[i - 15] << (32 - 7))) ^
                      ((m[i - 15] >> 18) | (m[i - 15] << (32 - 18))) ^
                      (m[i - 15] >> 3);
        uint32_t s1 = ((m[i - 2] >> 17) | (m[i - 2] << (32 - 17))) ^
                      ((m[i - 2] >> 19) | (m[i - 2] << (32 - 19))) ^
                      (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        uint32_t S1 = ((e >> 6) | (e << (32 - 6))) ^
                      ((e >> 11) | (e << (32 - 11))) ^
                      ((e >> 25) | (e << (32 - 25)));
        uint32_t ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + k_device[i] + m[i];
        uint32_t S0 = ((a >> 2) | (a << (32 - 2))) ^
                      ((a >> 13) | (a << (32 - 13))) ^
                      ((a >> 22) | (a << (32 - 22)));
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

__device__ void sha256_update_device(SHA256_CTX_DEV *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform_device(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

__device__ void sha256_final_device(SHA256_CTX_DEV *ctx, uint8_t hash[32]) {
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform_device(ctx, ctx->data);
        for (i = 0; i < 56; i++)
            ctx->data[i] = 0;
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform_device(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0xff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0xff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0xff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
    }
}

__device__ void sha256_device(const uint8_t *data, size_t len, uint8_t hash[32]) {
    SHA256_CTX_DEV ctx;
    sha256_init_device(&ctx);
    sha256_update_device(&ctx, data, len);
    sha256_final_device(&ctx, hash);
}

// Packs the BlockHeader fields into an 80-byte array (big-endian) and performs double SHA-256.
typedef struct {
    uint32_t version;
    uint8_t prevBlock[32];
    uint8_t merkleRoot[32];
    uint32_t time;
    uint32_t bits;
    uint32_t nonce; // This is varied by each thread.
} BlockHeader;

__device__ void pack_uint32_be(uint32_t val, uint8_t out[4]) {
    out[0] = (uint8_t)((val >> 24) & 0xff);
    out[1] = (uint8_t)((val >> 16) & 0xff);
    out[2] = (uint8_t)((val >> 8) & 0xff);
    out[3] = (uint8_t)(val & 0xff);
}

__device__ void double_sha256_device(const BlockHeader *header, uint8_t hash_out[32]) {
    uint8_t header_bytes[80];
    // Pack version.
    pack_uint32_be(header->version, header_bytes);
    // Copy prevBlock.
    for (int i = 0; i < 32; i++)
        header_bytes[4 + i] = header->prevBlock[i];
    // Copy merkleRoot.
    for (int i = 0; i < 32; i++)
        header_bytes[36 + i] = header->merkleRoot[i];
    // Pack time.
    pack_uint32_be(header->time, header_bytes + 68);
    // Pack bits.
    pack_uint32_be(header->bits, header_bytes + 72);
    // Pack nonce.
    pack_uint32_be(header->nonce, header_bytes + 76);

    uint8_t first_hash[32];
    sha256_device(header_bytes, 80, first_hash);
    sha256_device(first_hash, 32, hash_out);
}

// ---------------------------------------------------------------------------
// Kernel and mining code
// ---------------------------------------------------------------------------

// Adjust these grid parameters for your GPU.
#define NUM_BLOCKS 10240
#define NUM_THREADS 1024
#define TOTAL_THREADS (NUM_BLOCKS * NUM_THREADS)

// Fixed difficulty target: first two bytes must be zero.
__constant__ uint8_t target[32] = {
    0x00, 0x00, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
};

// Device constant memory for the computed merkle root and previous block hash
__constant__ uint8_t d_merkleRoot[32];
__constant__ uint8_t d_prevBlockHash[32];

// Structure to hold each thread's computed nonce and hash.
typedef struct {
    uint32_t nonce;
    uint8_t hash[32];
} Result;

// Compare two 32-byte arrays.
__device__ bool isValidHash(const uint8_t *hash, const uint8_t *target_val) {
    for (int i = 0; i < 32; i++) {
        if (hash[i] < target_val[i])
            return true;
        else if (hash[i] > target_val[i])
            return false;
    }
    return false;
}

// Kernel: performs actual double SHA-256 work and updates a counter of bytes processed.
__global__ void mine_kernel(Result *results, uint32_t *found_nonce, uint8_t *found_hash, uint32_t current_time, unsigned long long *d_total_bytes) {
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t nonce = idx;

    BlockHeader header;
    header.version = 0x20000000;
    // Copy previous block hash from constant memory
    for (int i = 0; i < 32; i++)
        header.prevBlock[i] = d_prevBlockHash[i];
    // Copy computed merkle root from constant memory.
    for (int i = 0; i < 32; i++)
        header.merkleRoot[i] = d_merkleRoot[i];
    header.time = current_time;
    header.bits = 0x1d00ffff;  // Fixed difficulty
    header.nonce = nonce;

    uint8_t hash[32];
    double_sha256_device(&header, hash);

    results[idx].nonce = nonce;
    for (int i = 0; i < 32; i++)
        results[idx].hash[i] = hash[i];

    // Update counter: each thread processed 192 bytes (80-byte header becomes 128 bytes after padding in first SHA256,
    // and 32-byte hash padded to 64 bytes in the second SHA256).
    atomicAdd(d_total_bytes, (unsigned long long)192);

    if (isValidHash(hash, target)) {
        uint32_t old = atomicMin(found_nonce, nonce);
        if (nonce < old) {
            for (int i = 0; i < 32; i++)
                found_hash[i] = hash[i];
        }
    }
}

// Structure to represent a transaction
typedef struct {
    char sender[256];
    char receiver[256];
    double amount;
} Transaction;

// Structure to represent a mined block
typedef struct {
    int height;
    uint32_t nonce;
    uint8_t hash[32];
    uint8_t prev_hash[32];
    uint8_t merkle_root[32];
    uint8_t target[32];
    uint32_t timestamp;
    size_t tx_count;
} MinedBlock;

// Function to read transactions from a file
std::vector<Transaction> read_transactions_from_file(const char* filename) {
    std::vector<Transaction> transactions;
    std::ifstream file(filename);
    
    if (!file.is_open()) {
        printf("Error opening file: %s\n", filename);
        return transactions;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;
        
        std::istringstream iss(line);
        Transaction tx;
        
        if (iss >> tx.sender >> tx.receiver >> tx.amount) {
            transactions.push_back(tx);
        } else {
            printf("Warning: Could not parse line: %s\n", line.c_str());
        }
    }
    
    file.close();
    return transactions;
}

// Function to build Merkle root from multiple transactions
void build_merkle_root(const std::vector<Transaction>& transactions, uint8_t merkle_root[32]) {
    // For simplicity, we'll just concatenate all transaction data and hash it
    // In a real implementation, you would build a proper Merkle tree
    std::string all_transactions;
    for (const auto& tx : transactions) {
        char buffer[1024];
        snprintf(buffer, sizeof(buffer), "%s|%s|%.8f", tx.sender, tx.receiver, tx.amount);
        all_transactions += buffer;
    }
    
    sha256_hash((const uint8_t*)all_transactions.c_str(), all_transactions.size(), merkle_root);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <transactions_file>\n", argv[0]);
        return 1;
    }
    
    // Initialize NVML for power usage monitoring.
    nvmlInit();
    nvmlDevice_t device;
    nvmlDeviceGetHandleByIndex(0, &device);

    // Initialize previous block hash (genesis block)
    uint8_t prev_block_hash[32] = {0};
    
    // Read all transactions from file
    std::vector<Transaction> all_transactions = read_transactions_from_file(argv[1]);
    if (all_transactions.empty()) {
        printf("No transactions found in file or error reading file.\n");
        nvmlShutdown();
        return 1;
    }
    
    printf("\nTotal transactions to be mined: %zu\n", all_transactions.size());
    
    // Vector to store all mined blocks
    std::vector<MinedBlock> blockchain;
    
    // Process transactions in blocks of 100
    size_t total_blocks = (all_transactions.size() + 99) / 100; // Round up
    size_t tx_index = 0;
    int block_height = 0;
    
    while (tx_index < all_transactions.size()) {
        // Get next 100 transactions (or remaining if less than 100)
        size_t block_tx_count = std::min((size_t)100, all_transactions.size() - tx_index);
        std::vector<Transaction> block_transactions(all_transactions.begin() + tx_index, 
                                                   all_transactions.begin() + tx_index + block_tx_count);
        tx_index += block_tx_count;
        
        printf("\nMining Block %d (%zu transactions)\n", block_height, block_tx_count);
        printf("Transactions in this block:\n");
        for (const auto& tx : block_transactions) {
            printf("- %s -> %s (%.8f BTC)\n", tx.sender, tx.receiver, tx.amount);
        }
        
        // Build Merkle root from transactions
        uint8_t h_merkleRoot[32];
        build_merkle_root(block_transactions, h_merkleRoot);
        
        // Copy the computed merkle root and previous block hash to device constant memory.
        cudaMemcpyToSymbol(d_merkleRoot, h_merkleRoot, 32 * sizeof(uint8_t));
        cudaMemcpyToSymbol(d_prevBlockHash, prev_block_hash, 32 * sizeof(uint8_t));

        // Allocate memory for found nonce and hash.
        uint32_t *d_found_nonce;
        uint8_t *d_found_hash;
        uint32_t h_found_nonce = 0xFFFFFFFF;
        uint8_t h_found_hash[32] = {0};

        cudaMalloc((void **)&d_found_nonce, sizeof(uint32_t));
        cudaMalloc((void **)&d_found_hash, 32 * sizeof(uint8_t));
        cudaMemcpy(d_found_nonce, &h_found_nonce, sizeof(uint32_t), cudaMemcpyHostToDevice);

        // Allocate memory for kernel results.
        Result *d_results;
        cudaMalloc((void **)&d_results, TOTAL_THREADS * sizeof(Result));

        // Allocate and initialize counter for total bytes processed.
        unsigned long long *d_total_bytes;
        unsigned long long h_total_bytes = 0;
        cudaMalloc((void **)&d_total_bytes, sizeof(unsigned long long));
        cudaMemcpy(d_total_bytes, &h_total_bytes, sizeof(unsigned long long), cudaMemcpyHostToDevice);

        // Reset values for new mining attempt
        h_found_nonce = 0xFFFFFFFF;
        cudaMemcpy(d_found_nonce, &h_found_nonce, sizeof(uint32_t), cudaMemcpyHostToDevice);
        h_total_bytes = 0;
        cudaMemcpy(d_total_bytes, &h_total_bytes, sizeof(unsigned long long), cudaMemcpyHostToDevice);

        // Get power usage before mining
        unsigned int power_before;
        nvmlDeviceGetPowerUsage(device, &power_before);

        // Create and record CUDA events for timing.
        cudaEvent_t start, stop;
        cudaEventCreate(&start);
        cudaEventCreate(&stop);
        cudaEventRecord(start, 0);

        // Get current real-time timestamp.
        uint32_t current_time = (uint32_t) time(NULL);

        // Launch kernel.
        mine_kernel<<<NUM_BLOCKS, NUM_THREADS>>>(d_results, d_found_nonce, d_found_hash, current_time, d_total_bytes);

        // Synchronize to ensure proper timing
        cudaDeviceSynchronize();

        cudaEventRecord(stop, 0);
        cudaEventSynchronize(stop);

        // Get power usage after mining
        unsigned int power_after;
        nvmlDeviceGetPowerUsage(device, &power_after);

        // Calculate elapsed time in seconds.
        float elapsed_ms = 0.0f;
        cudaEventElapsedTime(&elapsed_ms, start, stop);
        double elapsed_sec = elapsed_ms / 1000.0;

        // Retrieve the total bytes processed.
        cudaMemcpy(&h_total_bytes, d_total_bytes, sizeof(unsigned long long), cudaMemcpyDeviceToHost);
        double throughput = (double)h_total_bytes / (1024.0 * 1024.0 * 1024.0) / elapsed_sec;

        // Calculate and print total hashes computed and hash rate.
        unsigned long long total_hashes = TOTAL_THREADS;
        double hash_rate = total_hashes / elapsed_sec;
        
        printf("\nMining Performance Metrics for Block %d:\n", block_height);
        printf("------------------------------------\n");
        printf("Kernel execution time: %.2f ms\n", elapsed_ms);
        printf("Throughput: %.2f GB/s\n", throughput);
        printf("Total Hashes Calculated: %llu\n", total_hashes);
        printf("Hash Rate: %.2f hashes/sec\n", hash_rate);
        printf("Average power: %.2f W\n", (float)(power_after + power_before) / 2000.0f);

        // Retrieve kernel results.
        Result *h_results = new Result[TOTAL_THREADS];
        cudaMemcpy(h_results, d_results, TOTAL_THREADS * sizeof(Result), cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_found_nonce, d_found_nonce, sizeof(uint32_t), cudaMemcpyDeviceToHost);
        cudaMemcpy(h_found_hash, d_found_hash, 32 * sizeof(uint8_t), cudaMemcpyDeviceToHost);

        if (h_found_nonce != 0xFFFFFFFF) {
            printf("\nBlock %d Mined Successfully!\n", block_height);
            printf("---------------------------\n");
            printf("Nonce: %u\n", h_found_nonce);
            printf("Block Hash: ");
            for (int i = 0; i < 32; i++)
                printf("%02x", h_found_hash[i]);
            printf("\n");
            
            // Store the mined block
            MinedBlock block;
            uint8_t h_target[32];
            block.height = block_height;
            block.nonce = h_found_nonce;
            memcpy(block.hash, h_found_hash, 32);
            memcpy(block.prev_hash, prev_block_hash, 32);
            memcpy(block.merkle_root, h_merkleRoot, 32);
            cudaMemcpyFromSymbol(h_target, target, 32 * sizeof(uint8_t), 0, cudaMemcpyDeviceToHost);
            memcpy(block.target, h_target, 32);
            block.timestamp = current_time;
            block.tx_count = block_tx_count;
            blockchain.push_back(block);
            
            // Update previous block hash for next block
            memcpy(prev_block_hash, h_found_hash, 32);
            block_height++;
        } else {
            printf("\nNo valid nonce found for Block %d. Try again with more hashes.\n", block_height);
            // Clean up and exit if we can't mine a block
            delete[] h_results;
            cudaFree(d_found_nonce);
            cudaFree(d_found_hash);
            cudaFree(d_results);
            cudaFree(d_total_bytes);
            cudaEventDestroy(start);
            cudaEventDestroy(stop);
            nvmlShutdown();
            return 1;
        }

        // Clean up.
        delete[] h_results;
        cudaFree(d_found_nonce);
        cudaFree(d_found_hash);
        cudaFree(d_results);
        cudaFree(d_total_bytes);
        cudaEventDestroy(start);
        cudaEventDestroy(stop);
    }

    // Print the entire blockchain at the end
    printf("\n\nFinal Blockchain:\n");
    printf("=================\n");
    for (const auto& block : blockchain) {
        printf("\nBlock %d:\n", block.height);
        printf("  Hash: ");
        for (int i = 0; i < 32; i++) printf("%02x", block.hash[i]);
        printf("\n");
        printf("  Previous Hash: ");
        for (int i = 0; i < 32; i++) printf("%02x", block.prev_hash[i]);
        printf("\n");
        printf("  Target: ");
        for (int i = 0; i < 32; i++) printf("%02x", block.target[i]);  // <-- Print target
        printf("\n");
        printf("  Merkle Root: ");
        for (int i = 0; i < 32; i++) printf("%02x", block.merkle_root[i]);
        printf("\n");
        printf("  Timestamp: %u\n", block.timestamp);
        printf("  Nonce: %u\n", block.nonce);
    }

    nvmlShutdown();
    return 0;
}