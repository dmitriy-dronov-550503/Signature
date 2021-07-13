#pragma once
#include <iostream>
#include <fstream>
#include <vector>
#include <array>
#include <queue>
#include <sha256.h>
#include <boost/thread.hpp>
#include "Pool.h"

#define KB 1024ULL
#define MB (KB * 1024ULL)
#define GB (MB * 1024ULL)

// Block structure allows tracking read block number
struct Block
{
    uint64_t number;
    std::vector<unsigned char> block;

    Block(uint64_t num, size_t blockSize)
        : number(num) {
        block.resize(blockSize);
    }
};

// Hash structure allows to track whether a specific hash has been calculated
struct Hash
{
    boost::mutex mx;
    boost::condition_variable cv;
    bool ready = false;
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> hash;

    Hash() : hash{ 0 } {}
    Hash(const Hash& item) : hash{ 0 } {}
};

// This exception contains information that can be shown to the user
class SignatureGeneratorException {
private:
    std::string message;
    int error;
public:
    SignatureGeneratorException(const char* msg, int err)
        : message(msg), error(err) {}

    const char* What() {
        return message.c_str();
    }

    const int ErrorCode() {
        return error;
    }
};

class SignatureGenerator
{
private:
    static const uint32_t DEFAULT_NUM_OF_CORES = 4UL;
    static const uint32_t Q_RESERVATION_MULT = 4UL;     // Multiplier for processing units reservation
    static const uint64_t BLOCKS_POOL_MEM_LIMIT = 1.5 * GB;
    static const uint32_t HASH_SIZE = CSHA256::OUTPUT_SIZE;
    typedef CSHA256 Hasher;

    std::ifstream inputFile;
    std::ofstream outputFile;
    const uint64_t blockSize;

    uint64_t inputFileSize;
    uint64_t blocksCount;   // Total number of blocks to be processed
    uint32_t numOfCores;    // The number of cores in the system

    SyncPool<Block> blocksPool;                 // Pool of Blocks for better memory management
    std::queue<std::shared_ptr<Block>> blockQ;  // Queue of Blocks for processing
    std::vector<Hash> hashes;                   // Vector of Hashes that is not supposed to consume much memory
    std::mutex blockQSync;
    std::atomic<bool> writeCompleted = false;   // Signals that write to the output file is finished

    void ReadFileThread();
    void WriteFileThread();
    void HashingThread();

    inline void ShowProgress(float progress);

public:
    SignatureGenerator(const std::string inputFilePath, const std::string outputFilePath, const uint64_t blockSize);
    ~SignatureGenerator();
    void Generate();
};

