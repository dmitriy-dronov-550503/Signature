#pragma once
#include <iostream>
#include <fstream>
#include <vector>
#include <array>
#include <queue>
#include <sha256.h>
#include <cstdint>
#include "Pool.h"

struct Block
{
    uint64_t number;
    std::vector<unsigned char> block;

    Block(uint64_t num, size_t blockSize)
        : number(num) {
        block.resize(blockSize);
    }
};

struct Hash
{
    std::atomic<bool> ready = false;
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> hash;

    Hash() : hash{ 0 } {}
    Hash(const Hash& item) : hash{ 0 } {}
};

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
    static const uint32_t DEFAULT_NUM_OF_CORES = 8UL;
    static const uint32_t Q_RESERVATION_MULT = 4UL;
    static const uint32_t HASH_SIZE = CSHA256::OUTPUT_SIZE;
    typedef CSHA256 Hasher;

    std::ifstream inputFile;
    std::ofstream outputFile;
    const uint64_t blockSize;

    uint64_t inputFileSize;
    uint64_t blocksCount;
    uint32_t numOfCores;

    SyncPool<Block> blocksPool;
    std::queue<std::shared_ptr<Block>> blockQ;
    std::vector<Hash> hashQ;
    std::mutex blockQSync;
    std::mutex hashQSync;
    std::atomic<bool> writeCompleted = false;

    void ReadFileThread();
    void WriteFileThread();
    void HashingThread();

    inline void ShowProgress(float progress);

public:
    SignatureGenerator(const std::string inputFilePath, const std::string outputFilePath, const uint64_t blockSize);
    ~SignatureGenerator();
    void Generate();
};

