#pragma once
#include <fstream>
#include <vector>
#include <array>
#include <queue>
#include <sha256.h>
#include <cstdint>

//template<typename T>
//class Pool
//{
//private:
//    std::queue<std::shared_ptr<T>> items;
//    std::mutex poolMutex;
//
//public:
//
//    std::shared_ptr<T> allocate() {
//        std::shared_ptr<T> item;
//        poolMutex.lock();
//        if (!items.empty())
//        {
//            item = std::move(items.front());
//            items.pop();
//        }
//        poolMutex.unlock();
//        return item;
//    }
//
//    void release(std::shared_ptr<T> item) {
//        poolMutex.lock();
//        items.push(item);
//        poolMutex.unlock();
//    }
//};
//
//class BlockProcessor
//{
//private:
//    std::vector<unsigned char> block;
//    unsigned int blockSize;
//    std::array<unsigned char, CSHA256::OUTPUT_SIZE> hash = { 0 };
//    CSHA256 hasher;
//public:
//    BlockProcessor(unsigned int blockSize)
//        : blockSize(blockSize) {}
//
//    void calculateHash() {
//        hasher.Reset();
//        hasher.Write(block.data(), blockSize);
//        hasher.Finalize(hash.data());
//    }
//};

class SignatureGenerator
{
private:
    std::ifstream inputFile;
    std::ofstream outputFile;
    unsigned int blockSize;
public:
    SignatureGenerator(std::string inputFilePath, std::string outputFilePath, unsigned int blockSize);
};

