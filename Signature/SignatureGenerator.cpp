#include "SignatureGenerator.h"
#include <filesystem>

#define DEBUG_LOG 0

SignatureGenerator::SignatureGenerator(const std::string inputFilePath, const std::string outputFilePath, const unsigned int blockSize) :
    blockSize(blockSize)
{
    inputFile.open(inputFilePath, std::ios::in | std::ios::binary);
    if (!inputFile) throw std::exception("Cannot find input file");
    outputFile.open(outputFilePath, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!outputFile) throw std::exception("Cannot create output file");

    inputFileSize = std::filesystem::file_size(inputFilePath);
    blocksCount = static_cast<uint64_t>(ceil((double)inputFileSize / (double)blockSize));
    const unsigned int cores = std::thread::hardware_concurrency();
    numOfCores = (cores == 0) ? DEFAULT_NUM_OF_CORES : cores;

    blocksPool.init("SignGen_blocks_semaphore", numOfCores * Q_RESERVATION_MULT);
    hashesPool.init("SignGen_hashes_semaphore", numOfCores * Q_RESERVATION_MULT);

    for (uint32_t i = 0; i < numOfCores * Q_RESERVATION_MULT; ++i) {
        auto block = std::make_shared<Block>(i, blockSize);
        blocksPool.release(block); // Add block to the pool
    }

    for (uint32_t i = 0; i < numOfCores * Q_RESERVATION_MULT; i++) {
        auto hash = std::make_shared<Hash>();
        hashesPool.release(hash); // Add hash to the pool
    }

    const uint64_t outputFileSize = blocksCount * CSHA256::OUTPUT_SIZE;
    const auto si = std::filesystem::space(outputFilePath);
    if (si.available < outputFileSize) {
        throw std::exception("Not enough disk space for creating signature file");
    }
}

SignatureGenerator::~SignatureGenerator()
{
    outputFile.close();
    inputFile.close();
}

void SignatureGenerator::ReadFileThread()
{
    for (int i = 0; i < blocksCount; ++i) {
#if DEBUG_LOG
        std::stringstream ss;
        ss << "Reading block " << i << " out of " << blocksCount << std::endl;
        std::cout << ss.str();
#endif
        auto block = blocksPool.allocate();

        block->number = i;
        auto bytesLeft = inputFileSize - inputFile.tellg();
        if (bytesLeft < blockSize) {
            memset(block->block.data(), 0, block->block.size());
        }
        inputFile.read(reinterpret_cast<char*>(block->block.data()), blockSize);

        {
            std::lock_guard<std::mutex> lock(blockQSync);
            blockQ.push(block);
        }
    }
}

void SignatureGenerator::WriteFileThread()
{
    uint64_t blocksLeft = blocksCount;
    while (!processingCompleted) {
        std::shared_ptr<Hash> hash;
        {
            std::lock_guard<std::mutex> lock(hashQSync);
            if (!hashQ.empty()) {
                hash = hashQ.front();
                hashQ.pop();
            }
            else {
                hash.reset();
            }
        }

        if (hash) {
            outputFile.seekp(hash->number * HASH_SIZE);
            outputFile.write((char*)hash->hash.data(), HASH_SIZE);
            ShowProgress(static_cast<float>(blocksCount - blocksLeft) / (static_cast<float>(blocksCount) - 1));
            hashesPool.release(hash);
            blocksLeft--;
            processingCompleted = (blocksLeft == 0) ? true : false;
        }
    }
}

void SignatureGenerator::HashingThread()
{
    std::shared_ptr<Block> block;

    while (!processingCompleted) {
        
        {
            std::lock_guard<std::mutex> lock(blockQSync);
            if (!blockQ.empty()) {
                block = blockQ.front();
                blockQ.pop();
            }
            else {
                block.reset();
            }
        }

        if (block) {
            auto num = block->number;
            auto hash = hashesPool.allocate();
            hash->number = num;

#if DEBUG_LOG
            std::stringstream ss;
            ss << "Calculate hash of " << num << " block" << std::endl;
            std::cout << ss.str();
#endif

            Hasher hasher;
            hasher.Reset();
            hasher.Write(block->block.data(), blockSize);
            hasher.Finalize(hash->hash.data());

            {
                std::lock_guard<std::mutex> lock(hashQSync);
                hashQ.push(hash);
            }

            blocksPool.release(block);
        }
    }
}

void SignatureGenerator::ShowProgress(float progress)
{
    static const unsigned int BAR_WIDTH = 70UL;
    std::stringstream ss;
    ss << "[";
    int pos = BAR_WIDTH * progress;
    for (int i = 0; i < BAR_WIDTH; ++i) {
        if (i < pos) ss << "=";
        else if (i == pos) ss << ">";
        else ss << " ";
    }
    ss << "] " << int(progress * 100.0) << " %\r";
    std::cout << ss.str();
    std::cout.flush();
}

void SignatureGenerator::Generate()
{
    std::thread fileReader(&SignatureGenerator::ReadFileThread, this);
    std::thread fileWriter(&SignatureGenerator::WriteFileThread, this);

    std::vector<std::thread> hashProcessors;
    for (uint32_t i = 0; i < numOfCores; ++i)
    {
        hashProcessors.push_back(std::move(std::thread(&SignatureGenerator::HashingThread, this)));
    }

    for (auto& hp : hashProcessors) hp.join();

    fileWriter.join();
    fileReader.join();
}
