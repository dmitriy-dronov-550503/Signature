#include "Windows.h"
#include "SignatureGenerator.h"
#include <boost/filesystem.hpp>

SignatureGenerator::SignatureGenerator(const std::string inputFilePath, const std::string outputFilePath, const uint64_t blockSize) :
    blockSize(blockSize)
{
    inputFile.open(inputFilePath, std::ios::in | std::ios::binary);
    if (!inputFile) throw SignatureGeneratorException("Cannot open input file", ERROR_FILE_NOT_FOUND);
    outputFile.open(outputFilePath, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!outputFile) throw SignatureGeneratorException("Cannot create output file. Is path to the file exist?", ERROR_PATH_NOT_FOUND);

    inputFileSize = boost::filesystem::file_size(inputFilePath);
    blocksCount = static_cast<uint64_t>(ceil((double)inputFileSize / (double)blockSize));
    const unsigned int cores = std::thread::hardware_concurrency();
    numOfCores = (cores == 0) ? DEFAULT_NUM_OF_CORES : cores;

    blocksPool.Init("SignGen_semaphore", numOfCores * Q_RESERVATION_MULT);

    for (uint32_t i = 0; i < blocksPool.GetMaxItems(); ++i) {
        auto block = std::make_shared<Block>(i, blockSize);
        blocksPool.Release(block); // Add block to the pool
    }

    hashes.resize(static_cast<size_t>(blocksCount));

    const uint64_t outputFileSize = blocksCount * HASH_SIZE;
    const auto free = boost::filesystem::space(outputFilePath).free;
    if (free < outputFileSize) {
        throw SignatureGeneratorException("Not enough disk space for creating output signature file", ERROR_OUTOFMEMORY);
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
        auto block = blocksPool.Allocate();

        block->number = i;
        auto bytesLeft = inputFileSize - inputFile.tellg();
        if (bytesLeft < blockSize) {
            memset(block->block.data(), 0, block->block.size());
        }
        inputFile.read(reinterpret_cast<char*>(block->block.data()), blockSize);
        std::lock_guard<std::mutex> lock(blockQSync);
        blockQ.push(block);
    }
}

void SignatureGenerator::WriteFileThread()
{
    for (int i = 0; i < blocksCount; ++i) {
        if (hashes[i].ready) {
            outputFile.write((char*)hashes[i].hash.data(), HASH_SIZE);
            ShowProgress(static_cast<float>(i) / (static_cast<float>(blocksCount) - 1));
        }
        else {
            i--;
            std::this_thread::yield();
        }
    }
    writeCompleted = true;
}

void SignatureGenerator::HashingThread()
{
    std::shared_ptr<Block> block;

    while (!writeCompleted) {

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
            auto& hash = hashes[static_cast<const unsigned int>(num)];

            Hasher hasher;
            hasher.Reset();
            hasher.Write(block->block.data(), static_cast<size_t>(blockSize));
            hasher.Finalize(hash.hash.data());

            hash.ready = true;
            blocksPool.Release(block);
        }
    }
}

void SignatureGenerator::ShowProgress(float progress)
{
    static const unsigned int BAR_WIDTH = 70UL;
    std::stringstream ss;
    ss << "[";
    int pos = static_cast<int>(BAR_WIDTH * progress);
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
    uint32_t hashCores = (numOfCores >= 3) ? numOfCores - 2 : 1;
    for (uint32_t i = 0; i < hashCores; ++i) // Reserve 2 cores for reader and writer
    {
        hashProcessors.push_back(std::move(std::thread(&SignatureGenerator::HashingThread, this)));
    }

    for (auto& hp : hashProcessors) hp.join();

    fileWriter.join();
    fileReader.join();
}
