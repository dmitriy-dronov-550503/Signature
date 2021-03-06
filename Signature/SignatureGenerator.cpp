#include "Windows.h"
#include "SignatureGenerator.h"
#include <boost/filesystem.hpp>

SignatureGenerator::SignatureGenerator(const std::string inputFilePath, const std::string outputFilePath, const uint64_t blockSize) :
    blockSize(blockSize)
{
    inputFile.open(inputFilePath, std::ios::in | std::ios::binary);
    if (!inputFile) throw SignatureGeneratorException("Cannot open input file", ERROR_FILE_NOT_FOUND);
    outputFile.open(outputFilePath, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!outputFile) throw SignatureGeneratorException("Cannot create output file. Does path exist?", ERROR_PATH_NOT_FOUND);
    if (blockSize == 0) throw SignatureGeneratorException("Block size must be greater than zero", ERROR_INVALID_DATA);

    inputFileSize = boost::filesystem::file_size(inputFilePath);
    if (inputFileSize == 0) throw SignatureGeneratorException("Input file is empty", ERROR_INVALID_DATA);
    blocksCount = static_cast<uint64_t>(ceil((double)inputFileSize / (double)blockSize));
    const unsigned int cores = std::thread::hardware_concurrency();
    numOfCores = (cores == 0) ? DEFAULT_NUM_OF_CORES : cores;

    const uint64_t outputFileSize = blocksCount * HASH_SIZE;
    const auto free = boost::filesystem::space(outputFilePath).free;
    if (free < outputFileSize) {
        throw SignatureGeneratorException("Not enough disk space for creating output signature file", ERROR_OUTOFMEMORY);
    }

    // Assuming Blocks Pool can consume no more than 1.5 GB of process memory
    if (static_cast<uint64_t>(numOfCores) * static_cast<uint64_t>(Q_RESERVATION_MULT) * blockSize > BLOCKS_POOL_MEM_LIMIT) {
        throw SignatureGeneratorException("Please, reduce the block size", ERROR_INVALID_DATA);
    }

    blocksPool.Init("SignGen_semaphore", numOfCores * Q_RESERVATION_MULT);

    for (uint32_t i = 0; i < blocksPool.GetMaxItems(); ++i) {
        auto block = std::make_shared<Block>(i, static_cast<size_t>(blockSize));
        blocksPool.Release(block); // Add block to the pool
    }

    hashes.resize(static_cast<size_t>(blocksCount));
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
        boost::unique_lock<boost::mutex> lk(hashes[i].mx);
        while (!hashes[i].ready) {
            hashes[i].cv.wait(lk);
        }

        outputFile.write((char*)hashes[i].hash.data(), HASH_SIZE);
        ShowProgress(static_cast<float>(i) / (static_cast<float>(blocksCount) - 1));
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

            blocksPool.Release(block);

            {
                boost::lock_guard<boost::mutex> lk(hash.mx);
                hash.ready = true;
                hash.cv.notify_all();
            }
        }
    }
}

void SignatureGenerator::ShowProgress(float progress)
{
    static const unsigned int BAR_WIDTH = 70UL;
    std::stringstream ss;
    ss << "[";
    int pos = static_cast<int>(BAR_WIDTH * progress);
    for (uint32_t i = 0; i < BAR_WIDTH; ++i) {
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
