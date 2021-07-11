#include <Windows.h>
#include <boost/lambda/lambda.hpp>
#include <boost/program_options.hpp>
#include <boost/thread/thread.hpp>
#include <boost/interprocess/sync/named_semaphore.hpp>
#include <iostream>
#include <iterator>
#include <algorithm>
#include <exception>
#include <fstream>
#include <filesystem>
#include <array>
#include <vector>
#include <queue>
#include <mutex>
#include <thread>

#include <sha256.h>


namespace po = boost::program_options;

#define KB 1024ULL
#define MB (KB * KB)
#define MAX_CORES 12


struct BlockItem
{
    uintmax_t number;
    std::vector<unsigned char> block;

    BlockItem(uintmax_t n, std::vector<unsigned char> b)
        : number(n), block(b) {}
};

struct HashItem
{
    uintmax_t number;
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> hash;

    HashItem(uintmax_t n, std::array<unsigned char, CSHA256::OUTPUT_SIZE> h)
        : number(n), hash(h) {}
};

class HashItemCompare
{
public:
    bool operator() (const HashItem& left, const HashItem& right)
    {
        return left.number > right.number;
    }
};

class SignatureGenerator2
{
private:
    std::ifstream inputFile;
    std::ofstream outputFile;
    const size_t blockSize;
    uintmax_t inputFileSize;
    
    std::queue<BlockItem> blocks;
    std::priority_queue<HashItem, std::vector<HashItem>, HashItemCompare> hashes;
    std::mutex blocks_mutex;
    std::mutex hashes_mutex;

    boost::mutex m_mutex;
    boost::condition_variable cv;

    bool makeCalculation = true;

    std::mutex log_mutex;

    const char* const semaphoreName = "hash_thrds_sync";
    unsigned int maxNumberOfCores;
    static const unsigned int defaultNumOfCores = 8;

public:
    double blocksCount;

    SignatureGenerator2() = delete;

    SignatureGenerator2(std::string inputFilePath, std::string outputFilePath, size_t bSize) : blockSize(bSize) {
        inputFile.open(inputFilePath, std::ios::binary);
        outputFile.open(outputFilePath, std::ios::out | std::ios::trunc | std::ios::binary);
        inputFileSize = std::filesystem::file_size(inputFilePath);
        blocksCount = ceil((double)inputFileSize / (double)blockSize);

        const uintmax_t outputFileSize = blocksCount * CSHA256::OUTPUT_SIZE;
        const auto si = std::filesystem::space(outputFilePath);
        if (si.available < outputFileSize) {
            throw std::exception("Not enough disk space for creating signature file");
        }

        const unsigned int cores = std::thread::hardware_concurrency();
        maxNumberOfCores = (cores == 0) ? defaultNumOfCores : cores;

        boost::interprocess::named_semaphore::remove(semaphoreName);
        boost::interprocess::named_semaphore semaphore(boost::interprocess::create_only_t(), semaphoreName, maxNumberOfCores * 4);
    }

    void run() {
        std::thread rft(&SignatureGenerator2::readFileThread, this);
        //SetThreadAffinityMask(rft.native_handle(), 1 << maxNumberOfCores-1);

        std::vector<std::thread> threads;
        for (int i = 0; i < maxNumberOfCores - 1; i++) // reserve at least 2 threads for read/write to files
        {
            threads.push_back(std::thread(&SignatureGenerator2::calculateHashThread, this));
            //SetThreadAffinityMask(threads[i].native_handle(), 1 << i);
        }
        
        std::thread wft(&SignatureGenerator2::writeFileThread, this);
        //SetThreadAffinityMask(wft.native_handle(), 1 << maxNumberOfCores);
        
        for (auto& t : threads) t.join();

        rft.join();
        wft.join();

    }

    // This thread is able to read block from the file and put them into queue
    void readFileThread() {
        boost::interprocess::named_semaphore semaphore(boost::interprocess::open_only_t(), semaphoreName);
        try {
            for (int i = 0; i < blocksCount; ++i) {
                std::vector<unsigned char> buf(blockSize);
                inputFile.read((char*)buf.data(), blockSize);
                blocks_mutex.lock();
                blocks.push(BlockItem(i, buf));
                blocks_mutex.unlock();
                log_mutex.lock();
                std::cout << "Reading block " << i << " out of " << blocksCount << std::endl;
                log_mutex.unlock();
                semaphore.wait();
            }
        }
        catch (std::exception& e) {
            std::wcerr << "error: " << e.what() << "\n";
        }
    }

    DWORD GetCurrentProcessorNumberXP(void)
    {
        _asm {mov eax, 1}
        _asm {cpuid}
        _asm {shr ebx, 24}
        _asm {mov eax, ebx}
    }

    // This thread calculates hash for the block
    void calculateHashThread() {
        boost::interprocess::named_semaphore semaphore(boost::interprocess::open_only_t(), semaphoreName);
        while (makeCalculation) {
            blocks_mutex.lock();
            if (!blocks.empty()) {
                BlockItem bi = blocks.front();
                blocks.pop();
                blocks_mutex.unlock();

                uintmax_t number = bi.number;
                std::vector<unsigned char> buf = bi.block;

                log_mutex.lock();
                std::cout << "Calculate hash for block " << number << std::endl;
                std::cout << "Thread #" << std::this_thread::get_id() << ": on CPU " << GetCurrentProcessorNumberXP() << "\n";
                log_mutex.unlock();

                // Calculate SHA256 hash
                CSHA256 hasher;
                std::array<unsigned char, CSHA256::OUTPUT_SIZE> hash;

                hasher.Reset();
                hasher.Write(buf.data(), blockSize);
                hasher.Finalize(hash.data());

                //number = rand() % 1000; // !!! TODO: Remove it

                hashes_mutex.lock();
                hashes.push(HashItem(number, hash));
                hashes_mutex.unlock();

                semaphore.post();

                {
                    boost::mutex::scoped_lock lock(m_mutex);
                    cv.notify_all();
                }
            }
            else
            {
                blocks_mutex.unlock();
            }
        }
    }

    // This thread pops hashes and writes them to the output file
    void writeFileThread() {
        bool processingFinished = false;
        uintmax_t currentBlock = 0;
        double blocksLeft = blocksCount - 1;
        do {
            hashes_mutex.lock();
            if (!hashes.empty()) {
                HashItem hi = hashes.top();

                if (currentBlock != hi.number) {
                    std::cout << "====== GOT WRONG SEQUENCE ======" << std::endl;
                    hashes_mutex.unlock();
                    boost::mutex::scoped_lock lock(m_mutex);
                    cv.wait(lock);
                    continue;
                }

                hashes.pop();
                hashes_mutex.unlock();

                outputFile.seekp(hi.number * CSHA256::OUTPUT_SIZE);
                outputFile.write((char*)hi.hash.data(), CSHA256::OUTPUT_SIZE);
                log_mutex.lock();
                std::cout << "Writing block " << hi.number << " out of " << blocksCount << " Progress: " << (blocksCount - blocksLeft) / blocksCount * 100 << " %" << std::endl;
                log_mutex.unlock();
                blocksLeft--;
                if (hi.number == blocksCount - 1) {
                    processingFinished = true;
                }
                currentBlock++;
            }
            else {
                hashes_mutex.unlock();
            }
        } while (!processingFinished);
        makeCalculation = false;
    }

    ~SignatureGenerator2() {
        outputFile.close();
        inputFile.close();
        boost::interprocess::named_semaphore::remove(semaphoreName);
    }
};


int main(int argc, char** argv)
{
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);

    try {

        po::options_description desc("Calculate signature for the file");
        desc.add_options()
            ("help", "shows this message")
            ("input,if", po::value<std::string>(), "Input file")
            ("output,of", po::value<std::string>(), "Output file")
            ("block,bs", po::value<size_t>(), "Block size in KB");


        po::variables_map args;
        po::store(po::parse_command_line(argc, argv, desc), args);
        po::notify(args);

        if (args.count("help")) {
            std::cout << desc << std::endl;
            return 0;
        }

        // Initialize input variables
        std::string inputFilePath = "";
        std::string outputFilePath = "";
        size_t blockSize = 0;

        if (args.count("input")) {
            std::cout << "Input file set to " << args["input"].as<std::string>() << std::endl;
            inputFilePath = args["input"].as<std::string>();
        }

        if (args.count("output")) {
            std::cout << "Output file set to " << args["output"].as<std::string>() << std::endl;
            outputFilePath = args["output"].as<std::string>();
        }

        if (args.count("block")) {
            std::cout << "Block size set to " << args["block"].as<size_t>() << std::endl;
            blockSize = args["block"].as<size_t>() * KB; // Read and convert block size from kilobytes to bytes
        }
        else
        {
            blockSize = 1 * MB;
        }

        SignatureGenerator2 sg(inputFilePath, outputFilePath, blockSize);

        sg.run();

        /*sg.readFileThread();

        for (int i = 0; i < sg.blocksCount; i++) {
            sg.calculateHashThread();
        }

        sg.writeFileThread();*/
    }
    catch (std::exception& e) {
        std::wcerr << "error: " << e.what() << "\n";
        return 1;
    }
    catch (...) {
        std::wcerr << "Exception of unknown type!\n";
        return 1;
    }
    return 0;
}
