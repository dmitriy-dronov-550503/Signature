#include <Windows.h>
//#include <boost/lambda/lambda.hpp>
#include <boost/program_options.hpp>
//#include <boost/thread/thread.hpp>
//#include <iostream>
//#include <iterator>
//#include <algorithm>
//#include <exception>
//#include <fstream>
#include <filesystem>
//#include <array>
//#include <vector>
//#include <queue>
//#include <mutex>
//#include <thread>
//
//#include <sha256.h>

#include "SignatureGenerator.h"

namespace po = boost::program_options;

#define KB 1024ULL
#define MB (KB * KB)
#define MAX_CORES 12

#define LOGGING_ENABLED 1

int main(int argc, char** argv)
{
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);

    try {
        po::options_description desc("This program calculates signature of the file. It divides inputFile into blocks with fixed size, \
            calculates hashes for each block and writes them to the outputFile. \
            By default block size is 1 MB");
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
            inputFilePath = args["input"].as<std::string>();

            if (!std::filesystem::exists(inputFilePath)) {
                throw std::exception("Input file does not exist");
            }
        }
        else {
            throw std::exception("Input file is required")
        }

        if (args.count("output")) {
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

        SignatureGenerator sg(inputFilePath, outputFilePath, blockSize);
        sg.Generate();
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
