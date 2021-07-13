#include <Windows.h>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include "SignatureGenerator.h"

namespace po = boost::program_options;

#define KB 1024ULL
#define MB (KB * KB)

int main(int argc, char** argv)
{
    int errorCode = ERROR_SUCCESS;

    try {
        po::options_description desc("This program calculates signature of the file. It divides inputFile into blocks with fixed size, \
calculates hashes for each block and writes them to the outputFile. By default block size is 1 MB");
        desc.add_options()
            ("help", "shows this message")
            ("input,if", po::value<std::string>(), "Input file")
            ("output,of", po::value<std::string>(), "Output file")
            ("block,bs", po::value<uint32_t>(), "Block size in KB");


        po::variables_map args;
        po::store(po::parse_command_line(argc, argv, desc), args);
        po::notify(args);

        // Initialize input variables
        std::string inputFilePath = "";
        std::string outputFilePath = "";
        size_t blockSize = 0;

        do {
            if (args.count("help")) {
                std::cout << desc << std::endl;
                break;
            }

            if (args.count("input")) {
                inputFilePath = args["input"].as<std::string>();
            }
            else {
                std::cerr << "Input file is a required parameter" << std::endl;
                break;
            }

            if (!(boost::filesystem::exists(inputFilePath) && boost::filesystem::is_regular_file(inputFilePath))) {
                std::cerr << "Input file does not exist" << std::endl;
                break;
            }

            if (args.count("output")) {
                outputFilePath = args["output"].as<std::string>();
            }
            else {
                std::cerr << "Output file is a required parameter" << std::endl;
                break;
            }

            if (args.count("block")) {
                blockSize = args["block"].as<size_t>() * KB; // Read and convert block size from kilobytes to bytes
            }
            else
            {
                std::cout << "Block size is set to default 1 MB size" << std::endl;
                blockSize = 1 * MB;
            }

            SignatureGenerator sg(inputFilePath, outputFilePath, blockSize);
            sg.Generate();

        } while (false);
    }
    catch (SignatureGeneratorException& e) {
        std::cerr << e.What() << std::endl;
        errorCode = e.ErrorCode();
    }
    catch (boost::exception&) {
        std::cerr << "Boost library exception occured. Please, report a bug\n";
        errorCode = ERROR_INVALID_FUNCTION;
    }
    catch (std::bad_alloc& e) {
        std::cerr << "Bad allocation. Try varying the size of the block\n";
        std::cerr << "Exception description: " << e.what() << std::endl;
        errorCode = ERROR_NOT_ENOUGH_MEMORY;
    }
    catch (std::exception& e) {
        std::cerr << "Standart library exception occured. Please, report a bug\n";
        std::wcerr << "Exception description: " << e.what() << "\n";
        errorCode = ERROR_INVALID_FUNCTION;
    }
    catch (...) {
        std::wcerr << "Exception of unknown type!\n";
        errorCode = ERROR_INVALID_FUNCTION;
    }
    return errorCode;
}
