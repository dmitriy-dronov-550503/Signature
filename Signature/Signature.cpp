#include <Windows.h>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include "SignatureGenerator.h"

namespace po = boost::program_options;

int main(int argc, char** argv)
{
    int errorCode = ERROR_SUCCESS;

    try {
        po::options_description desc("This program calculates signature of the file. It divides input file into blocks of a fixed size, \
calculates hashes for each block and writes hashes to output file. By default block size is 1 MB");
        desc.add_options()
            ("help", "shows this message")
            ("input,if", po::value<std::string>(), "Input file")
            ("output,of", po::value<std::string>(), "Output file")
            ("block,bs", po::value<int>(), "Block size in KB");

        po::variables_map args;
        po::store(po::parse_command_line(argc, argv, desc), args);
        po::notify(args);

        // Initialize input variables
        std::string inputFilePath = "";
        std::string outputFilePath = "";
        uint64_t blockSize = 0;

        do {
            if (args.count("help") || args.empty()) {
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
                int bsArg = args["block"].as<int>();
                
                if (bsArg <= 0) {
                    std::cerr << "Block size must be greater than zero" << std::endl;
                    break;
                }

                blockSize = bsArg * KB; // Convert from kylobytes to bytes
            }
            else
            {
                std::cout << "Block size is set to default 1 MB" << std::endl;
                blockSize = 1 * MB;
            }

            SignatureGenerator sg(inputFilePath, outputFilePath, blockSize);
            sg.Generate();

        } while (false);
    }
    catch (boost::program_options::invalid_option_value& e) {
        std::cerr << e.what() << std::endl;
        errorCode = ERROR_INVALID_FUNCTION;
    }
    catch (boost::program_options::unknown_option& e) {
        std::cerr << e.what() << std::endl;
        errorCode = ERROR_INVALID_FUNCTION;
    }
    catch (SignatureGeneratorException& e) {
        std::cerr << e.What() << std::endl;
        errorCode = e.ErrorCode();
    }
    catch (boost::exception& e) {
        std::cerr << "Boost library exception occured. Please, report a bug" << std::endl;
        std::cerr << "Exception description: " << boost::diagnostic_information(e) << std::endl;
        errorCode = ERROR_INVALID_FUNCTION;
    }
    catch (std::bad_alloc& e) {
        std::cerr << "Bad allocation. Try varying the size of the block" << std::endl;
        std::cerr << "Exception description: " << e.what() << std::endl;
        errorCode = ERROR_NOT_ENOUGH_MEMORY;
    }
    catch (std::exception& e) {
        std::cerr << "Standart library exception occured. Please, report a bug" << std::endl;
        std::cerr << "Exception description: " << e.what() << std::endl;
        errorCode = ERROR_INVALID_FUNCTION;
    }
    catch (...) {
        std::cerr << "Exception of unknown type!" << std::endl;
        errorCode = ERROR_INVALID_FUNCTION;
    }
    return errorCode;
}
