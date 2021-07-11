#include "SignatureGenerator.h"

SignatureGenerator::SignatureGenerator(std::string inputFilePath, std::string outputFilePath, unsigned int blockSize) :
    blockSize(blockSize)
{
    inputFile.open(inputFilePath, std::ios::in | std::ios::binary);
    if (!inputFile) throw std::exception("Cannot find input file");
    outputFile.open(outputFilePath, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!outputFile) throw std::exception("Cannot create output file");
}
