#include <rsa.h>
#include <osrng.h>
#include <files.h>
#include <string>
#include <boost/program_options.hpp>

template <typename Key>
void SaveKey(const std::string& filename, const Key& key) {
  CryptoPP::ByteQueue queue;
  key.Save(queue);
  CryptoPP::FileSink file(filename.c_str());
  
  queue.CopyTo(file);
  file.MessageEnd();
}

int main(int argc, char** argv) {
  using namespace CryptoPP;
  namespace po = boost::program_options;

  std::string publicKeyName, privateKeyName;
  size_t keyLength;


  po::options_description desc("Allowed Options");
  desc.add_options()
    ("help", "produce help message")
    ("length,l", po::value<size_t>(&keyLength)->default_value(1024), "set key length")
    ("pubKey,r", po::value<std::string>(&publicKeyName)->default_value("key.pub"), "set public key name")
    ("privKey,u", po::value<std::string>(&privateKeyName)->default_value("key.pem"), "set private key name")
    ;

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);    
  
  if (vm.count("help")) {
    std::cout << desc << "\n";
    return 1;
  }
  
  AutoSeededRandomPool prng;

  InvertibleRSAFunction parameters;
  parameters.GenerateRandomWithKeySize(prng, keyLength);

  RSA::PrivateKey privateKey(parameters);
  RSA::PublicKey publicKey(parameters);

  SaveKey(publicKeyName, publicKey);
  SaveKey(privateKeyName, privateKey);
}
