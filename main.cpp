#include <string>
#include <iostream>
#include <rsa.h>
#include <osrng.h>
#include <files.h>
#include <string>
#include <boost/program_options.hpp>

template <typename Key>
const Key loadKey(const std::string& filename)
{
  Key key;
  CryptoPP::ByteQueue queue;
  CryptoPP::FileSource file(filename.c_str(), true);
  file.TransferTo(queue);
  queue.MessageEnd();

  key.Load(queue);
  return key;
}


int main(int argc, char** argv) {
  using namespace CryptoPP;
  namespace po = boost::program_options;

  std::string privateKeyName, publicKeyName, plainText;
  
    po::options_description desc("Allowed Options");
  desc.add_options()
    ("help", "produce help message")
    ("plainText,l", po::value<std::string>(&plainText)->default_value("test"), "set plain text")
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


  privateKeyName = "key.pem";
  publicKeyName = "key.pub";
  AutoSeededRandomPool prng;

  auto privateKey = loadKey<RSA::PrivateKey>(privateKeyName);
  auto publicKey = loadKey<RSA::PublicKey>(publicKeyName);

  std::string encrypted, decrypted;
  RSAES_OAEP_SHA_Encryptor e(publicKey);

  StringSource(plainText, true,
	       new PK_EncryptorFilter(prng, e,
				      new StringSink(encrypted)));

  RSAES_OAEP_SHA_Decryptor d(privateKey);

  StringSource(encrypted, true,
	       new PK_DecryptorFilter(prng, d,
				      new StringSink(decrypted)));

  std::cout << plainText << " ---> " << encrypted << " <--- " << decrypted << std::endl;
}
