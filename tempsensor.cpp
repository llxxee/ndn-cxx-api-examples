#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fstream>
#include <functional>
#include <iostream>
#include <ndn-cxx/face.hpp>
#include <string>
using namespace ndn;

const std::string prefix = "/alice-home/TEMP";
const std::string device_id = "/bedroom/sensor-1";

class TempSensor {
public:
  TempSensor() {}

  void
  run(std::string filename)
  {
    m_file.open(filename);
    m_face.setInterestFilter("/alice-home/TEMP/CONTENT/current/bedroom",
                             std::bind(&TempSensor::onInterest, this, _2),
                             RegisterPrefixSuccessCallback(),
                             bind(&TempSensor::onRegisterFailed, this, _1, _2));
    m_face.processEvents();
    m_file.close();
  }

private:
  /** CS217B NDN Security Tutorial
   * @todo Demo how to use specific identity/key/certificate to sign the Data packet.
   * @todo Demo how to create a new identity/key in code.
   */
  void
  onInterest(const Interest& interest)
  {
    int temperature;
    if (!(m_file >> temperature)) {
      m_file.seekg(std::ios_base::beg);
      m_file >> temperature;
    }
    Data data(Name(prefix).append("CONTENT").append("current").append(device_id).appendTimestamp());
    data.setFreshnessPeriod(10_ms);
    data.setContent(reinterpret_cast<uint8_t*>(&temperature),
                    sizeof(temperature));
    m_keyChain.sign(data);
    std::cout << "\n******\nInterest Name: " << interest.getName().toUri() << std::endl
              << "Temperature: " << temperature << std::endl
              << "Data Name: " << data.getName().toUri() << std::endl;
    m_face.put(data);
  }

  void
  onRegisterFailed(const Name& prefix, const std::string& reason)
  {
    std::cerr << "ERROR: Failed to register prefix \"" << prefix
              << "\" in local hub's daemon (" << reason << ")" << std::endl;
    m_face.shutdown();
  }

private:
  Face m_face;
  KeyChain m_keyChain;
  std::fstream m_file;
};

int
main(int argc, char* argv[])
{
  if (argc != 2) {
    std::cout << "Usage: " << argv[0] << "<file>" << std::endl;
    return -1;
  }

  TempSensor app;
  try {
    app.run(argv[1]);
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}
