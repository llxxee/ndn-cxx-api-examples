#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fstream>
#include <functional>
#include <iostream>
#include <ndn-cxx/face.hpp>
#include <string>
#include <ndn-cxx/security/validator-config.hpp>
#include <ndn-cxx/security/v2/validator.hpp>
#include <ndn-cxx/security/v2/validation-callback.hpp>
#include <ndn-cxx/security/v2/certificate-fetcher-offline.hpp>
using namespace ndn;

const std::string prefix = "/alice-home/AIRCON";
const std::string device_id = "/bedroom/aircon-1";

class AirCon {
public:
  AirCon() : m_state("off") {}

  void
  run()
  {
    m_face.registerPrefix(prefix, RegisterPrefixSuccessCallback(),
                          bind(&AirCon::onRegisterFailed, this, _1, _2));
    m_face.setInterestFilter(prefix + "/CMD",
                             std::bind(&AirCon::onCommand, this, _2));
    m_face.setInterestFilter(prefix + "/CONTENT/state",
                             std::bind(&AirCon::onInterest, this, _2));
    m_face.processEvents();
  }

private:
  /** CS217B NDN Security Tutorial
   * @todo Demo how to use specific identity/key/certificate to sign the Data packet.
   * @todo Demo how to create a new identity/key in code.
   *
   * This part is the same as the one used in TempSensor. Will be omitted.
   */
  void
  onInterest(const Interest& interest)
  {
    Data data(Name(prefix).append("CONTENT").append("state").append(device_id).appendTimestamp());
    data.setFreshnessPeriod(10_ms);
    data.setContent(reinterpret_cast<const uint8_t*>(m_state.c_str()),
                    m_state.length() + 1);
    m_keyChain.sign(data);
    std::cout << "\n******\nInterest Name: " << interest.getName().toUri() << std::endl
              << "State: " << m_state << std::endl
              << "Data Name: " << data.getName().toUri() << std::endl;
    m_face.put(data);
  }

  /** CS217B NDN Security Tutorial
   * @todo Demo how to use specific identity/key/certificate to verify Interest's signature.
   * @todo Demo how to use trust schema to verify Interest's signature.
   *
   * Must first finish the Interest signing part in controller.
   */
  void
  onCommand(const Interest& interest)
  {
    namespace ndnsec = ndn::security::v2;
    //ndnsec::Validator validator(make_unique<ndnsec::ValidationPolicyConfig>(), make_unique<ndnsec::CertificateFetcherOffline>());
    const auto& pib = m_keyChain.getPib();
    const auto& identity = pib.getIdentity(Name("/alice-home"));
    const auto& key = identity.getDefaultKey();
    std::cout << security::verifySignature(interest, key.getPublicKey().get<uint8_t>(), key.getPublicKey().size()) << std::endl;

    //auto& config = static_cast<ndnsec::ValidationPolicyConfig&>(validator.getPolicy());
    //config.load("schema.conf");
    //validator.validate(interest,
    //[this](auto interest) {
      std::cout << "ValidatorConfig::NICE. Command Interest has a valid signature" << std::endl;
      Data data(interest.getName());
      m_state = interest.getName()[3].toUri();
      m_keyChain.sign(data);
      std::cout << "\n******\nInterest Name: " << interest.getName().toUri() << std::endl
                << "New State: " << m_state << std::endl;
      m_face.put(data);
    //},
    //[](auto v, auto error) {
    //  std::cout << "Error is " << error.getInfo() << std::endl;
    //});
  }
  // void
  // onCommand(const Interest& interest)
  // {
  //   namespace ndnsec = ndn::security::v2;
  //   ndnsec::Validator validator(make_unique<ndnsec::ValidationPolicyConfig>(), make_unique<ndnsec::CertificateFetcherOffline>());
  //   auto& config = static_cast<ndnsec::ValidationPolicyConfig&>(validator.getPolicy());
  //   config.load("schema.conf");
  //   validator.validate(interest,
  //   [this](auto interest) {
  //     std::cout << "ValidatorConfig::NICE. Command Interest has a valid signature" << std::endl;
  //     Data data(interest.getName());
  //     m_state = interest.getName()[3].toUri();
  //     m_keyChain.sign(data);
  //     std::cout << "\n******\nInterest Name: " << interest.getName().toUri() << std::endl
  //               << "New State: " << m_state << std::endl;
  //     m_face.put(data);
  //   },
  //   [](auto v, auto error) {
  //     std::cout << "Error is " << error.getInfo() << std::endl;
  //   });
  // }

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
  std::string m_state;
};

int
main(int argc, char* argv[])
{
  AirCon app;
  try {
    app.run();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}
