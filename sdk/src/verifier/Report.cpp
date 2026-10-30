//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <Report.hpp>
#include <cstddef>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include "ed25519/ed25519.h"

using json11::Json;
std::string
Report::BytesToHex(byte* bytes, size_t len) {
  unsigned int i;
  std::string str;
  for (i = 0; i < len; i += 1) {
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << std::hex << (uintptr_t)bytes[i];

    str += ss.str();
  }
  return str;
}

void
Report::HexToBytes(byte* bytes, size_t len, std::string hexstr) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    unsigned int data = 0;
    std::stringstream ss;
    ss << hexstr.substr(i * 2, 2);
    ss >> std::hex >> data;
    bytes[i] = (byte)data;
  }
}

void
Report::fromJson(std::string jsonstr) {
  std::string err;
  const auto json = Json::parse(jsonstr, err);

  std::string device_pubkey = json["device_pubkey"].string_value();
  HexToBytes(report.dev_public_key, PUBLIC_KEY_SIZE, device_pubkey);

  std::string sm_hash = json["security_monitor"]["hash"].string_value();
  HexToBytes(report.sm.hash, MDSIZE, sm_hash);
  std::string sm_pubkey = json["security_monitor"]["pubkey"].string_value();
  HexToBytes(report.sm.public_key, PUBLIC_KEY_SIZE, sm_pubkey);
  std::string sm_signature =
      json["security_monitor"]["signature"].string_value();
  HexToBytes(report.sm.signature, SIGNATURE_SIZE, sm_signature);

  std::string enclave_hash = json["enclave"]["hash"].string_value();
  HexToBytes(report.enclave.hash, MDSIZE, enclave_hash);
  report.enclave.report_version =
      static_cast<uint64_t>(json["enclave"]["report_version"].number_value());
  report.enclave.security_policy_version =
      static_cast<uint64_t>(
          json["enclave"]["security_policy_version"].number_value());
  report.enclave.group_id =
      static_cast<uint64_t>(json["enclave"]["group_id"].number_value());
  report.enclave.group_generation =
      static_cast<uint64_t>(json["enclave"]["group_generation"].number_value());
  report.enclave.group_role =
      static_cast<uint64_t>(json["enclave"]["group_role"].number_value());
  report.enclave.group_hart_mask =
      static_cast<uint64_t>(json["enclave"]["group_hart_mask"].number_value());
  report.enclave.bound_hart =
      static_cast<uint64_t>(json["enclave"]["bound_hart"].number_value());
  report.enclave.allowed_slice_mask =
      static_cast<uint64_t>(
          json["enclave"]["allowed_slice_mask"].number_value());
  report.enclave.membership_epoch =
      static_cast<uint64_t>(
          json["enclave"]["membership_epoch"].number_value());
  report.enclave.phase_epoch =
      static_cast<uint64_t>(json["enclave"]["phase_epoch"].number_value());
  report.enclave.session_epoch =
      static_cast<uint64_t>(json["enclave"]["session_epoch"].number_value());
  std::string runtime_hash = json["enclave"]["runtime_hash"].string_value();
  HexToBytes(report.enclave.runtime_hash, MDSIZE, runtime_hash);
  std::string group_session_hash =
      json["enclave"]["group_session_hash"].string_value();
  HexToBytes(report.enclave.group_session_hash, MDSIZE, group_session_hash);
  report.enclave.data_len  = json["enclave"]["datalen"].int_value();
  std::string enclave_data = json["enclave"]["data"].string_value();
  HexToBytes(report.enclave.data, report.enclave.data_len, enclave_data);
  std::string enclave_signature = json["enclave"]["signature"].string_value();
  HexToBytes(report.enclave.signature, SIGNATURE_SIZE, enclave_signature);
}

void
Report::fromBytes(byte* bin) {
  std::memcpy(&report, bin, sizeof(struct report_t));
}

std::string
Report::stringfy() {
  if (report.enclave.data_len > ATTEST_DATA_MAXLEN) {
    return "{ \"error\" : \"invalid data length\" }";
  }
  auto json = Json::object{
      {"device_pubkey", BytesToHex(report.dev_public_key, PUBLIC_KEY_SIZE)},
      {
          "security_monitor",
          Json::object{
              {"hash", BytesToHex(report.sm.hash, MDSIZE)},
              {"pubkey", BytesToHex(report.sm.public_key, PUBLIC_KEY_SIZE)},
              {"signature", BytesToHex(report.sm.signature, SIGNATURE_SIZE)}},
      },
      {
          "enclave",
          Json::object{
              {"hash", BytesToHex(report.enclave.hash, MDSIZE)},
              {"report_version",
               static_cast<double>(report.enclave.report_version)},
              {"security_policy_version",
               static_cast<double>(report.enclave.security_policy_version)},
              {"group_id", static_cast<double>(report.enclave.group_id)},
              {"group_generation",
               static_cast<double>(report.enclave.group_generation)},
              {"group_role", static_cast<double>(report.enclave.group_role)},
              {"group_hart_mask",
               static_cast<double>(report.enclave.group_hart_mask)},
              {"bound_hart", static_cast<double>(report.enclave.bound_hart)},
              {"allowed_slice_mask",
               static_cast<double>(report.enclave.allowed_slice_mask)},
              {"membership_epoch",
               static_cast<double>(report.enclave.membership_epoch)},
              {"phase_epoch",
               static_cast<double>(report.enclave.phase_epoch)},
              {"session_epoch",
               static_cast<double>(report.enclave.session_epoch)},
              {"runtime_hash",
               BytesToHex(report.enclave.runtime_hash, MDSIZE)},
              {"group_session_hash",
               BytesToHex(report.enclave.group_session_hash, MDSIZE)},
              {"datalen", static_cast<int>(report.enclave.data_len)},
              {"data",
               BytesToHex(report.enclave.data, report.enclave.data_len)},
              {"signature",
               BytesToHex(report.enclave.signature, SIGNATURE_SIZE)},
          },
      },
  };

  return json11::Json(json).dump();
}

void
Report::printJson() {
  std::cout << stringfy() << std::endl;
}

void
Report::printPretty() {
  std::cout << "\t\t=== Security Monitor ===" << std::endl;
  std::cout << "Hash: " << BytesToHex(report.sm.hash, MDSIZE) << std::endl;
  std::cout << "Pubkey: " << BytesToHex(report.sm.public_key, PUBLIC_KEY_SIZE)
            << std::endl;
  std::cout << "Signature: " << BytesToHex(report.sm.signature, SIGNATURE_SIZE)
            << std::endl;
  std::cout << std::endl << "\t\t=== Enclave Application ===" << std::endl;
  std::cout << "Hash: " << BytesToHex(report.enclave.hash, MDSIZE) << std::endl;
  std::cout << "Runtime Hash: "
            << BytesToHex(report.enclave.runtime_hash, MDSIZE) << std::endl;
  std::cout << "Group: id=" << report.enclave.group_id
            << " generation=" << report.enclave.group_generation
            << " role=" << report.enclave.group_role
            << " hart_mask=0x" << std::hex << report.enclave.group_hart_mask
            << " slice_mask=0x" << report.enclave.allowed_slice_mask
            << std::dec << " session=" << report.enclave.session_epoch
            << std::endl;
  std::cout << "Signature: "
            << BytesToHex(report.enclave.signature, SIGNATURE_SIZE)
            << std::endl;
  std::cout << "Enclave Data: "
            << BytesToHex(report.enclave.data, report.enclave.data_len)
            << std::endl;
  std::cout << "\t\t-- Device pubkey --" << std::endl;
  std::cout << BytesToHex(report.dev_public_key, PUBLIC_KEY_SIZE) << std::endl;
}

byte*
Report::getEnclaveHash() {
    return report.enclave.hash;
}

byte*
Report::getSmHash() {
    return report.sm.hash;
}

int
Report::verify(
    const byte* expected_enclave_hash, const byte* expected_sm_hash,
    const byte* dev_public_key) {
  /* verify that enclave hash matches */
  int encl_hash_valid =
      memcmp(expected_enclave_hash, report.enclave.hash, MDSIZE) == 0;
  int sm_hash_valid = memcmp(expected_sm_hash, report.sm.hash, MDSIZE) == 0;

  int signature_valid = checkSignaturesOnly(dev_public_key);

  return encl_hash_valid && sm_hash_valid && signature_valid;
}

int
Report::checkSignaturesOnly(const byte* dev_public_key) {
  int sm_valid      = 0;
  int enclave_valid = 0;

  /* verify SM report */
  sm_valid = ed25519_verify(
      report.sm.signature, reinterpret_cast<byte*>(&report.sm),
      MDSIZE + PUBLIC_KEY_SIZE, dev_public_key);

  if (report.enclave.data_len > ATTEST_DATA_MAXLEN)
    return 0;

  /* verify Enclave report */
  enclave_valid = ed25519_verify(
      report.enclave.signature, reinterpret_cast<byte*>(&report.enclave),
      offsetof(struct enclave_report_t, data) + report.enclave.data_len,
      report.sm.public_key);

  return sm_valid && enclave_valid;
}

void*
Report::getDataSection() {
  return report.enclave.data;
}

size_t
Report::getDataSize() {
  return report.enclave.data_len;
}
