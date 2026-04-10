/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file unit_ATECC608B_TNGTLS.hpp
  @brief ATECC608B-TNGTLS Unit for M5UnitUnified
*/
#ifndef M5_UNIT_CRYPTO_UNIT_ATECC608B_TNGTLS_HPP
#define M5_UNIT_CRYPTO_UNIT_ATECC608B_TNGTLS_HPP

#include "unit_ATECC608B.hpp"

namespace m5 {
namespace unit {

/*!
  @class m5::unit::UnitATECC608B_TNGTLS
  @brief ATECC608B-TNGTLS unit
*/
class UnitATECC608B_TNGTLS : public UnitATECC608B {
    M5_UNIT_COMPONENT_HPP_BUILDER(UnitATECC608B_TNGTLS, 0x35);

public:
    explicit UnitATECC608B_TNGTLS(const uint8_t addr = DEFAULT_ADDRESS) : UnitATECC608B(addr)
    {
    }
    virtual ~UnitATECC608B_TNGTLS()
    {
    }

    ///@name Random
    ///@{
    /*!
      @brief Read TRNG output
      @param[out] data Output value (At least 32 bytes)
      @param[in] updateSeed Ignored. ATECC608B-TNGTLS only supports Mode=0x00 (UPDATE_SEED).
      @return True if successful
      @warning The @p updateSeed parameter is not supported on ATECC608B-TNGTLS (DS40002250A Table 5-19).
      The RNG seed is always updated regardless of this argument.
     */
    bool readRandomArray(uint8_t data[32], const bool updateSeed = true) override;
    ///@}

    ///@name Certificate
    ///@{
    /*!
      @brief Read the device certificate (DER)
      @param[out] out Output buffer
      @param[in,out] in:Output buffer length out:Length of output to buffer
      @param fillAuthKeyId Fill auth key id from signer if true
      @return True if successful
     */
    bool readDeviceCertificate(uint8_t* out, uint16_t& olen, const bool fillAuthKeyId = true);
    /*!
      @brief Read the signer certificate (DER)
      @param[out] out Output buffer
      @param[in,out] in:Output buffer length out:Length of output to buffer
      @return True if successful
     */
    bool readSignerCertificate(uint8_t* out, uint16_t& olen);
    ///@}

protected:
    virtual bool begin_impl() override;

    virtual bool ecdh_receive32(uint8_t out[32], const uint8_t mode, const uint16_t param2,
                                const uint8_t pubKey[64]) override;
    virtual bool ecdh_receive32x2(uint8_t out[32], uint8_t nonce[32], const uint8_t mode, const uint16_t param2,
                                  const uint8_t pubKey[64]) override;
    virtual bool ecdh_no_output(const uint8_t mode, const uint16_t param2, const uint8_t pubKey[64]) override;

    virtual bool generate_key(uint8_t pubKey[64], const uint8_t mode, const uint16_t param2 = 0x0000,
                              const uint8_t* data = nullptr, const uint32_t dlen = 0) override;
    virtual bool sign(uint8_t signature[64], const uint8_t mode, const uint16_t param2,
                      const atecc608::Source src) override;
};

}  // namespace unit
}  // namespace m5
#endif
