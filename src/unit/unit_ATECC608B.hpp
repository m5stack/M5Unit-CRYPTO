/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file unit_ATECC608B.hpp
  @brief ATECC608B Unit for M5UnitUnified
*/
#ifndef M5_UNIT_CRYPTO_UNIT_ATECC608B_HPP
#define M5_UNIT_CRYPTO_UNIT_ATECC608B_HPP

#include "atecc608.hpp"
#include <M5UnitComponent.hpp>
#include <m5_utility/container/circular_buffer.hpp>
#include <array>
#include <limits>

namespace m5 {
namespace unit {

/*!
  @class m5::unit::UnitATECC608B
  @brief ATECC608B unit
*/
class UnitATECC608B : public Component {
    M5_UNIT_COMPONENT_HPP_BUILDER(UnitATECC608B, 0x35);

public:
    /*!
      @struct config_t
      @brief Settings for begin
     */
    struct config_t {
        //! Device to idle on begin?
        bool idle{true};
    };

    explicit UnitATECC608B(const uint8_t addr = DEFAULT_ADDRESS) : Component(addr)
    {
        auto ccfg  = component_config();
        ccfg.clock = 400 * 1000U;
        component_config(ccfg);
    }
    virtual ~UnitATECC608B()
    {
    }

    virtual bool begin() override;

    ///@name Settings for begin
    ///@{
    /*! @brief Gets the configration */
    inline config_t config()
    {
        return _cfg;
    }
    //! @brief Set the configration
    inline void config(const config_t& cfg)
    {
        _cfg = cfg;
    }
    ///@}

    ///@name State transition
    ///@{
    /*!
      @brief Device to active
      @return True if successful
      @note The following error message is output, but can be ignored
      @note "write_with_transaction(): 2 endTransmission stop:1"
     */
    bool wakeup();
    /*!
      @brief Device to idle
      @return True if successful
      @note Keep SRAM memory
     */
    bool idle();
    /*!
      @brief Device to sleep
      @return True if successful
      @warning Clear SRAM memory (TempKey,Message Digest Buffer,Alternate Key Buffer, SHA Context Buffer,...)
    */
    bool sleep();
    ///@}

    ///@name Counter
    ///@{
    /*!
      @brief Read the counter value
      @param[out] value Counter value
      @param target Target counter (0 or 1)
      @return True if successful
      @note The maximum value that the counter may have is 2097151 (0x1fffff)
     */
    inline bool readCounter(uint32_t& value, const uint8_t target)
    {
        return counter(value, target, 0 /*read*/);
    }
    /*!
      @brief Increment counter
      @param[out] value Counter value (incremented)
      @param target Target counter (0 or 1)
      @return True if successful
      @note The maximum value that the counter may have is 2097151 (0x1fffff)
     */
    inline bool incrementCounter(uint32_t& value, const uint8_t target)
    {
        return counter(value, target, 1 /* increment */);
    }
    ///@}

    ///@name Info
    ///@{
    /*!
      @brief Read the revision
      @param[out] data[4] Output buffer at least 4 bytes
      @return True if successful
     */
    bool readRevision(uint8_t data[4]);
    /*!
      @brief Read the KeyValid
      @details Is the ECC private or public key a valid ECC key?
      @param[out] valid ECC key is valid if true
      @param slot Slot
      @return True if successful
     */
    bool readKeyValid(bool& valid, const atecc608::Slot slot);
    /*!
      @brief Read the device state
      @param[out] state Device status
      @return True if successful
      @note Status flags
      |bit|name|decription|
      |---|---|---|
      |15|TempKey.Valid| Valid if 1|
      |14:11|AuthComplete.KeyID|Authorization keyslot ID|
      |10|AuthComplete.Valid| Valid if 1|
      |9:8| | No use|
      |7|TempKey.NoMacFlag| Valid if 1|
      |6|TempKey.GenKeyData| Valid if 1|
      |5|TempKey.GenDigData| Valid if 1|
      |4|TempKey.SourceFlag| Fixed souerce if 1, RNG source if 0|
      |3:0|TempKey.KeyID| TempKey keyslot ID|
     */
    bool readDeviceState(uint16_t& state);
    ///@}

    ///@name Nonce
    ///@{
    /*!
      @brief Create nonce by input data with RNG or TempKey.
      @param dest Output destination
      @param[out] output Output buffer at least 32 bytes if not nullptr
      @param input Input buffer at least 20 bytes
      @param useRNG Using TRNG if true, Using TempKey if false
      @param updateSeed Update seed if true
      @return True if successful
      @warning If useRNG is false, TempKey must already have a valid value
    */
    bool createNonce(const atecc608::Destination dest, uint8_t output[32], const uint8_t input[20],
                     const bool useRNG = true, const bool updateSeed = true);

    /*!
      @brief write nonce 32 bytes
      @param dest Output destination
      @param input Input buffer at least 32 bytes
      @return True if successful
     */
    bool writeNonce32(const atecc608::Destination dest, const uint8_t input[32])
    {
        return write_nonce(dest, input, 32);
    }
    /*!
      @brief write nonce 64 bytes
      @param dest Output destination
      @param input Input buffer at least 64 bytes
      @return True if successful
     */
    bool writeNonce64(const atecc608::Destination dest, const uint8_t input[64])
    {
        return write_nonce(dest, input, 64);
    }
    ///@}

    ///@name Random
    ///@{
    /*!
      @brief Read TRNG output
      @param[out] data Output value (At least 32 bytes)
      @return True if successful
     */
    bool readRandomArray(uint8_t data[32], const bool updateSeed = true);
    /*!
      @brief Generate a random value of type T in the specified range
      @tparam T Type of the value (must be an integral type)
      @param[out] value The output variable to store the random value
      @param lower The lower bound (inclusive)
      @param upper The upper bound (exclusive)
      @return True if successful
      @note Output range is [lower, upper) - that is, lower <= value < upper
    */
    template <typename T, typename std::enable_if<std::is_integral<T>::value, std::nullptr_t>::type = nullptr>
    bool readRandom(T& value, const T lower, const T upper)
    {
        static_assert(sizeof(T) <= 32, "readRandom only supports types up to 32 bytes");

        value = lower;
        if (upper <= lower) {
            M5_LIB_LOGE("lower must be less than upper");
            return false;
        }

        using U       = typename std::make_unsigned<T>::type;
        const U range = static_cast<U>(upper - lower);
        const U limit = std::numeric_limits<U>::max() - (std::numeric_limits<U>::max() % range);

        uint8_t rv[32]{};
        uint_fast8_t offset{};

        while (true) {
            if (!readRandomArray(rv)) {
                return false;
            }
            offset = 0;
            while (offset + sizeof(U) <= 32) {
                U raw{};
                memcpy(&raw, rv + offset, sizeof(U));
                offset += sizeof(U);

                if (raw > limit) {  // Rejection sampling
                    continue;
                }
                value = static_cast<T>(lower + (raw % range));
                return true;
            }
        }

        return false;
    }
    /*!
      @brief Generate a random floating-point value in the specified range
      @tparam T Type of the value (must be a floating-point type)
      @param[out] value The output variable to store the random value
      @param lower The lower bound (inclusive)
      @param upper The upper bound (exclusive)
      @return True if successful
      @note Output range is [lower, upper) - that is, lower <= value < upper
    */
    template <typename T, typename std::enable_if<std::is_floating_point<T>::value, std::nullptr_t>::type = nullptr>
    bool readRandom(T& value, const T lower, const T upper)
    {
        value = std::numeric_limits<T>::quiet_NaN();
        if (upper <= lower) {
            M5_LIB_LOGE("lower must be less than upper");
            return false;
        }

        uint8_t rv[32]{};
        if (!readRandomArray(rv)) {
            return false;
        }

        uint32_t raw{};
        memcpy(&raw, rv, sizeof(uint32_t));  // use first 4 bytes

        // convert to [0.0, 1.0)
        constexpr double norm = 1.0 / static_cast<double>(std::numeric_limits<uint32_t>::max());
        double r              = static_cast<double>(raw) * norm;
        value                 = static_cast<T>(lower + r * static_cast<double>(upper - lower));
        return true;
    }
    /*!
      @brief Generate a random integral value covering the entire valid range of type T
      @tparam T Type of the value (must be an integral type)
      @param[out] value The output variable to store the random value
      @return True if successful
      @note Range is [lowest, max) -  covers the full valid value space of T
    */
    template <typename T, typename std::enable_if<std::is_integral<T>::value, std::nullptr_t>::type = nullptr>
    inline bool readRandom(T& value)
    {
        return readRandom(value, std::numeric_limits<T>::lowest(), std::numeric_limits<T>::max());
    }
    /*!
      @brief Generate a random floating-point value covering the full range of T
      @tparam T Type of the value (must be a floating-point type)
      @param[out] value The output variable to store the random value
      @return True if successful
      @note Output range is [lowest, max)
    */
    template <typename T, typename std::enable_if<std::is_floating_point<T>::value, std::nullptr_t>::type = nullptr>
    inline bool readRandom(T& value)
    {
        return readRandom(value, std::numeric_limits<T>::lowest(), std::numeric_limits<T>::max());
    }
    ///@}

    ///@name Read
    ///@{
    /*!
      @brief Read the config zone
      @param[out] config[128] Output buffer at least 128 bytes
     */
    bool readConfigZone(uint8_t config[128]);

    /*!
      @brief Read the serial number
      @param[out] sn[9] Output buffer at least 9 bytes
      @return True if successful
     */
    bool readSerialNumber(uint8_t sn[9]);
    /*!
      @brief Read the serial number as string
      @param[out] str[9] Output buffer at least 19 bytes
      @return True if successful
     */
    bool readSerialNumber(char str[19]);

    /*!
      @brief Read the lock state for zone
      @param[out] configLocked Configurate zone
      @param[out] dataLocked Data zone
      @return True if successful
     */
    bool readZoneLocked(bool& configLocked, bool& dataLocked);
    /*!
      @brief Read the lock state for data zone
      @param[out] slotLockedBits Bits representing the lock status of each slot
      @return True if successful
     */
    bool readSlotLocked(uint16_t& slotLockedBits);
    /*!
      @brief Read the SlotConfig
      @param[out]  cfg SlotConfig value
      @param slot Slot
      @return True if successful
     */
    inline bool readSlotConfig(uint16_t& cfg, const atecc608::Slot slot)
    {
        constexpr uint8_t SLOT_CONFIG_BASE{20};  // Offset in ConfigZone
        return read_slot_config_word(cfg, SLOT_CONFIG_BASE, slot);
    }
    /*!
      @brief Read the KeyConfig
      @param[out]  cfg KeyConfig value
      @param slot Slot
      @return True if successful
     */
    inline bool readKeyConfig(uint16_t& cfg, const atecc608::Slot slot)
    {
        constexpr uint8_t KEY_CONFIG_BASE{96};  // Offset in ConfigZone
        return read_slot_config_word(cfg, KEY_CONFIG_BASE, slot);
    }

    /*!
      @brief Read the data zone
      @param[out] data Output buffer
      @param slot Slot
      @patam len Buffer length
      @return True if successful
     */
    bool readDataZone(uint8_t* data, const uint16_t len, const atecc608::Slot slot);
    ///@}

    /*!
      @brief Read the OTP zone
      @paran[out] Output buffer at least 64 bytes
      @return True if successful
     */
    bool readOTPZone(uint8_t otp[64]);
    ///@}

    ///@nme SelfTest
    ///@{
    /*!
      @brief Self test
      @param[out] resultBits The bit corresponding to a failed test is set
      @param testBits Bits to be tested
      @return True if successful
      @note bits
      |b[7:6]|b[5]|b[4]|b[3]|b[2]|b[1]|b[0]|
      |---|---|---|---|---|---|---|
      |00|SHA|AES|ECDH|EECDSA|0|RNG,DRBG|
     */
    bool selfTest(uint8_t resultBits, const uint8_t testBits = 0x3D /* All */);
    ///@}

    ///@name SHA256
    ///@{
    /*!
      @brief Start calculate SHA256
      @return True if successful
     */
    bool startSHA256();
    /*!
      @brief Update calculate SHA256
      @param msg Message
      @param mlen Length of the message
      @return True if successful
     */
    bool updateSHA256(const uint8_t* msg, const uint32_t mlen);
    /*!
      @brief Finalize calculate SHA256
      @param dest Output destination (Output buffer is always output)
      @param[out] digest Output buffer at least 32 bytes
      @return True if successful
     */
    bool finalizeSHA256(const atecc608::Destination dest, uint8_t digest[32]);
    /*!
      @brief Calculate SHA256
      @param dest Output destination (Output buffer is always output)
      @param[out] digest Output buffer at least 32 bytes
      @param msg Message
      @param mlen Length of the message
      @return True if successful
     */
    inline bool SHA256(const atecc608::Destination dest, uint8_t digest[32], const uint8_t* msg, const uint32_t mlen)
    {
        return startSHA256() && updateSHA256(msg, mlen) && finalizeSHA256(dest, digest);
    }
    ///@}

    ///@warning For TNGTLS, the ECDH command may be run using the ECC private keys stored in Slots 0 and 2-4
    ///@name ECDH
    ///@{
    /*!
      @brief ECDH (Plane text)
      @param[out] out Shared Master Secret as clear text at least 32 bytes
      @param pubKey Public key
      @param slot ECC private key source Slot
      @return True if successful
    */
    inline bool ECDHStoredKey(uint8_t out[32], const uint8_t pubKey[64], const atecc608::Slot slot)
    {
        using namespace m5::unit::atecc608;
        return ecdh_receive32(out, pubKey, ECDH_MODE_SRC_SLOT | ECDH_MODE_OUTPUT_BUFFER, m5::stl::to_underlying(slot));
    }
    /*!
      @brief ECDH (Encrypted)
      @param[out] out Shared Master Secret as encrypted text at least 32 bytes
      @param[out] nonce nonce used for encryption
      @param pubKey Public key
      @param slot ECC private key source Slot
      @return True if successful
     */
    inline bool ECDHStoredKey(uint8_t out[32], uint8_t nonce[32], const uint8_t pubKey[64], const atecc608::Slot slot)
    {
        using namespace m5::unit::atecc608;
        return ecdh_receive32x2(out, nonce, pubKey, ECDH_MODE_SRC_SLOT | ECDH_MODE_OUTPUT_BUFFER | ECDH_MODE_ENCRYPT,
                                m5::stl::to_underlying(slot));
    }
    /*!
      @brief ECDH (Output to TempKey)
      @param pubKey Public key
      @param slot ECC private key source Slot
      @return True if successful
     */
    inline bool ECDHStoredKey(const uint8_t pubKey[64], const atecc608::Slot slot)
    {
        using namespace m5::unit::atecc608;
        return ecdh_no_output(pubKey, ECDH_MODE_SRC_SLOT | ECDH_MODE_OUTPUT_TEMPKEY, m5::stl::to_underlying(slot));
    }
    /*!
      @brief ECDH (Plane text)
      @param[out] out Shared Master Secret as clear text at least 32 bytes
      @param pubKey Public key
      @return True if successful
      @note TempKey as its starting value for an ECDH command
     */
    inline bool ECDHTempKey(uint8_t out[32], const uint8_t pubKey[64])
    {
        using namespace m5::unit::atecc608;
        return ecdh_receive32(out, pubKey, ECDH_MODE_SRC_TEMPKEY | ECDH_MODE_OUTPUT_BUFFER, 0x0000);
    }
    /*!
      @brief ECDH (Encrypted)
      @param[out] out Shared Master Secret as encrypted text at least 32 bytes
      @param[out] nonce nonce used for encryption
      @param pubKey Public key
      @return True if successful
      @note TempKey as its starting value for an ECDH command
     */
    inline bool ECDHTempKey(uint8_t out[32], uint8_t nonce[32], const uint8_t pubKey[64])
    {
        using namespace m5::unit::atecc608;
        return ecdh_receive32x2(out, nonce, pubKey, ECDH_MODE_SRC_TEMPKEY | ECDH_MODE_OUTPUT_BUFFER | ECDH_MODE_ENCRYPT,
                                0x0000);
    }
    /*!
      @brief ECDH (Output to TempKey)
      @param pubKey Public key
      @return True if successful
      @note TempKey as its starting value for an ECDH command
     */
    inline bool ECDHTempKey(const uint8_t pubKey[64])
    {
        using namespace m5::unit::atecc608;
        return ecdh_no_output(pubKey, ECDH_MODE_SRC_TEMPKEY | ECDH_MODE_OUTPUT_TEMPKEY, 0x0000);
    }
    /*!
      @brief ECDH(Store to slot)
      @param slot Output slot
      @param pubKey Public key
      @return True if successful
      @note TempKey as its starting value for an ECDH command
     */
    bool ECDHTempKey(const atecc608::Slot slot, const uint8_t pubKey[64])
    {
        using namespace m5::unit::atecc608;
        return ecdh_no_output(pubKey, ECDH_MODE_SRC_TEMPKEY | ECDH_MODE_OUTPUT_SLOT, m5::stl::to_underlying(slot));
    }
    ///@}

    ///@name GenKey
    ///@{
    /*!
      @brief Generate the private key to slot
      @param slot Output slot
      @param[out] pubKey Output buffer at least 64 bytes
      @param digest Public key digest is generated and stored in TempKey if true
      @return True if successful
      @warning For TNGTLS, the GenKey command can be used to generate private keys only in Slots 2, 3 and 4
     */
    inline bool generatePrivateKey(const atecc608::Slot slot, uint8_t pubKey[64], const bool digest = false)
    {
        using namespace m5::unit::atecc608;
        return generate_key(pubKey, GENKEY_MODE_PRIVATE | (digest ? GENKEY_MODE_DIGEST : 0x00),
                            m5::stl::to_underlying(slot));
    }
    /*!
      @brief Make disposable private key to TempKey and output public key
      @param[out] pubKey Output buffer at least 64 bytes
      @return True if successful
     */
    bool generateKey(uint8_t pubKey[64]);
    /*!
      @brief Generate the public key from private key in slot
      @param[out] pubKey Output buffer at least 64 bytes
      @param slot Private key Slot
      @param digest Public key digest is generated and stored in TempKey if true
      @return True if successful
     */
    inline bool generatePublicKey(uint8_t pubKey[64], const atecc608::Slot slot, const bool digest = false)
    {
        using namespace m5::unit::atecc608;
        return generate_key(pubKey, GENKEY_MODE_PUBLIC | (digest ? GENKEY_MODE_DIGEST : 0x00),
                            m5::stl::to_underlying(slot));
    }
    /*!
      @brief Generate digest of a public key and stored in TempKey
      @param slot Public key slot
      @return True if successful
      @warning For TNGTLS, a digest can be created from Slot 11
     */
    bool generatePublicKeyDigest(const atecc608::Slot slot);
    ///@}

    ///@name Sign
    ///@{
    /*!
      @brief Sign internal message
      @param[out] signature Signature at least 64 butes
      @param slot Slot of the private key to be used to sign the message
      @param src Message source
      @param includeSerial Serial number is included in the message digest calculation
      @return True if successful
      @warning For TNGTLS device, only Slot 1 is capable of signing internally generated messages
    */
    inline bool signInternal(uint8_t signature[64], const atecc608::Slot slot, const atecc608::Source src,
                             const bool includeSerial = false)
    {
        using namespace m5::unit::atecc608;
        return sign(signature, (SIGN_MODE_INTERNAL | (includeSerial ? SIGN_MODE_INCLUDE_SN : 0x00)),
                    m5::stl::to_underlying(slot), src);
    }
    /*!
      @brief Sign external message
      @param[out] signature Signature at least 64 butes
      @param slot Private key slot used to sign the message
      @param src Message source
      @param includeSerial Serial number is included in the message digest calculation
      @return True if successful
      @warning For TNGTLS device, Slots 0 and 2-4 are enabled to sign external messages
    */
    inline bool signExternal(uint8_t signature[64], const atecc608::Slot slot, const atecc608::Source src,
                             const bool includeSerial = false)
    {
        using namespace m5::unit::atecc608;
        return sign(signature, (SIGN_MODE_EXTERNAL | (includeSerial ? SIGN_MODE_INCLUDE_SN : 0x00)),
                    m5::stl::to_underlying(slot), src);
    }
    ///@}

    ///@name Verify
    ///@{
    /*!
      @brief Verify the external public key
      @param[out] mac validating MAC output buffer if not nullptr
      @param signature Signature to be verified
      @param pubKey  public key to be used for verification
      @param src Message source
      @return True if successful
     */
    inline bool verifyExternal(uint8_t mac[32], const uint8_t signature[64], const uint8_t pubKey[64],
                               const atecc608::Source src)
    {
        using namespace m5::unit::atecc608;
        return verify(mac, VERIFY_MODE_EXTERNAL | (mac ? VERIFY_MODE_MAC : 0x00), 0x0004 /* P256 */, signature, pubKey,
                      src);
    }
    /*!
      @brief Verify the stored publick key
      @param[out] mac validating MAC output buffer if not nullptr
      @param signature Signature to be verified
      @param slot Slot containing the public key to be used for the verification
      @param src Message source
      @return True if successful
     */
    inline bool verifyStored(uint8_t mac[32], const uint8_t signature[64], const atecc608::Slot slot,
                             const atecc608::Source src)
    {
        using namespace m5::unit::atecc608;
        return verify(mac, VERIFY_MODE_STORED | (mac ? VERIFY_MODE_MAC : 0x00), m5::stl::to_underlying(slot), signature,
                      nullptr, src);
    }

    // @todo AES, CheckMac, GenDig, KDF, MAC command support
    
protected:
    bool send_command(const uint8_t opcode, const uint8_t param1 = 0, const uint16_t param2 = 0,
                      const uint8_t* data = nullptr, uint32_t dlen = 0);
    bool receive_response(uint8_t* data, const uint32_t dlen);

    bool counter(uint32_t& value, const uint8_t counter, const uint8_t mode);
    bool write_nonce(const atecc608::Destination dest, const uint8_t* input, const uint32_t ilen);
    bool read_data(uint8_t* rbuf, const uint32_t rlen, const uint8_t zone, const uint16_t address,
                   const uint32_t delayMs = 3 /* read default */);
    bool read_slot_config_word(uint16_t& cfg, const uint8_t baseOffset, const atecc608::Slot slot);
    virtual bool ecdh_receive32(uint8_t out[32], const uint8_t pubKey[64], const uint8_t mode, const uint16_t param2);
    virtual bool ecdh_receive32x2(uint8_t out[32], uint8_t nonce[32], const uint8_t pubKey[64], const uint8_t mode,
                                  const uint16_t param2);
    virtual bool ecdh_no_output(const uint8_t pubKey[64], const uint8_t mode, const uint16_t param2);
    virtual bool generate_key(uint8_t pubKey[64], const uint8_t mode, const uint16_t param2 = 0x0000,
                              const uint8_t* data = nullptr, const uint32_t dlen = 0);
    virtual bool sign(uint8_t signature[64], const uint8_t mode, const uint16_t param2, const atecc608::Source src);

    bool verify(uint8_t mac[32], const uint8_t mode, const uint16_t param2, const uint8_t signature[64],
                const uint8_t pubKey[64], const atecc608::Source src);

private:
    config_t _cfg{};
};

}  // namespace unit
}  // namespace m5
#endif
