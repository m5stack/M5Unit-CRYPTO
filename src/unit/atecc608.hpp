/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file atecc608.hpp
  @brief ATECC608 definition
*/
#ifndef M5_UNIT_CRYPTO_ATECC608_HPP
#define M5_UNIT_CRYPTO_ATECC608_HPP

#include <cstdint>

namespace m5 {
namespace unit {
/*!
  @namespace atecc608
  @brief For ATECC608
 */
namespace atecc608 {
/*!
  @enum Slot
  @brief Slot configuration summay
 */
enum class Slot : uint8_t {
    PrimaryPrivateKey,            //!< Primary authentication key
    InternalSignPrivateKey,       //!< Private key that can only be used to attest to the internal keys and state of the
                                  //!< device
    SecondaryPrivateKey1,         //!< Secondary private key for other uses
    SecondaryPrivateKey2,         //!< Secondary private key for other uses
    SecondaryPrivateKey3,         //!< Secondary private key for other uses
    MACAddress,                   //!< IEEE EUI-48 MAC Address
    IOProtectionKey,              //!< Key used to protect the I2C bus communication (IO) of certain commands
    GeneralData = 8,              //!< General purpose data storage (416 bytes)
    AESKey,                       //!< Intermediate key storage for ECDH and KDF output
    DeviceCompressedCertificate,  //!< Certificate primary public key in the CryptoAuthentication compressed format
    SignerPublicKey,              //!< Public key for the CA (signer) that signed the device cert
    SignerCompressedCertificate,  //!< Certificate for the CA (signer) certificate for the device certificate in the
                                  //!< CryptoAuthentication compressed format
    // 7,13,14,15 are reserved
};

///@name Zone
///@{
constexpr uint8_t ZONE_CONFIG{0x00};
constexpr uint8_t ZONE_OTP{0x01};
constexpr uint8_t ZONE_DATA{0x02};
///@}

/*!
  @enum Error
 @brief Error status
*/
enum Error : uint8_t {
    CHECK_MAC_OR_VERIFY_ERROR  = 0x01,
    PARSE_ERROR                = 0x03,
    ECC_FAULT                  = 0x05,
    SELF_TEST_ERROR            = 0x07,
    HEALTH_TEST_ERROR          = 0x08,
    EXECUTION_ERROR            = 0x0F,
    AFTER_WAKE_PRIOR_ERROR     = 0X11,
    WATCH_DOG_ERROR            = 0xEE,
    CRC_OR_COMMUNICATION_ERROR = 0XFF,
};

///@name Delay time for send/receive
///@{
#if 0
// コマンド名	最大実行時間 (ms)	備考
// Read	2.5	データシートの更新により、最大実行時間が2.0msから2.5msに増加しました。
// Write	4.0	
// GenKey	115.0	鍵の生成を行います。
// Sign	50.0	データに対する署名を生成します。
// Verify	58.0	署名の検証を行います。
// ECDH	58.0	楕円曲線Diffie-Hellman鍵共有を実行します。
// KDF	75.0	鍵派生関数を実行します。
// Nonce	3.0	
// MAC	10.0	メッセージ認証コードを生成します。
// HMAC	23.0	HMACを生成します。
// SHA	9.0	SHAハッシュを計算します。
// AES	3.0	AES暗号化/復号化を実行します。
// SelfTest	200.0	デバイスの自己診断を実行します。
// Info	2.0	デバイス情報を取得します。
// Lock	32.0	デバイスの領域をロックします。
// Random	23.0	ランダムな数値を生成します。
// DeriveKey	50.0	鍵の派生を行います。
// Counter	20.0	カウンタの操作を行います。
// UpdateExtra	8.0	追加情報の更新を行います。
// PrivWrite	48.0	秘密鍵の書き込みを行います。
// SecureBoot	500.0	セキュアブートを実行します。
//     { ATCA_AES,          27},
//     { ATCA_CHECKMAC,     40},
//     { ATCA_COUNTER,      25},
//     { ATCA_DERIVE_KEY,   50},
//     { ATCA_ECDH,         75},
//     { ATCA_GENDIG,       25},
//     { ATCA_GENKEY,       115},
//     { ATCA_INFO,         5},
//     { ATCA_KDF,          165},
//     { ATCA_LOCK,         35},
//     { ATCA_MAC,          55},
//     { ATCA_NONCE,        20},
//     { ATCA_PRIVWRITE,    50},
//     { ATCA_RANDOM,       23},
//     { ATCA_READ,         5},
//     { ATCA_SECUREBOOT,   80},
//     { ATCA_SELFTEST,     250},
//     { ATCA_SHA,          36},
//     { ATCA_SIGN,         115},
//     { ATCA_UPDATE_EXTRA, 10},
//     { ATCA_VERIFY,       105},
//     { ATCA_WRITE,        45}
#endif
constexpr uint32_t DELAY_READ{3};
constexpr uint32_t DELAY_WRITE{4};
constexpr uint32_t DELAY_INFO{2};
constexpr uint32_t DELAY_NONCE{15};
constexpr uint32_t DELAY_SELFTEST{200};
constexpr uint32_t DELAY_RANDOM{23};
constexpr uint32_t DELAY_COUNTER{20};
constexpr uint32_t DELAY_GENKEY{115};
constexpr uint32_t DELAY_SIGN{70};
constexpr uint32_t DELAY_SHA{9};
constexpr uint32_t DELAY_ECDH{58};
constexpr uint32_t DELAY_VERIFY{58};
///@}

///@name Word address
///@{
constexpr uint8_t WORD_ADRESS_VALUE_RESET{0x00};
constexpr uint8_t WORD_ADRESS_VALUE_SLEEP{0x01};
constexpr uint8_t WORD_ADRESS_VALUE_IDLE{0x02};
constexpr uint8_t WORD_ADRESS_VALUE_COMMAND{0x03};
///@}

///@name Operation code
///@{
constexpr uint8_t OPCODE_READ{0x02};
constexpr uint8_t OPCODE_WRITE{0x12};
constexpr uint8_t OPCODE_NONCE{0x16};
// constexpr uint8_t OPCODE_LOCK{0x17};
constexpr uint8_t OPCODE_RANDOM{0x1B};
constexpr uint8_t OPCODE_COUNTER{0x24};
constexpr uint8_t OPCODE_INFO{0x30};
constexpr uint8_t OPCODE_GENKEY{0x40};
constexpr uint8_t OPCODE_SIGN{0x41};
constexpr uint8_t OPCODE_ECDH{0x43};
constexpr uint8_t OPCODE_VERIFY{0x45};
constexpr uint8_t OPCODE_SHA{0x47};
constexpr uint8_t OPCODE_SELFTEST{0x77};
///@}

///@name Info
///@{
constexpr uint8_t INFO_MODE_REVISION{0x00};
constexpr uint8_t INFO_MODE_KEYVALID{0x01};
constexpr uint8_t INFO_MODE_DEVICE_STATE{0x02};
///@}

///@name Random
///@{
constexpr uint8_t RANDOM_MODE_UPDATE_SEED{0x00};
constexpr uint8_t RANDOM_MODE_NOT_UPDATE_SEED{0x01};
///@}

///@name Nonce
///@{
constexpr uint8_t NONCE_MODE_RANDOM_UPDATE_SEED{0x00};
constexpr uint8_t NONCE_MODE_RANDOM_NOT_UPDATE_SEED{0x01};
constexpr uint8_t NONCE_MODE_PASSTHROUGH{0x03};

constexpr uint8_t NONCE_MODE_INPUT_64{0x20};

constexpr uint8_t NONCE_MODE_TARGET_TEMPKEY{0x00};  //!< Nonce mode: target is TempKey
constexpr uint8_t NONCE_MODE_TARGET_MSGDIG{0x40};   //!< Nonce mode: target is Message Digest Buffer
constexpr uint8_t NONCE_MODE_TARGET_ALTKEY{0x80};   //!< Nonce mode: target is Alternate Key Buffer

constexpr uint16_t NONCE_USE_TRNG{0x0000};
constexpr uint16_t NONCE_USE_TEMPKEY{0x8000};
///@}

///@name SHA
///@{
constexpr uint8_t SHA_MODE_START{0x00};
constexpr uint8_t SHA_MODE_UPDATE{0x01};
constexpr uint8_t SHA_MODE_FINALIZE{0x02};
constexpr uint8_t SHA_MODE_OUTPUT_TEMPKEY{0x00};
constexpr uint8_t SHA_MODE_OUTPUT_DIGEST{0x40};
constexpr uint8_t SHA_MODE_OUTPUT_BUFFER{0xC0};
///@}

///@name GenKey
///@{
constexpr uint8_t GENKEY_MODE_PUBLIC{0x00};
constexpr uint8_t GENKEY_MODE_PRIVATE{0x04};
constexpr uint8_t GENKEY_MODE_DIGEST{0x08};
///@}

///@name Sign
///@{
constexpr uint8_t SIGN_MODE_INTERNAL{0x00};
constexpr uint8_t SIGN_MODE_INVALIDATE{0x01};
constexpr uint8_t SIGN_MODE_INCLUDE_SN{0x40};
constexpr uint8_t SIGN_MODE_EXTERNAL{0x80};
constexpr uint8_t SIGN_MODE_TEMPKEY{0x00};
constexpr uint8_t SIGN_MODE_DIGEST{0x20};

///@name ECDH
///@{
// constexpr uint8_t ECDH_MODE_SLOT{0x04};
constexpr uint8_t ECDH_MODE_SRC_SLOT{0x00};
constexpr uint8_t ECDH_MODE_SRC_TEMPKEY{0x01};

constexpr uint8_t ECDH_MODE_ENCRYPT{0x02};

constexpr uint8_t ECDH_MODE_OUTPUT_TEMPKEY{0x08};
constexpr uint8_t ECDH_MODE_OUTPUT_BUFFER{0x0C};
constexpr uint8_t ECDH_MODE_OUTPUT_SLOT{0x04};
///@}

///@name Verify
///@{
constexpr uint8_t VERIFY_MODE_STORED{0x00};
constexpr uint8_t VERIFY_MODE_EXTERNAL{0x02};

constexpr uint8_t VERIFY_MODE_TEMPKEY{0x00};
constexpr uint8_t VERIFY_MODE_DIGEST{0x20};

constexpr uint8_t VERIFY_MODE_MAC{0x80};
///@}

///@cond
constexpr uint16_t slot_data_size_table[16] = {
    36,  36, 36, 36, 36, 36, 36, 36,  // slot 0〜7
    416,                              // slot 8
    72,  72, 72, 72, 72, 72, 72       // slot 9〜15
};
///@endcond

//! @brief Get the data storage size of the slot
constexpr uint16_t slotDataSize(const Slot s)
{
    return slot_data_size_table[(uint8_t)s];
}

//! @brief Conversion offset to address for Config,OTP zone
inline uint16_t offset_to_param2_for_config(const uint8_t offset)
{
    const uint8_t block = (offset >> 5) & 0x03;         // 0〜3
    const uint8_t index = ((offset & 31) >> 2) & 0x07;  // 0〜7
    return (block << 3) | index;
}
//! @brief Conversion slot and block to address for Data zone
inline uint16_t slot_block_to_param2(const uint8_t slot, const uint8_t offset)
{
    const uint8_t block       = offset >> 5;         // 0〜2
    const uint8_t word_offset = (offset & 31) >> 2;  // 0〜7
    return (slot << 3) | (block << 8) | word_offset;
}

//! @brief Convert der to pem
bool convertToPEM(char* out, const uint32_t out_len, const uint8_t* der, uint32_t dlen,
                  const char* header = "CERTIFICATE", const char* footer = "CERTIFICATE");

//! @brief Print PEM to serial
void printPEM(const uint8_t* der, const uint32_t dlen, const char* header = "CERTIFICATE",
              const char* footer = "CERTIFICATE");

///@cond
extern const uint8_t template_for_device[];
extern const uint8_t template_for_signer[];
extern const uint32_t template_for_device_size;
extern const uint32_t template_for_signer_size;
///@endcond

/*1
  @class m5::unit::atecc608::CompCertAccessor
  @brief Compressed certificate accessor
 */
class CompCertAccessor {
public:
    struct DateTime {
        int tm_sec;   // 0 to 59
        int tm_min;   // 0 to 59
        int tm_hour;  // 0 to 23
        int tm_mday;  // 1 to 31
        int tm_mon;   // 0 to 11
        int tm_year;  // years since 1900
    };

    explicit CompCertAccessor(const uint8_t* data) : _data(data)
    {
        _issue_date  = get_issue_date();
        _expire_date = get_expire_date();
    }

    uint8_t format_version() const
    {
        return _data[70] & 0x0F;
    }
    uint8_t template_id() const
    {
        return (_data[69] >> 4) & 0x0F;
    }
    uint8_t chain_id() const
    {
        return _data[69] & 0x0F;
    }
    uint8_t sn_source() const
    {
        return (_data[70] >> 4) & 0x0F;
    }

    const uint8_t* signer_id() const
    {
        return _data + 67;
    }

    const uint8_t* signature() const
    {
        return _data + 0;
    }
    const uint8_t* signature_r() const
    {
        return _data + 0;
    }
    const uint8_t* signature_s() const
    {
        return _data + 32;
    }

    DateTime issue_date() const
    {
        return _issue_date;
    }
    DateTime expire_date() const
    {
        return _expire_date;
    }

private:
    const uint8_t* _data{};
    DateTime _issue_date{}, _expire_date{};

    DateTime get_issue_date() const
    {
        DateTime dt{};
        uint8_t b64 = _data[64];
        uint8_t b65 = _data[65];
        uint8_t b66 = _data[66];
        uint8_t b71 = _data[71];

        uint8_t format_version = _data[70] & 0x0F;

        if (format_version == 1 || format_version == 2) {
            dt.tm_year = ((((b71 & 0xC0) >> 1) | ((b64 >> 3) & 0x1F)) + 100);
        } else {
            dt.tm_year = ((b64 >> 3) + 100);
        }
        dt.tm_mon  = (((b64 & 0x07) << 1) | ((b65 & 0x80) >> 7)) - 1;  // 公式準拠で 0〜11
        dt.tm_mday = (b65 & 0x7C) >> 2;
        dt.tm_hour = ((b65 & 0x03) << 3) | ((b66 & 0xE0) >> 5);
        dt.tm_min  = 0;
        dt.tm_sec  = 0;
        return dt;
    }

    DateTime get_expire_date() const
    {
        DateTime dt = issue_date();
        uint8_t b66 = _data[66];
        uint8_t b71 = _data[71];

        uint8_t format_version = _data[70] & 0x0F;
        uint8_t expire_years;

        if (format_version == 1 || format_version == 2) {
            expire_years = (b66 & 0x1F) | ((b71 & 0x30) << 1);
        } else {
            expire_years = b66 & 0x1F;
        }

        if (expire_years != 0) {
            dt.tm_year += expire_years;
        } else {
            // 無期限
            dt.tm_year = 9999 - 1900;
            dt.tm_mon  = 11;
            dt.tm_mday = 31;
            dt.tm_hour = 23;
            dt.tm_min  = 59;
            dt.tm_sec  = 59;
        }
        return dt;
    }
};

}  // namespace atecc608
}  // namespace unit
}  // namespace m5
#endif
