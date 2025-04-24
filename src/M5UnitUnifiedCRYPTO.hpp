/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file M5UnitUnifiedCRYPTO.hpp
  @brief Main header of M5UnitCRYPTO

  @mainpage M5UnitCRYPTO
  Library for UnitCRYPTO using M5UnitUnified.
*/
#ifndef M5_UNIT_UNIFIED_CRYPTO_HPP
#define M5_UNIT_UNIFIED_CRYPTO_HPP

#include "unit/unit_ATECC608B.hpp"
#include "unit/unit_ATECC608B_TNGTLS.hpp"

/*!
  @namespace m5
  @brief Top level namespace of M5stack
 */
namespace m5 {
/*!
  @namespace unit
  @brief Unit-related namespace
 */
namespace unit {
//! @brief Alias for M5Stack's UnitID(SKU:U124) unit (internally uses ATECC680B-TNGTLS)
using UnitID = m5::unit::UnitATECC608B_TNGTLS;

}  // namespace unit
}  // namespace m5
#endif
