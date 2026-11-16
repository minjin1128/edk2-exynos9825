/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef N976N_ESP_POLICY_H
#define N976N_ESP_POLICY_H
/* Enabled only in the separately preserved SEC86 source tree. */
#define N976N_MUTABLE_ESP_PROFILE 86
STATIC BOOLEAN N976nEspBcdLength (UINT64 Bytes) {
 return Bytes>=8192 && Bytes<=65536 && Bytes%4096==0;
}
#endif
