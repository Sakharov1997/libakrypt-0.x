//
// Created by Anton Sakharov on 2019-06-26.
//

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <memory.h>
#include "asn_processor/ak_asn_codec_new.h"

/* Исходные данные */
//ak_byte test_data[] = {0x30, 0x82, 0x03, 0x39, 0x02, 0x01, 0x00, 0xA0, 0x42, 0x30, 0x40, 0x04, 0x10, 0x8B, 0x78, 0x48, 0x50, 0x1A, 0x78, 0x91, 0xBF, 0x8C, 0x15, 0x5B, 0x80, 0x15, 0x8A, 0x28, 0x5E, 0xA0, 0x2C, 0x30, 0x2A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C, 0x30, 0x1D, 0x04, 0x08, 0xE9, 0xC2, 0xCF, 0xAB, 0x57, 0xFE, 0x3E, 0x9D, 0x02, 0x02, 0x07, 0xD0, 0x02, 0x01, 0x20, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x04, 0x02, 0x30, 0x82, 0x02, 0xEE, 0xA3, 0x82, 0x01, 0x73, 0xA0, 0x82, 0x01, 0x6F, 0xBB, 0x82, 0x01, 0x6B, 0x06, 0x08, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x05, 0x01, 0x30, 0x82, 0x01, 0x5D, 0x30, 0x12, 0x0C, 0x10, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x6B, 0x65, 0x79, 0x30, 0x39, 0x04, 0x10, 0xD0, 0x35, 0x6A, 0x5A, 0x3B, 0xFD, 0x4D, 0xB6, 0xF6, 0x5D, 0x82, 0x78, 0xB4, 0xA5, 0x69, 0x9B, 0x03, 0x03, 0x06, 0xC0, 0x00, 0x18, 0x0F, 0x32, 0x30, 0x31, 0x39, 0x30, 0x35, 0x32, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x80, 0x0F, 0x32, 0x30, 0x32, 0x30, 0x30, 0x35, 0x32, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A, 0xA1, 0x82, 0x01, 0x0A, 0xA2, 0x82, 0x01, 0x06, 0x02, 0x01, 0x02, 0x31, 0x81, 0x86, 0xA2, 0x81, 0x83, 0x02, 0x01, 0x04, 0x30, 0x12, 0x04, 0x10, 0x8B, 0x78, 0x48, 0x50, 0x1A, 0x78, 0x91, 0xBF, 0x8C, 0x15, 0x5B, 0x80, 0x15, 0x8A, 0x28, 0x5E, 0x30, 0x1E, 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x0D, 0x01, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x1F, 0x01, 0x04, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x04, 0x4A, 0x30, 0x48, 0x04, 0x40, 0x7D, 0xD1, 0xF0, 0x00, 0x6D, 0x82, 0x65, 0x30, 0xF0, 0x3E, 0x5A, 0x4D, 0x48, 0xF9, 0x63, 0xB0, 0xED, 0x77, 0x8E, 0x66, 0x96, 0x3B, 0x9F, 0xB5, 0x8B, 0xC4, 0x2C, 0x0A, 0xE7, 0x91, 0x27, 0xF4, 0xC4, 0xD1, 0xC5, 0x21, 0xB5, 0xB0, 0x0E, 0xB4, 0xDD, 0xBD, 0x10, 0x08, 0x6D, 0x16, 0xAD, 0xCE, 0xEA, 0xC7, 0xA6, 0x07, 0x9D, 0xFD, 0xEC, 0xAF, 0xD9, 0x7B, 0x84, 0x00, 0x9E, 0x37, 0x4C, 0xC9, 0x04, 0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0x30, 0x78, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x30, 0x1F, 0x06, 0x08, 0x2A, 0x85, 0x03, 0x02, 0x04, 0x03, 0x02, 0x02, 0x30, 0x13, 0x04, 0x08, 0x23, 0xBE, 0x18, 0x7F, 0xDF, 0xB0, 0x67, 0xEB, 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x1F, 0x01, 0x80, 0x4A, 0x04, 0x44, 0xC2, 0xC2, 0x3B, 0xC3, 0x69, 0x30, 0xA8, 0x7F, 0x02, 0xBE, 0x6F, 0x68, 0x64, 0x10, 0xFB, 0xFE, 0x9E, 0x77, 0x3B, 0x89, 0xAD, 0x91, 0x4E, 0x39, 0x22, 0x72, 0x23, 0xDC, 0x60, 0xFE, 0x74, 0x55, 0xA5, 0x12, 0xE9, 0x2D, 0xA3, 0xA6, 0xB1, 0xE9, 0xF6, 0x25, 0x89, 0x01, 0xB7, 0xB4, 0xE7, 0xCE, 0xDB, 0x0D, 0xC4, 0xE4, 0xF2, 0x74, 0x1A, 0x03, 0x41, 0x56, 0x64, 0x31, 0x17, 0x47, 0x9A, 0x3B, 0x00, 0x08, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xA3, 0x82, 0x01, 0x73, 0xA0, 0x82, 0x01, 0x6F, 0xBB, 0x82, 0x01, 0x6B, 0x06, 0x08, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x05, 0x01, 0x30, 0x82, 0x01, 0x5D, 0x30, 0x12, 0x0C, 0x10, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x6B, 0x65, 0x79, 0x30, 0x39, 0x04, 0x10, 0x91, 0xDB, 0x82, 0xFC, 0x71, 0x4C, 0x57, 0x7E, 0x21, 0x7E, 0xEB, 0x79, 0x6A, 0x20, 0x83, 0xB1, 0x03, 0x03, 0x06, 0xC0, 0x00, 0x18, 0x0F, 0x32, 0x30, 0x31, 0x39, 0x30, 0x35, 0x32, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x80, 0x0F, 0x32, 0x30, 0x32, 0x30, 0x30, 0x35, 0x32, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A, 0xA1, 0x82, 0x01, 0x0A, 0xA2, 0x82, 0x01, 0x06, 0x02, 0x01, 0x02, 0x31, 0x81, 0x86, 0xA2, 0x81, 0x83, 0x02, 0x01, 0x04, 0x30, 0x12, 0x04, 0x10, 0x8B, 0x78, 0x48, 0x50, 0x1A, 0x78, 0x91, 0xBF, 0x8C, 0x15, 0x5B, 0x80, 0x15, 0x8A, 0x28, 0x5E, 0x30, 0x1E, 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x0D, 0x01, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x1F, 0x01, 0x04, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x04, 0x4A, 0x30, 0x48, 0x04, 0x40, 0xA8, 0x30, 0xFE, 0x49, 0xB7, 0x75, 0x09, 0xA9, 0xEC, 0x7A, 0x8B, 0x6E, 0x2C, 0xD3, 0xFB, 0x72, 0x02, 0xCA, 0xB0, 0xA3, 0x2E, 0xAC, 0xFC, 0x65, 0x04, 0x72, 0xCE, 0x37, 0x89, 0xC7, 0x04, 0xD3, 0x99, 0x4E, 0x99, 0x14, 0x8B, 0x85, 0x43, 0x74, 0xCF, 0x4D, 0x3C, 0x97, 0x48, 0xFA, 0xEA, 0x39, 0x47, 0x30, 0x89, 0x7A, 0xB0, 0x93, 0x39, 0xAA, 0xB5, 0x12, 0x34, 0x42, 0x4A, 0x6C, 0xC8, 0x87, 0x04, 0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0x30, 0x78, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0x30, 0x1F, 0x06, 0x08, 0x2A, 0x85, 0x03, 0x02, 0x04, 0x03, 0x02, 0x02, 0x30, 0x13, 0x04, 0x08, 0x5E, 0x53, 0xFC, 0xEE, 0x3D, 0x56, 0xED, 0x40, 0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x1F, 0x01, 0x80, 0x4A, 0x04, 0x44, 0x55, 0xD7, 0xBC, 0x71, 0x76, 0x74, 0xB9, 0x41, 0xE4, 0x4B, 0x0C, 0xAC, 0x2E, 0x5D, 0x97, 0xAB, 0xD1, 0xD6, 0xB3, 0x1F, 0x8D, 0x9C, 0x10, 0x7C, 0x92, 0xAB, 0x34, 0x88, 0x0A, 0x7F, 0xBD, 0xFF, 0x3A, 0x22, 0xB6, 0x04, 0xE5, 0xA0, 0xB9, 0xCE, 0x00, 0xF6, 0x38, 0xA6, 0xFC, 0xEC, 0x96, 0x32, 0x3C, 0x8B, 0x06, 0x1B, 0x62, 0x2C, 0x9F, 0x13, 0x8B, 0x1C, 0xA2, 0xC8, 0x3B, 0x39, 0xCA, 0x36, 0x00, 0x08, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};
static ak_byte test_data[] = {
                       0x30, 0x82, 0x05, 0x14, 0x30, 0x82, 0x04, 0xc1, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x4e,
                       0x6d, 0x47, 0x8b, 0x26, 0xf2, 0x7d, 0x65, 0x7f, 0x76, 0x8e, 0x02, 0x5c, 0xe3, 0xd3, 0x93, 0x30,
                       0x0a, 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x03, 0x02, 0x30, 0x82, 0x01, 0x24, 0x31,
                       0x1e, 0x30, 0x1c, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x0f,
                       0x64, 0x69, 0x74, 0x40, 0x6d, 0x69, 0x6e, 0x73, 0x76, 0x79, 0x61, 0x7a, 0x2e, 0x72, 0x75, 0x31,
                       0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x52, 0x55, 0x31, 0x18, 0x30, 0x16,
                       0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0f, 0x37, 0x37, 0x20, 0xd0, 0x9c, 0xd0, 0xbe, 0xd1, 0x81,
                       0xd0, 0xba, 0xd0, 0xb2, 0xd0, 0xb0, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c,
                       0x10, 0xd0, 0xb3, 0x2e, 0x20, 0xd0, 0x9c, 0xd0, 0xbe, 0xd1, 0x81, 0xd0, 0xba, 0xd0, 0xb2, 0xd0,
                       0xb0, 0x31, 0x2e, 0x30, 0x2c, 0x06, 0x03, 0x55, 0x04, 0x09, 0x0c, 0x25, 0xd1, 0x83, 0xd0, 0xbb,
                       0xd0, 0xb8, 0xd1, 0x86, 0xd0, 0xb0, 0x20, 0xd0, 0xa2, 0xd0, 0xb2, 0xd0, 0xb5, 0xd1, 0x80, 0xd1,
                       0x81, 0xd0, 0xba, 0xd0, 0xb0, 0xd1, 0x8f, 0x2c, 0x20, 0xd0, 0xb4, 0xd0, 0xbe, 0xd0, 0xbc, 0x20,
                       0x37, 0x31, 0x2c, 0x30, 0x2a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x23, 0xd0, 0x9c, 0xd0, 0xb8,
                       0xd0, 0xbd, 0xd0, 0xba, 0xd0, 0xbe, 0xd0, 0xbc, 0xd1, 0x81, 0xd0, 0xb2, 0xd1, 0x8f, 0xd0, 0xb7,
                       0xd1, 0x8c, 0x20, 0xd0, 0xa0, 0xd0, 0xbe, 0xd1, 0x81, 0xd1, 0x81, 0xd0, 0xb8, 0xd0, 0xb8, 0x31,
                       0x18, 0x30, 0x16, 0x06, 0x05, 0x2a, 0x85, 0x03, 0x64, 0x01, 0x12, 0x0d, 0x31, 0x30, 0x34, 0x37,
                       0x37, 0x30, 0x32, 0x30, 0x32, 0x36, 0x37, 0x30, 0x31, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x08, 0x2a,
                       0x85, 0x03, 0x03, 0x81, 0x03, 0x01, 0x01, 0x12, 0x0c, 0x30, 0x30, 0x37, 0x37, 0x31, 0x30, 0x34,
                       0x37, 0x34, 0x33, 0x37, 0x35, 0x31, 0x2c, 0x30, 0x2a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x23,
                       0xd0, 0x9c, 0xd0, 0xb8, 0xd0, 0xbd, 0xd0, 0xba, 0xd0, 0xbe, 0xd0, 0xbc, 0xd1, 0x81, 0xd0, 0xb2,
                       0xd1, 0x8f, 0xd0, 0xb7, 0xd1, 0x8c, 0x20, 0xd0, 0xa0, 0xd0, 0xbe, 0xd1, 0x81, 0xd1, 0x81, 0xd0,
                       0xb8, 0xd0, 0xb8, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x38, 0x30, 0x37, 0x30, 0x36, 0x31, 0x32, 0x31,
                       0x38, 0x30, 0x36, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x37, 0x30, 0x31, 0x31, 0x32, 0x31, 0x38,
                       0x30, 0x36, 0x5a, 0x30, 0x82, 0x01, 0x24, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x09, 0x2a, 0x86, 0x48,
                       0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x0f, 0x64, 0x69, 0x74, 0x40, 0x6d, 0x69, 0x6e, 0x73,
                       0x76, 0x79, 0x61, 0x7a, 0x2e, 0x72, 0x75, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
                       0x13, 0x02, 0x52, 0x55, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0f, 0x37,
                       0x37, 0x20, 0xd0, 0x9c, 0xd0, 0xbe, 0xd1, 0x81, 0xd0, 0xba, 0xd0, 0xb2, 0xd0, 0xb0, 0x31, 0x19,
                       0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x10, 0xd0, 0xb3, 0x2e, 0x20, 0xd0, 0x9c, 0xd0,
                       0xbe, 0xd1, 0x81, 0xd0, 0xba, 0xd0, 0xb2, 0xd0, 0xb0, 0x31, 0x2e, 0x30, 0x2c, 0x06, 0x03, 0x55,
                       0x04, 0x09, 0x0c, 0x25, 0xd1, 0x83, 0xd0, 0xbb, 0xd0, 0xb8, 0xd1, 0x86, 0xd0, 0xb0, 0x20, 0xd0,
                       0xa2, 0xd0, 0xb2, 0xd0, 0xb5, 0xd1, 0x80, 0xd1, 0x81, 0xd0, 0xba, 0xd0, 0xb0, 0xd1, 0x8f, 0x2c,
                       0x20, 0xd0, 0xb4, 0xd0, 0xbe, 0xd0, 0xbc, 0x20, 0x37, 0x31, 0x2c, 0x30, 0x2a, 0x06, 0x03, 0x55,
                       0x04, 0x0a, 0x0c, 0x23, 0xd0, 0x9c, 0xd0, 0xb8, 0xd0, 0xbd, 0xd0, 0xba, 0xd0, 0xbe, 0xd0, 0xbc,
                       0xd1, 0x81, 0xd0, 0xb2, 0xd1, 0x8f, 0xd0, 0xb7, 0xd1, 0x8c, 0x20, 0xd0, 0xa0, 0xd0, 0xbe, 0xd1,
                       0x81, 0xd1, 0x81, 0xd0, 0xb8, 0xd0, 0xb8, 0x31, 0x18, 0x30, 0x16, 0x06, 0x05, 0x2a, 0x85, 0x03,
                       0x64, 0x01, 0x12, 0x0d, 0x31, 0x30, 0x34, 0x37, 0x37, 0x30, 0x32, 0x30, 0x32, 0x36, 0x37, 0x30,
                       0x31, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x08, 0x2a, 0x85, 0x03, 0x03, 0x81, 0x03, 0x01, 0x01, 0x12,
                       0x0c, 0x30, 0x30, 0x37, 0x37, 0x31, 0x30, 0x34, 0x37, 0x34, 0x33, 0x37, 0x35, 0x31, 0x2c, 0x30,
                       0x2a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x23, 0xd0, 0x9c, 0xd0, 0xb8, 0xd0, 0xbd, 0xd0, 0xba,
                       0xd0, 0xbe, 0xd0, 0xbc, 0xd1, 0x81, 0xd0, 0xb2, 0xd1, 0x8f, 0xd0, 0xb7, 0xd1, 0x8c, 0x20, 0xd0,
                       0xa0, 0xd0, 0xbe, 0xd1, 0x81, 0xd1, 0x81, 0xd0, 0xb8, 0xd0, 0xb8, 0x30, 0x66, 0x30, 0x1f, 0x06,
                       0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x85, 0x03,
                       0x02, 0x02, 0x23, 0x01, 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02, 0x03, 0x43,
                       0x00, 0x04, 0x40, 0x75, 0x39, 0x2a, 0x45, 0xa7, 0xb9, 0xa2, 0x95, 0x7d, 0xf7, 0x10, 0xfd, 0x22,
                       0x92, 0x07, 0xba, 0x1d, 0xb6, 0x5a, 0x71, 0x8a, 0x7d, 0x7d, 0x58, 0xfc, 0xb1, 0x46, 0xb9, 0x45,
                       0x61, 0x57, 0xac, 0x1d, 0xbb, 0x48, 0xa5, 0xf9, 0x4a, 0xfb, 0x48, 0x19, 0xea, 0x6a, 0x29, 0xeb,
                       0xfa, 0xf5, 0x14, 0x98, 0x78, 0x71, 0xca, 0x47, 0xe8, 0xd3, 0xf5, 0x85, 0xf6, 0x36, 0xe4, 0x8a,
                       0xf7, 0x03, 0x8d, 0xa3, 0x82, 0x01, 0xc2, 0x30, 0x82, 0x01, 0xbe, 0x30, 0x81, 0xf5, 0x06, 0x05,
                       0x2a, 0x85, 0x03, 0x64, 0x70, 0x04, 0x81, 0xeb, 0x30, 0x81, 0xe8, 0x0c, 0x34, 0xd0, 0x9f, 0xd0,
                       0x90, 0xd0, 0x9a, 0xd0, 0x9c, 0x20, 0xc2, 0xab, 0xd0, 0x9a, 0xd1, 0x80, 0xd0, 0xb8, 0xd0, 0xbf,
                       0xd1, 0x82, 0xd0, 0xbe, 0xd0, 0x9f, 0xd1, 0x80, 0xd0, 0xbe, 0x20, 0x48, 0x53, 0x4d, 0xc2, 0xbb,
                       0x20, 0xd0, 0xb2, 0xd0, 0xb5, 0xd1, 0x80, 0xd1, 0x81, 0xd0, 0xb8, 0xd0, 0xb8, 0x20, 0x32, 0x2e,
                       0x30, 0x0c, 0x43, 0xd0, 0x9f, 0xd0, 0x90, 0xd0, 0x9a, 0x20, 0xc2, 0xab, 0xd0, 0x93, 0xd0, 0xbe,
                       0xd0, 0xbb, 0xd0, 0xbe, 0xd0, 0xb2, 0xd0, 0xbd, 0xd0, 0xbe, 0xd0, 0xb9, 0x20, 0xd1, 0x83, 0xd0,
                       0xb4, 0xd0, 0xbe, 0xd1, 0x81, 0xd1, 0x82, 0xd0, 0xbe, 0xd0, 0xb2, 0xd0, 0xb5, 0xd1, 0x80, 0xd1,
                       0x8f, 0xd1, 0x8e, 0xd1, 0x89, 0xd0, 0xb8, 0xd0, 0xb9, 0x20, 0xd1, 0x86, 0xd0, 0xb5, 0xd0, 0xbd,
                       0xd1, 0x82, 0xd1, 0x80, 0xc2, 0xbb, 0x0c, 0x35, 0xd0, 0x97, 0xd0, 0xb0, 0xd0, 0xba, 0xd0, 0xbb,
                       0xd1, 0x8e, 0xd1, 0x87, 0xd0, 0xb5, 0xd0, 0xbd, 0xd0, 0xb8, 0xd0, 0xb5, 0x20, 0xe2, 0x84, 0x96,
                       0x20, 0x31, 0x34, 0x39, 0x2f, 0x33, 0x2f, 0x32, 0x2f, 0x32, 0x2f, 0x32, 0x33, 0x20, 0xd0, 0xbe,
                       0xd1, 0x82, 0x20, 0x30, 0x32, 0x2e, 0x30, 0x33, 0x2e, 0x32, 0x30, 0x31, 0x38, 0x0c, 0x34, 0xd0,
                       0x97, 0xd0, 0xb0, 0xd0, 0xba, 0xd0, 0xbb, 0xd1, 0x8e, 0xd1, 0x87, 0xd0, 0xb5, 0xd0, 0xbd, 0xd0,
                       0xb8, 0xd0, 0xb5, 0x20, 0xe2, 0x84, 0x96, 0x20, 0x31, 0x34, 0x39, 0x2f, 0x37, 0x2f, 0x36, 0x2f,
                       0x31, 0x30, 0x35, 0x20, 0xd0, 0xbe, 0xd1, 0x82, 0x20, 0x32, 0x37, 0x2e, 0x30, 0x36, 0x2e, 0x32,
                       0x30, 0x31, 0x38, 0x30, 0x3f, 0x06, 0x05, 0x2a, 0x85, 0x03, 0x64, 0x6f, 0x04, 0x36, 0x0c, 0x34,
                       0xd0, 0x9f, 0xd0, 0x90, 0xd0, 0x9a, 0xd0, 0x9c, 0x20, 0xc2, 0xab, 0xd0, 0x9a, 0xd1, 0x80, 0xd0,
                       0xb8, 0xd0, 0xbf, 0xd1, 0x82, 0xd0, 0xbe, 0xd0, 0x9f, 0xd1, 0x80, 0xd0, 0xbe, 0x20, 0x48, 0x53,
                       0x4d, 0xc2, 0xbb, 0x20, 0xd0, 0xb2, 0xd0, 0xb5, 0xd1, 0x80, 0xd1, 0x81, 0xd0, 0xb8, 0xd0, 0xb8,
                       0x20, 0x32, 0x2e, 0x30, 0x30, 0x43, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x3c, 0x30, 0x3a, 0x30,
                       0x08, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x64, 0x71, 0x01, 0x30, 0x08, 0x06, 0x06, 0x2a, 0x85, 0x03,
                       0x64, 0x71, 0x02, 0x30, 0x08, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x64, 0x71, 0x03, 0x30, 0x08, 0x06,
                       0x06, 0x2a, 0x85, 0x03, 0x64, 0x71, 0x04, 0x30, 0x08, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x64, 0x71,
                       0x05, 0x30, 0x06, 0x06, 0x04, 0x55, 0x1d, 0x20, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f,
                       0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13,
                       0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
                       0x0e, 0x04, 0x16, 0x04, 0x14, 0xc2, 0x54, 0xf1, 0xb4, 0x6b, 0xd4, 0x4c, 0xb7, 0xe0, 0x6d, 0x36,
                       0xb4, 0x23, 0x90, 0xf1, 0xfe, 0xc3, 0x3c, 0x9b, 0x06, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x85, 0x03,
                       0x07, 0x01, 0x01, 0x03, 0x02, 0x03, 0x41, 0x00, 0x9a, 0xfa, 0xfd, 0xe2, 0x3b, 0xac, 0x72, 0xfb,
                       0xf8, 0x5b, 0x10, 0x9e, 0x81, 0xf6, 0x8b, 0xa0, 0xd5, 0xc6, 0xa6, 0xa5, 0x6c, 0x8c, 0x4b, 0x2a,
                       0x3d, 0x39, 0x79, 0xda, 0x59, 0x18, 0xf2, 0xcb, 0x6f, 0xa0, 0x76, 0x3d, 0x30, 0x0c, 0xc9, 0xae,
                       0xe9, 0x4a, 0xdf, 0x61, 0x6f, 0xc4, 0x27, 0x14, 0x00, 0x60, 0xb1, 0x1e, 0x08, 0x13, 0x98, 0x13,
                       0xe1, 0x55, 0x64, 0x0d, 0x66, 0xd7, 0xfe, 0x7e};


//static void asn_print_universal(tag data_tag, ak_uint32 data_len, ak_byte* p_data)
//{
//    bit_string bit_string_data;
//    if ((data_tag & UNIVERSAL) == 0)
//    {
//        switch (data_tag & 0x1F)
//        {
//        case TBOOLEAN:
//            if(*p_data == 0x00)
//                printf("False\n");
//            else
//                printf("True\n");
//            break;
//        case TINTEGER:
//            //FIXME: переделать под вовод нормельного значения
//            ak_asn_print_hex_data(p_data, data_len);
//            break;
//        case TBIT_STRING:
//            new_asn_get_bitstr(p_data, data_len, &bit_string_data);
//
//            for(size_t i = 0; i < bit_string_data.m_val_len; i++)
//            {
//                ak_uint8 unused_bits = 0;
//                if (i == bit_string_data.m_val_len - 1)
//                    unused_bits = bit_string_data.m_unused;
//
//                for(ak_int8 j = 7; j >= (ak_int8)unused_bits; j--)
//                {
//                    ak_uint8 bit = (bit_string_data.mp_value[i] >> j) & (ak_uint8)0x01;
//                    printf("%u", bit);
//                }
//            }
//            putchar('\n');
//
//            break;
//        default: printf("bad data");
//        }
//    }
//
//}

int ak_function_log_logfile( const char *message )
{
    if( message != NULL )
    {
        FILE* err_file = fopen("/Users/anton/Desktop/log.txt", "w+");
        if(err_file)
        {
            fprintf(err_file, "%s\n", message);
            fclose(err_file);
        }
        else
            fprintf(stderr, "%s\n", "Can't open error log file");
    }
    return ak_error_ok;
}

 int main( int argc, char *argv[] )
{
    ak_uint32 i = 0;
    int error = ak_error_ok;

    /* Структура, хранящая результат декодирования данных */
    ak_asn_tlv p_root_tlv;

    /* Массив закодированных данных */
    ak_byte* p_plain_data = test_data;

    /* Массив закодированных данных */
    ak_byte* p_encoded_data;
    /* Размер данных после кодирования */
    ak_uint32 size = 0;

    /* Результат теста */
    bool_t test_result = ak_true;

    /* массив для хранения данных, считанных с диска */
    ak_byte file_data[4098];
    /* размер обрабатываемых данных */
    size_t data_length = sizeof( test_data );

    if( argc > 1 ) {
      /* интерпретируем параметр программы как имя файла в der-кодировке
         и считываем данные в массив file_data */
       FILE *fp = fopen( argv[1], "rb" );
       data_length = 0;
       memset( file_data, 0, sizeof( file_data ));

       if( !fp ) {
         printf("Incorrect file name %s\n", argv[1] );
         return ak_libakrypt_destroy();
       }
       while( !feof(fp)) {
        fread( file_data+data_length, 1, 1, fp ); data_length++;
        if( data_length >= sizeof( file_data )) break;
       }
       data_length--;
       fclose(fp);
       p_plain_data = file_data;
    }


    /* Инициализируем библиотеку */
    if (ak_libakrypt_create( ak_function_log_stderr ) != ak_true) return ak_libakrypt_destroy();

    /* Декодируем данные */
    printf("parsing result code: %d\n", error = ak_asn_parse_data( p_plain_data, data_length, &p_root_tlv));
    if( error != ak_error_ok ) {
      printf("Parsing error\n");
      return ak_libakrypt_destroy();
    }

    /* Выводим декодированые данные в виде дерева */
    printf("Decoded data:\n");

    new_ak_asn_print_tree(p_root_tlv);

    /* Кодируем данные обратно */
    ak_asn_build_data(p_root_tlv, &p_encoded_data, &size);

    /* Выводим исходную ASN.1 последовательность */
    printf("%-20s", "Original data : ");
    ak_asn_print_hex_data( p_plain_data, (ak_uint32)data_length );
    putchar('\n');

    /* Выводим закодированную ASN.1 последовательность */
    printf("%-20s", "Encoded data : ");
    ak_asn_print_hex_data( p_encoded_data, size );
    putchar('\n');

    /* Сравниваем размер исходных данных с закодированными */
    if(size != data_length )
    {
        test_result = ak_false;
        printf("Sizes differ, original: %u, encoded: %u\n", (ak_uint32)data_length, size );
        if( size < data_length ) {
          printf("Original data greather then encoded data!\n");
        } else printf("Encoded data greather then original data!\n");
    }

    /* Сравниваем исходные данные с закодированными */
    for ( i = 0; i < ak_min( size, data_length ); i++) {
      if( p_plain_data[i] != p_encoded_data[i]) {

        printf("Data differ at %u byte\n", i + 1);
        test_result = ak_false;
        break;
      }
    }

    if(test_result) {
      if( argc>1 ) printf("Test for file %s passed!\n", argv[1] );
          else printf("Test passed!\n");
    } else {
      if( argc>1 ) printf("Test for file %s failed!\n", argv[1] );
        else printf("Test failed!\n");
    }

    /* Освобождаем память */
    ak_asn_free_tree(p_root_tlv);
    free(p_encoded_data);

  /* Деинициализируем библиотеку */
   ak_libakrypt_destroy();
  if( test_result ) return EXIT_SUCCESS;
   else return EXIT_FAILURE;
}
