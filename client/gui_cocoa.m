#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>

#include <netinet/in.h>
#include <sys/socket.h>

#import <CoreFoundation/CoreFoundation.h>
#import <Cocoa/Cocoa.h>
#import <QuartzCore/QuartzCore.h>

static const uint8_t bluePNG[] = {
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
    0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08,
    0x08, 0x06, 0x00, 0x00, 0x00, 0xc4, 0x0f, 0xbe, 0x8b, 0x00, 0x00, 0x00,
    0x01, 0x73, 0x52, 0x47, 0x42, 0x00, 0xae, 0xce, 0x1c, 0xe9, 0x00, 0x00,
    0x00, 0x3e, 0x49, 0x44, 0x41, 0x54, 0x18, 0x57, 0x63, 0xf8, 0xff, 0xff,
    0x3f, 0x03, 0x3b, 0xe3, 0x7f, 0x71, 0x20, 0xae, 0x03, 0xe2, 0xb5, 0x50,
    0x0c, 0x62, 0x8b, 0x83, 0xe4, 0x60, 0x92, 0x5b, 0x81, 0xf8, 0x00, 0x1a,
    0x06, 0x89, 0x89, 0x33, 0x40, 0x55, 0xa3, 0x4b, 0xc2, 0x70, 0x1d, 0x03,
    0xd4, 0x48, 0x5c, 0x0a, 0xd6, 0x12, 0xa5, 0x80, 0xa0, 0x15, 0xf8, 0x1d,
    0x49, 0xc8, 0x9b, 0x00, 0xaf, 0x96, 0x6e, 0x7d, 0x64, 0x1b, 0xd8, 0x8b,
    0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82, };

static const uint8_t newContactPDF[] = {
    0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x35, 0x0a, 0x25, 0xb5, 0xed,
    0xae, 0xfb, 0x0a, 0x33, 0x20, 0x30, 0x20, 0x6f, 0x62, 0x6a, 0x0a, 0x3c,
    0x3c, 0x20, 0x2f, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x20, 0x34, 0x20,
    0x30, 0x20, 0x52, 0x0a, 0x20, 0x20, 0x20, 0x2f, 0x46, 0x69, 0x6c, 0x74,
    0x65, 0x72, 0x20, 0x2f, 0x46, 0x6c, 0x61, 0x74, 0x65, 0x44, 0x65, 0x63,
    0x6f, 0x64, 0x65, 0x0a, 0x3e, 0x3e, 0x0a, 0x73, 0x74, 0x72, 0x65, 0x61,
    0x6d, 0x0a, 0x78, 0x9c, 0x65, 0x53, 0xbd, 0x8e, 0x94, 0x31, 0x0c, 0xec,
    0xf3, 0x14, 0x7e, 0x81, 0x0d, 0xb6, 0x63, 0x27, 0x71, 0x4b, 0x83, 0x84,
    0x44, 0x71, 0xb4, 0x88, 0x02, 0x2d, 0x70, 0x08, 0xdd, 0x15, 0x77, 0x14,
    0xbc, 0x3e, 0x93, 0xbf, 0x0f, 0x09, 0x76, 0xb5, 0xca, 0x97, 0xf9, 0xc6,
    0xe3, 0xf1, 0x24, 0xfb, 0x92, 0x98, 0xc6, 0xf7, 0xf5, 0x91, 0xde, 0x7c,
    0x61, 0x7a, 0xfc, 0xb5, 0xf7, 0x1f, 0xdf, 0x11, 0xe7, 0x4e, 0xbf, 0xb1,
    0x7d, 0x8f, 0xdf, 0xcf, 0xf4, 0xe9, 0x33, 0x00, 0xa6, 0xaf, 0xc9, 0xe8,
    0x03, 0xbd, 0x90, 0x4c, 0xd6, 0x6d, 0x2c, 0xda, 0x3d, 0x97, 0xc0, 0xc7,
    0xe8, 0xfe, 0x9c, 0xbc, 0x49, 0x66, 0x3c, 0x0e, 0x94, 0x45, 0xe9, 0x99,
    0x34, 0x14, 0x48, 0x07, 0x62, 0x39, 0x5a, 0xa3, 0x27, 0x2a, 0x5c, 0x73,
    0x78, 0x21, 0xd5, 0x92, 0xb5, 0xea, 0x40, 0xc4, 0x72, 0xe9, 0x40, 0xb0,
    0x8a, 0x80, 0x93, 0xa8, 0xe8, 0x26, 0x89, 0xe4, 0x5e, 0x26, 0xc9, 0xfb,
    0x22, 0xa1, 0xbc, 0x86, 0x0c, 0x24, 0x56, 0x99, 0x84, 0x1c, 0xa1, 0x28,
    0xb9, 0xa3, 0xad, 0x34, 0x5f, 0x55, 0x10, 0x8a, 0x96, 0xb5, 0xf4, 0x09,
    0x1d, 0x92, 0x67, 0x57, 0x94, 0x55, 0x3e, 0x8e, 0x7a, 0xcf, 0xb5, 0x82,
    0xe3, 0xbc, 0xfa, 0x03, 0xe1, 0x85, 0x94, 0xbf, 0x42, 0xad, 0x6e, 0xc8,
    0x0e, 0xa9, 0xed, 0x6e, 0x2a, 0xd9, 0x6d, 0x22, 0x75, 0xb9, 0x16, 0xd1,
    0x6c, 0xbc, 0x5c, 0xc7, 0x6c, 0x76, 0x75, 0x4f, 0xa5, 0xfa, 0xac, 0x72,
    0x3b, 0x63, 0x74, 0x99, 0x0e, 0xf5, 0x04, 0x64, 0xbc, 0x18, 0x75, 0xf7,
    0x31, 0xd3, 0x39, 0x27, 0x6f, 0x4d, 0x6b, 0x73, 0x6e, 0x58, 0xda, 0xd1,
    0xd8, 0x9e, 0x51, 0x75, 0x4b, 0x3a, 0xdb, 0xf4, 0xea, 0x27, 0x18, 0x47,
    0x68, 0x43, 0xa2, 0x97, 0x0b, 0x58, 0x8c, 0x16, 0x03, 0x48, 0x13, 0xf1,
    0x29, 0x12, 0x7e, 0x51, 0x96, 0x2f, 0x91, 0x7a, 0x1a, 0x9f, 0xe4, 0xec,
    0xc8, 0x58, 0x8f, 0xc5, 0xf1, 0x3a, 0xcd, 0xa7, 0x01, 0xed, 0x30, 0x6b,
    0xbb, 0xec, 0xe9, 0x46, 0x62, 0xe7, 0x64, 0x51, 0xe7, 0xa5, 0x90, 0x7e,
    0xce, 0xd2, 0xa5, 0xaf, 0xe4, 0xe2, 0x12, 0x72, 0xdb, 0xb9, 0xc0, 0xd8,
    0x2a, 0xf3, 0xc6, 0xfb, 0x52, 0xf0, 0x2e, 0xfb, 0x91, 0xde, 0xd2, 0x43,
    0x42, 0x30, 0xda, 0xcc, 0x85, 0xfe, 0x7f, 0xc0, 0xcd, 0x56, 0x24, 0x1d,
    0x55, 0xe0, 0x1a, 0xa7, 0x1b, 0x65, 0xdc, 0xc9, 0x8d, 0xc0, 0x4f, 0xeb,
    0x0d, 0x3d, 0xe1, 0x74, 0xac, 0x9a, 0xdb, 0x3c, 0xce, 0x96, 0xad, 0x9f,
    0xdd, 0x1d, 0x5d, 0x33, 0x37, 0xa3, 0xb4, 0x01, 0x3e, 0x65, 0x7c, 0x29,
    0xde, 0xc7, 0xff, 0x00, 0x9e, 0x3c, 0xe2, 0xb0, 0x15, 0xd3, 0xd7, 0x56,
    0x8e, 0xd8, 0xd9, 0xde, 0x4f, 0xb3, 0x74, 0x41, 0xc7, 0xcc, 0x11, 0xf8,
    0xd7, 0xee, 0x1d, 0x43, 0x7e, 0x4f, 0xd8, 0xd3, 0x9a, 0x26, 0x72, 0xb5,
    0x15, 0x38, 0x82, 0x81, 0x9c, 0x0d, 0xfd, 0x5b, 0x69, 0x39, 0x2c, 0xe8,
    0xf5, 0x1b, 0x81, 0xcb, 0xd8, 0x08, 0x3c, 0xe0, 0xa6, 0x22, 0xb7, 0xfd,
    0xea, 0xb6, 0xa8, 0xb6, 0x38, 0x0f, 0xe9, 0x0f, 0xb6, 0x66, 0xca, 0x66,
    0x0a, 0x65, 0x6e, 0x64, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x0a, 0x65,
    0x6e, 0x64, 0x6f, 0x62, 0x6a, 0x0a, 0x34, 0x20, 0x30, 0x20, 0x6f, 0x62,
    0x6a, 0x0a, 0x20, 0x20, 0x20, 0x34, 0x34, 0x32, 0x0a, 0x65, 0x6e, 0x64,
    0x6f, 0x62, 0x6a, 0x0a, 0x32, 0x20, 0x30, 0x20, 0x6f, 0x62, 0x6a, 0x0a,
    0x3c, 0x3c, 0x0a, 0x20, 0x20, 0x20, 0x2f, 0x45, 0x78, 0x74, 0x47, 0x53,
    0x74, 0x61, 0x74, 0x65, 0x20, 0x3c, 0x3c, 0x0a, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x2f, 0x61, 0x30, 0x20, 0x3c, 0x3c, 0x20, 0x2f, 0x43, 0x41,
    0x20, 0x31, 0x20, 0x2f, 0x63, 0x61, 0x20, 0x31, 0x20, 0x3e, 0x3e, 0x0a,
    0x20, 0x20, 0x20, 0x3e, 0x3e, 0x0a, 0x3e, 0x3e, 0x0a, 0x65, 0x6e, 0x64,
    0x6f, 0x62, 0x6a, 0x0a, 0x35, 0x20, 0x30, 0x20, 0x6f, 0x62, 0x6a, 0x0a,
    0x3c, 0x3c, 0x20, 0x2f, 0x54, 0x79, 0x70, 0x65, 0x20, 0x2f, 0x50, 0x61,
    0x67, 0x65, 0x0a, 0x20, 0x20, 0x20, 0x2f, 0x50, 0x61, 0x72, 0x65, 0x6e,
    0x74, 0x20, 0x31, 0x20, 0x30, 0x20, 0x52, 0x0a, 0x20, 0x20, 0x20, 0x2f,
    0x4d, 0x65, 0x64, 0x69, 0x61, 0x42, 0x6f, 0x78, 0x20, 0x5b, 0x20, 0x30,
    0x20, 0x30, 0x20, 0x35, 0x37, 0x31, 0x2e, 0x35, 0x30, 0x31, 0x32, 0x32,
    0x31, 0x20, 0x32, 0x38, 0x35, 0x2e, 0x33, 0x39, 0x39, 0x39, 0x39, 0x34,
    0x20, 0x5d, 0x0a, 0x20, 0x20, 0x20, 0x2f, 0x43, 0x6f, 0x6e, 0x74, 0x65,
    0x6e, 0x74, 0x73, 0x20, 0x33, 0x20, 0x30, 0x20, 0x52, 0x0a, 0x20, 0x20,
    0x20, 0x2f, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x20, 0x3c, 0x3c, 0x0a, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x2f, 0x54, 0x79, 0x70, 0x65, 0x20, 0x2f,
    0x47, 0x72, 0x6f, 0x75, 0x70, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x2f, 0x53, 0x20, 0x2f, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x61, 0x72,
    0x65, 0x6e, 0x63, 0x79, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x2f,
    0x49, 0x20, 0x74, 0x72, 0x75, 0x65, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x2f, 0x43, 0x53, 0x20, 0x2f, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65,
    0x52, 0x47, 0x42, 0x0a, 0x20, 0x20, 0x20, 0x3e, 0x3e, 0x0a, 0x20, 0x20,
    0x20, 0x2f, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x20,
    0x32, 0x20, 0x30, 0x20, 0x52, 0x0a, 0x3e, 0x3e, 0x0a, 0x65, 0x6e, 0x64,
    0x6f, 0x62, 0x6a, 0x0a, 0x31, 0x20, 0x30, 0x20, 0x6f, 0x62, 0x6a, 0x0a,
    0x3c, 0x3c, 0x20, 0x2f, 0x54, 0x79, 0x70, 0x65, 0x20, 0x2f, 0x50, 0x61,
    0x67, 0x65, 0x73, 0x0a, 0x20, 0x20, 0x20, 0x2f, 0x4b, 0x69, 0x64, 0x73,
    0x20, 0x5b, 0x20, 0x35, 0x20, 0x30, 0x20, 0x52, 0x20, 0x5d, 0x0a, 0x20,
    0x20, 0x20, 0x2f, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x20, 0x31, 0x0a, 0x3e,
    0x3e, 0x0a, 0x65, 0x6e, 0x64, 0x6f, 0x62, 0x6a, 0x0a, 0x36, 0x20, 0x30,
    0x20, 0x6f, 0x62, 0x6a, 0x0a, 0x3c, 0x3c, 0x20, 0x2f, 0x43, 0x72, 0x65,
    0x61, 0x74, 0x6f, 0x72, 0x20, 0x28, 0x63, 0x61, 0x69, 0x72, 0x6f, 0x20,
    0x31, 0x2e, 0x31, 0x32, 0x2e, 0x31, 0x36, 0x20, 0x28, 0x68, 0x74, 0x74,
    0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x61, 0x69, 0x72, 0x6f, 0x67, 0x72, 0x61,
    0x70, 0x68, 0x69, 0x63, 0x73, 0x2e, 0x6f, 0x72, 0x67, 0x29, 0x29, 0x0a,
    0x20, 0x20, 0x20, 0x2f, 0x50, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x65, 0x72,
    0x20, 0x28, 0x63, 0x61, 0x69, 0x72, 0x6f, 0x20, 0x31, 0x2e, 0x31, 0x32,
    0x2e, 0x31, 0x36, 0x20, 0x28, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f,
    0x63, 0x61, 0x69, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x70, 0x68, 0x69, 0x63,
    0x73, 0x2e, 0x6f, 0x72, 0x67, 0x29, 0x29, 0x0a, 0x3e, 0x3e, 0x0a, 0x65,
    0x6e, 0x64, 0x6f, 0x62, 0x6a, 0x0a, 0x37, 0x20, 0x30, 0x20, 0x6f, 0x62,
    0x6a, 0x0a, 0x3c, 0x3c, 0x20, 0x2f, 0x54, 0x79, 0x70, 0x65, 0x20, 0x2f,
    0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x0a, 0x20, 0x20, 0x20, 0x2f,
    0x50, 0x61, 0x67, 0x65, 0x73, 0x20, 0x31, 0x20, 0x30, 0x20, 0x52, 0x0a,
    0x3e, 0x3e, 0x0a, 0x65, 0x6e, 0x64, 0x6f, 0x62, 0x6a, 0x0a, 0x78, 0x72,
    0x65, 0x66, 0x0a, 0x30, 0x20, 0x38, 0x0a, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x36, 0x35, 0x35, 0x33, 0x35, 0x20,
    0x66, 0x20, 0x0a, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x38, 0x35,
    0x36, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x6e, 0x20, 0x0a, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x35, 0x35, 0x36, 0x20, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x20, 0x6e, 0x20, 0x0a, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x31, 0x35, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20,
    0x6e, 0x20, 0x0a, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x35, 0x33,
    0x34, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x6e, 0x20, 0x0a, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x36, 0x32, 0x38, 0x20, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x20, 0x6e, 0x20, 0x0a, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x39, 0x32, 0x31, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20,
    0x6e, 0x20, 0x0a, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x30, 0x35,
    0x30, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x6e, 0x20, 0x0a, 0x74,
    0x72, 0x61, 0x69, 0x6c, 0x65, 0x72, 0x0a, 0x3c, 0x3c, 0x20, 0x2f, 0x53,
    0x69, 0x7a, 0x65, 0x20, 0x38, 0x0a, 0x20, 0x20, 0x20, 0x2f, 0x52, 0x6f,
    0x6f, 0x74, 0x20, 0x37, 0x20, 0x30, 0x20, 0x52, 0x0a, 0x20, 0x20, 0x20,
    0x2f, 0x49, 0x6e, 0x66, 0x6f, 0x20, 0x36, 0x20, 0x30, 0x20, 0x52, 0x0a,
    0x3e, 0x3e, 0x0a, 0x73, 0x74, 0x61, 0x72, 0x74, 0x78, 0x72, 0x65, 0x66,
    0x0a, 0x31, 0x31, 0x30, 0x32, 0x0a, 0x25, 0x25, 0x45, 0x4f, 0x46, 0x0a, };

static const uint8_t composePDF[] = {
    0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x35, 0x0a, 0x25, 0xb5, 0xed,
    0xae, 0xfb, 0x0a, 0x33, 0x20, 0x30, 0x20, 0x6f, 0x62, 0x6a, 0x0a, 0x3c,
    0x3c, 0x20, 0x2f, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x20, 0x34, 0x20,
    0x30, 0x20, 0x52, 0x0a, 0x20, 0x20, 0x20, 0x2f, 0x46, 0x69, 0x6c, 0x74,
    0x65, 0x72, 0x20, 0x2f, 0x46, 0x6c, 0x61, 0x74, 0x65, 0x44, 0x65, 0x63,
    0x6f, 0x64, 0x65, 0x0a, 0x3e, 0x3e, 0x0a, 0x73, 0x74, 0x72, 0x65, 0x61,
    0x6d, 0x0a, 0x78, 0x9c, 0x75, 0x52, 0xcb, 0x4e, 0xc4, 0x30, 0x0c, 0xbc,
    0xe7, 0x2b, 0xfc, 0x03, 0x6b, 0x1c, 0xc7, 0x89, 0x93, 0x2f, 0x40, 0x42,
    0xe2, 0xb0, 0x70, 0x44, 0x1c, 0x50, 0x81, 0x45, 0xa8, 0x1c, 0x58, 0x0e,
    0xfc, 0x3e, 0xd3, 0x47, 0x82, 0xb4, 0x08, 0x55, 0x55, 0x33, 0x53, 0x67,
    0x3c, 0x9e, 0xe4, 0x33, 0x08, 0x9b, 0xba, 0xe5, 0x48, 0x7f, 0x17, 0xe7,
    0x13, 0x5d, 0x3d, 0x09, 0x9d, 0xbe, 0x82, 0x66, 0xe3, 0x56, 0x22, 0xc5,
    0xa4, 0xdc, 0xa4, 0xd0, 0x07, 0x75, 0xa6, 0x28, 0x67, 0x8a, 0xcd, 0xb9,
    0x56, 0xa7, 0x8c, 0x9d, 0x85, 0xa2, 0x3a, 0x5b, 0xdd, 0xc1, 0x44, 0xd9,
    0x59, 0xdc, 0x36, 0x18, 0x48, 0xb6, 0x1d, 0x32, 0xa4, 0x26, 0xac, 0x55,
    0x12, 0xa7, 0xa8, 0xbd, 0x54, 0x8b, 0x70, 0x82, 0xdc, 0x2e, 0xd4, 0xe1,
    0x34, 0xfa, 0xec, 0x4c, 0x18, 0x2e, 0xba, 0xc0, 0xa5, 0xcf, 0x89, 0xde,
    0xc2, 0x6b, 0x00, 0xa6, 0x75, 0x1a, 0x6d, 0x5c, 0x20, 0x18, 0xad, 0x72,
    0x8b, 0x06, 0x39, 0x5b, 0xf4, 0x0f, 0xc9, 0xb9, 0x59, 0xa6, 0xf3, 0x0b,
    0xa1, 0x56, 0x7c, 0xfd, 0xa7, 0xe8, 0x1d, 0xab, 0xd1, 0xfa, 0xaf, 0xd1,
    0x61, 0xab, 0xb5, 0xad, 0x48, 0x68, 0x79, 0xee, 0xae, 0xd1, 0x97, 0xab,
    0xa8, 0xe7, 0x46, 0xdf, 0x20, 0x6f, 0xf0, 0xbe, 0x87, 0x87, 0x47, 0x24,
    0x28, 0xf4, 0x1c, 0x8c, 0x6e, 0xe9, 0x13, 0x8d, 0x97, 0xda, 0xc3, 0xf2,
    0xd1, 0xe2, 0x9c, 0x3c, 0xd3, 0xf4, 0x11, 0x92, 0x35, 0xd6, 0x08, 0x5b,
    0x08, 0x7b, 0xcd, 0xd3, 0x2d, 0xb2, 0x79, 0xea, 0xc4, 0x4c, 0x8e, 0x19,
    0xa5, 0xd5, 0x4e, 0xb8, 0x67, 0x40, 0xf8, 0x42, 0x8e, 0xa2, 0x1d, 0x06,
    0x32, 0x63, 0x18, 0xc0, 0xa0, 0xa3, 0x40, 0x11, 0x05, 0xa6, 0x9a, 0x7f,
    0x19, 0x48, 0x37, 0x48, 0x77, 0x45, 0xcd, 0x05, 0x21, 0xb5, 0xd1, 0x72,
    0xc7, 0x01, 0x22, 0xdd, 0x56, 0x2f, 0x99, 0x29, 0x25, 0xe1, 0x5c, 0x75,
    0x30, 0x29, 0x66, 0xc6, 0xb8, 0x5d, 0xb3, 0xc3, 0xbd, 0xe9, 0xb4, 0x13,
    0xc3, 0xd7, 0x3c, 0x2a, 0x36, 0xdf, 0x5d, 0x6e, 0x9f, 0xea, 0x22, 0x86,
    0xe5, 0xb8, 0xee, 0xe9, 0x18, 0x54, 0x90, 0xe7, 0xbf, 0xd1, 0xa9, 0x71,
    0x8c, 0xb8, 0x1d, 0x38, 0xc4, 0x64, 0x88, 0x2e, 0x67, 0xdc, 0x86, 0x16,
    0xd7, 0x63, 0x55, 0x30, 0x5b, 0x76, 0x59, 0x6c, 0x39, 0x9e, 0x8c, 0x7b,
    0x3c, 0xd3, 0x22, 0x7a, 0x0c, 0x3f, 0xda, 0x51, 0x92, 0xeb, 0x0a, 0x65,
    0x6e, 0x64, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x0a, 0x65, 0x6e, 0x64,
    0x6f, 0x62, 0x6a, 0x0a, 0x34, 0x20, 0x30, 0x20, 0x6f, 0x62, 0x6a, 0x0a,
    0x20, 0x20, 0x20, 0x33, 0x34, 0x34, 0x0a, 0x65, 0x6e, 0x64, 0x6f, 0x62,
    0x6a, 0x0a, 0x32, 0x20, 0x30, 0x20, 0x6f, 0x62, 0x6a, 0x0a, 0x3c, 0x3c,
    0x0a, 0x20, 0x20, 0x20, 0x2f, 0x45, 0x78, 0x74, 0x47, 0x53, 0x74, 0x61,
    0x74, 0x65, 0x20, 0x3c, 0x3c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x2f, 0x61, 0x30, 0x20, 0x3c, 0x3c, 0x20, 0x2f, 0x43, 0x41, 0x20, 0x31,
    0x20, 0x2f, 0x63, 0x61, 0x20, 0x31, 0x20, 0x3e, 0x3e, 0x0a, 0x20, 0x20,
    0x20, 0x3e, 0x3e, 0x0a, 0x3e, 0x3e, 0x0a, 0x65, 0x6e, 0x64, 0x6f, 0x62,
    0x6a, 0x0a, 0x35, 0x20, 0x30, 0x20, 0x6f, 0x62, 0x6a, 0x0a, 0x3c, 0x3c,
    0x20, 0x2f, 0x54, 0x79, 0x70, 0x65, 0x20, 0x2f, 0x50, 0x61, 0x67, 0x65,
    0x0a, 0x20, 0x20, 0x20, 0x2f, 0x50, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x20,
    0x31, 0x20, 0x30, 0x20, 0x52, 0x0a, 0x20, 0x20, 0x20, 0x2f, 0x4d, 0x65,
    0x64, 0x69, 0x61, 0x42, 0x6f, 0x78, 0x20, 0x5b, 0x20, 0x30, 0x20, 0x30,
    0x20, 0x37, 0x38, 0x35, 0x2e, 0x34, 0x39, 0x39, 0x30, 0x38, 0x34, 0x20,
    0x32, 0x36, 0x37, 0x2e, 0x33, 0x37, 0x35, 0x20, 0x5d, 0x0a, 0x20, 0x20,
    0x20, 0x2f, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73, 0x20, 0x33,
    0x20, 0x30, 0x20, 0x52, 0x0a, 0x20, 0x20, 0x20, 0x2f, 0x47, 0x72, 0x6f,
    0x75, 0x70, 0x20, 0x3c, 0x3c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x2f, 0x54, 0x79, 0x70, 0x65, 0x20, 0x2f, 0x47, 0x72, 0x6f, 0x75, 0x70,
    0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x2f, 0x53, 0x20, 0x2f, 0x54,
    0x72, 0x61, 0x6e, 0x73, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x63, 0x79, 0x0a,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x2f, 0x49, 0x20, 0x74, 0x72, 0x75,
    0x65, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x2f, 0x43, 0x53, 0x20,
    0x2f, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x52, 0x47, 0x42, 0x0a, 0x20,
    0x20, 0x20, 0x3e, 0x3e, 0x0a, 0x20, 0x20, 0x20, 0x2f, 0x52, 0x65, 0x73,
    0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x20, 0x32, 0x20, 0x30, 0x20, 0x52,
    0x0a, 0x3e, 0x3e, 0x0a, 0x65, 0x6e, 0x64, 0x6f, 0x62, 0x6a, 0x0a, 0x31,
    0x20, 0x30, 0x20, 0x6f, 0x62, 0x6a, 0x0a, 0x3c, 0x3c, 0x20, 0x2f, 0x54,
    0x79, 0x70, 0x65, 0x20, 0x2f, 0x50, 0x61, 0x67, 0x65, 0x73, 0x0a, 0x20,
    0x20, 0x20, 0x2f, 0x4b, 0x69, 0x64, 0x73, 0x20, 0x5b, 0x20, 0x35, 0x20,
    0x30, 0x20, 0x52, 0x20, 0x5d, 0x0a, 0x20, 0x20, 0x20, 0x2f, 0x43, 0x6f,
    0x75, 0x6e, 0x74, 0x20, 0x31, 0x0a, 0x3e, 0x3e, 0x0a, 0x65, 0x6e, 0x64,
    0x6f, 0x62, 0x6a, 0x0a, 0x36, 0x20, 0x30, 0x20, 0x6f, 0x62, 0x6a, 0x0a,
    0x3c, 0x3c, 0x20, 0x2f, 0x43, 0x72, 0x65, 0x61, 0x74, 0x6f, 0x72, 0x20,
    0x28, 0x63, 0x61, 0x69, 0x72, 0x6f, 0x20, 0x31, 0x2e, 0x31, 0x32, 0x2e,
    0x31, 0x36, 0x20, 0x28, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63,
    0x61, 0x69, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x70, 0x68, 0x69, 0x63, 0x73,
    0x2e, 0x6f, 0x72, 0x67, 0x29, 0x29, 0x0a, 0x20, 0x20, 0x20, 0x2f, 0x50,
    0x72, 0x6f, 0x64, 0x75, 0x63, 0x65, 0x72, 0x20, 0x28, 0x63, 0x61, 0x69,
    0x72, 0x6f, 0x20, 0x31, 0x2e, 0x31, 0x32, 0x2e, 0x31, 0x36, 0x20, 0x28,
    0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x61, 0x69, 0x72, 0x6f,
    0x67, 0x72, 0x61, 0x70, 0x68, 0x69, 0x63, 0x73, 0x2e, 0x6f, 0x72, 0x67,
    0x29, 0x29, 0x0a, 0x3e, 0x3e, 0x0a, 0x65, 0x6e, 0x64, 0x6f, 0x62, 0x6a,
    0x0a, 0x37, 0x20, 0x30, 0x20, 0x6f, 0x62, 0x6a, 0x0a, 0x3c, 0x3c, 0x20,
    0x2f, 0x54, 0x79, 0x70, 0x65, 0x20, 0x2f, 0x43, 0x61, 0x74, 0x61, 0x6c,
    0x6f, 0x67, 0x0a, 0x20, 0x20, 0x20, 0x2f, 0x50, 0x61, 0x67, 0x65, 0x73,
    0x20, 0x31, 0x20, 0x30, 0x20, 0x52, 0x0a, 0x3e, 0x3e, 0x0a, 0x65, 0x6e,
    0x64, 0x6f, 0x62, 0x6a, 0x0a, 0x78, 0x72, 0x65, 0x66, 0x0a, 0x30, 0x20,
    0x38, 0x0a, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x20, 0x36, 0x35, 0x35, 0x33, 0x35, 0x20, 0x66, 0x20, 0x0a, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x37, 0x35, 0x35, 0x20, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x20, 0x6e, 0x20, 0x0a, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x34, 0x35, 0x38, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x6e,
    0x20, 0x0a, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x35,
    0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x6e, 0x20, 0x0a, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x34, 0x33, 0x36, 0x20, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x20, 0x6e, 0x20, 0x0a, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x35, 0x33, 0x30, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x6e,
    0x20, 0x0a, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x38, 0x32, 0x30,
    0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x6e, 0x20, 0x0a, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x39, 0x34, 0x39, 0x20, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x20, 0x6e, 0x20, 0x0a, 0x74, 0x72, 0x61, 0x69, 0x6c, 0x65,
    0x72, 0x0a, 0x3c, 0x3c, 0x20, 0x2f, 0x53, 0x69, 0x7a, 0x65, 0x20, 0x38,
    0x0a, 0x20, 0x20, 0x20, 0x2f, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x37, 0x20,
    0x30, 0x20, 0x52, 0x0a, 0x20, 0x20, 0x20, 0x2f, 0x49, 0x6e, 0x66, 0x6f,
    0x20, 0x36, 0x20, 0x30, 0x20, 0x52, 0x0a, 0x3e, 0x3e, 0x0a, 0x73, 0x74,
    0x61, 0x72, 0x74, 0x78, 0x72, 0x65, 0x66, 0x0a, 0x31, 0x30, 0x30, 0x31,
    0x0a, 0x25, 0x25, 0x45, 0x4f, 0x46, 0x0a, };

enum {
  SET_INDICATOR_IMAGES = 0,
  SHOW_TOR_PROMPT,
  DESTROY_TOR_PROMPT,
  SHOW_CREATE_PASSPHRASE,
  PASSPHRASE_ENTERED,
  SHOW_CREATE_ACCOUNT,
  CREATE_ACCOUNT_ENTERED,
  UPDATE_CREATE_ACCOUNT,
  DESTROY_CREATE_ACCOUNT,
  SET_TABLE_CONTENTS,
  NEW_CONTACT,
  NEW_CONTACT_REJECTED,
  NEW_CONTACT_ACCEPTED,
  SEND_MESSAGE,
  OUTLINE_CLICKED,
  TABLE_CLICKED,
  SET_CONTENTS,
  COMPOSE,
  COMPOSE_ERROR,
  OPEN_COMPOSE,
  ATTACH,
  ADD_ATTACHMENT,
  REMOVE_ATTACHMENT,
  REMOVE_DETACHMENT,
  PROMPT_DETACHMENT,
  SAVE_ENCRYPTED,
  UPLOAD,
  DETACHMENT_ERROR,
  DETACHMENT_UPDATE,
  ADD_DETACHMENT,
  CANCEL_DETACHMENT,
  UPDATE_USAGE,
  COMPOSE_TEXT,
  COMPOSE_CLOSE,
};

extern void sendCocoaEvent(int event, uint64_t i, const uint8_t* s, size_t len);

#define abortWithMessage(msg) abortWithLocationAndMessage(__LINE__, msg)

static void abortWithLocationAndMessage(unsigned line, const char* msg) {
  fprintf(stderr, "ABORT: gui_cocoa.m:%u: %s\n", line, msg);
  abort();
}

static NSTextField* labelNS(NSString* s) {
  NSTextField* label = [[NSTextField alloc] init];
  [label setTranslatesAutoresizingMaskIntoConstraints:NO];

  if (s != NULL)
    [label setStringValue:s];
  [label setBezeled:NO];
  [label setDrawsBackground:NO];
  [label setEditable:NO];
  [label setSelectable:NO];

  return label;
}

@interface SizedTextField : NSTextField {
 @private
  CGFloat _width;
}

@end

@implementation SizedTextField

- (SizedTextField*)init {
  return [self initWithWidth:0];
}

- (SizedTextField*)initWithWidth:(CGFloat)width {
  _width = width;
  return [super init];
}

- (NSSize)intrinsicContentSize {
  CGFloat width = _width;

  if (width == 0) {
    NSRect superFrame = [self.superview frame];
    width = superFrame.size.width - 16;
  }

  NSRect frame;
  memset(&frame, 0, sizeof(frame));
  frame.size.width = width;
  frame.size.height = CGFLOAT_MAX;
  CGFloat height = [self.cell cellSizeForBounds:frame].height;
  NSSize size = NSMakeSize(width, height);
  return size;
}

- (void)didChangeText {
  [super didChangeText];
  [self invalidateIntrinsicContentSize];
}

@end

static SizedTextField* multiLineLabelNS(NSString* s, CGFloat width) {
  SizedTextField* body = [[SizedTextField alloc] initWithWidth:width];
  [body setFocusRingType:NSFocusRingTypeNone];
  [body setTranslatesAutoresizingMaskIntoConstraints:NO];
  if (s)
    [body setStringValue:s];
  [[body cell] setWraps:YES];
  [body setDrawsBackground:NO];
  [body setBezeled:NO];
  [body setEditable:NO];
  return body;
}

static NSTextField* label(const char* msg) {
  return labelNS([[NSString alloc] initWithUTF8String:msg]);
}

static NSButton* button(const char* msg) {
  NSButton* b = [[NSButton alloc] init];
  [b setTranslatesAutoresizingMaskIntoConstraints:NO];
  [b setButtonType:NSMomentaryPushInButton];
  [b setBordered:YES];
  [b setBezelStyle:NSRoundedBezelStyle];
  [b setImagePosition:NSNoImage];
  [b setAlignment:NSCenterTextAlignment];
  [[b cell] setControlTint:NSBlueControlTint];
  [b setEnabled:YES];
  [b setTitle:[[NSString alloc] initWithUTF8String:msg]];
  return b;
}

static void clearSheet(NSWindow* sheet) {
  for (;;) {
    NSArray* subviews = [[sheet contentView] subviews];
    if ([subviews count] == 0)
      break;
    [[subviews objectAtIndex:0] removeFromSuperview];
  }
}

static void shakeWindow(id window) {
  // Thanks for StackOverflow for this.
  static int numberOfShakes = 2;
  static float durationOfShake = 0.25f;
  static float vigourOfShake = 0.03f;

  CGRect frame = [window frame];
  CAKeyframeAnimation* shakeAnimation = [CAKeyframeAnimation animation];

  CGMutablePathRef shakePath = CGPathCreateMutable();
  CGPathMoveToPoint(shakePath, NULL, NSMinX(frame), NSMinY(frame));
  int index;
  for (index = 0; index < numberOfShakes; ++index) {
    CGPathAddLineToPoint(shakePath,
                         NULL,
                         NSMinX(frame) - frame.size.width * vigourOfShake,
                         NSMinY(frame));
    CGPathAddLineToPoint(shakePath,
                         NULL,
                         NSMinX(frame) + frame.size.width * vigourOfShake,
                         NSMinY(frame));
  }
  CGPathCloseSubpath(shakePath);
  shakeAnimation.path = shakePath;
  shakeAnimation.duration = durationOfShake;

  [window setAnimations:[NSDictionary dictionaryWithObject:shakeAnimation
                                                    forKey:@"frameOrigin"]];
  [[window animator] setFrameOrigin:[window frame].origin];
};

static uint32_t getU8(const uint8_t** in_data, size_t* in_len) {
  const uint8_t* data = *in_data;
  size_t len = *in_len;

  if (len < 1)
    abortWithMessage("truncated data");

  uint8_t ret = data[0];

  *in_data = data + 1;
  *in_len = len - 1;
  return ret;
}

static uint32_t getU32(const uint8_t** in_data, size_t* in_len) {
  const uint8_t* data = *in_data;
  size_t len = *in_len;

  if (len < 4)
    abortWithMessage("truncated data");

  uint32_t ret = ((uint32_t)data[0]) | ((uint32_t)data[1]) << 8 |
                 ((uint32_t)data[2]) << 16 | ((uint32_t)data[3]) << 24;

  *in_data = data + 4;
  *in_len = len - 4;
  return ret;
}

static uint64_t getU64(const uint8_t** in_data, size_t* in_len) {
  const uint8_t* data = *in_data;
  size_t len = *in_len;

  if (len < 8)
    abortWithMessage("truncated data");

  uint64_t ret = ((uint64_t)data[0]) | ((uint64_t)data[1]) << 8 |
                 ((uint64_t)data[2]) << 16 | ((uint64_t)data[3]) << 24 |
                 ((uint64_t)data[4]) << 32 | ((uint64_t)data[5]) << 40 |
                 ((uint64_t)data[6]) << 48 | ((uint64_t)data[7]) << 56;

  *in_data = data + 8;
  *in_len = len - 8;
  return ret;
}

static NSString* getString(const uint8_t** inData,
                           size_t* inLen,
                           char** inBuf,
                           size_t* inBufLength) {
  const uint8_t* data = *inData;
  size_t len = *inLen;
  size_t bufLength = 0;
  char* buf = NULL;

  if (inBuf) {
    buf = *inBuf;
    bufLength = *inBufLength;
  }

  uint32_t stringLength = getU32(&data, &len);
  if (len < stringLength)
    abortWithMessage("truncated data");

  if (stringLength + 1 < stringLength)
    abortWithMessage("stringLength overflow");

  if (bufLength <= stringLength + 1) {
    if (buf)
      free(buf);
    bufLength = stringLength + 1;
    buf = malloc(bufLength);
  }
  memcpy(buf, data, stringLength);
  buf[stringLength] = 0;
  data += stringLength;
  len -= stringLength;

  NSString* s = [[NSString alloc] initWithUTF8String:buf];
  *inData = data;
  *inLen = len;
  if (inBuf) {
    *inBuf = buf;
    *inBufLength = bufLength;
  } else {
    if (buf)
      free(buf);
  }
  return s;
}

static uint8_t* makeSpace(uint8_t** inData, size_t* inLen, size_t bytes) {
  uint8_t* data = *inData;
  size_t len = *inLen;
  uint8_t* ret;

  if (!data) {
    len = bytes;
    ret = data = malloc(len);
  } else {
    data = realloc(data, len + bytes);
    ret = data + len;
    len += bytes;
  }

  *inData = data;
  *inLen = len;
  return ret;
}

static void autolayout(NSView* view, id context, ...) {
  va_list v;
  va_start(v, context);

  for (;;) {
    const char* visual = va_arg(v, const char*);
    if (visual == NULL)
      break;
    [view addConstraints:
              [NSLayoutConstraint constraintsWithVisualFormat:
                      [[NSString alloc] initWithUTF8String:visual]
                                                      options:0
                                                      metrics:nil
                                                        views:context]];
  }

  va_end(v);
}

@interface SplitDelegate : NSObject<NSSplitViewDelegate> {
}

@end

@implementation SplitDelegate

- (CGFloat)splitView:(NSSplitView*)splitView
    constrainSplitPosition:(CGFloat)proposedPosition
               ofSubviewAt:(NSInteger)dividerIndex {
  if (proposedPosition < 100)
    proposedPosition = 100;
  return proposedPosition;
}

@end

@interface ContentView : NSView {
 @private
  NSTextField* _lastHeader;
  NSView* _lastValue;
}

@end

@implementation ContentView

- (BOOL)isFlipped {
  return YES;
}

- (void)drawRect:(NSRect)rect {
  [[NSColor whiteColor] setFill];
  NSRectFill(rect);

  if (_lastValue) {
    const CGFloat bottom = [_lastValue frame].origin.y + [_lastValue frame]
                                                             .size.height +
                           8;
    CGRect frame = [self frame];
    CGRect headerRect = CGRectMake(0, 0, frame.size.width, bottom);
    headerRect = CGRectIntersection(headerRect, rect);
    [[NSColor colorWithWhite:0.98 alpha:1.0] setFill];
    NSRectFill(headerRect);

    headerRect = CGRectMake(0, bottom, frame.size.width, 1);
    headerRect = CGRectIntersection(headerRect, rect);
    [[NSColor lightGrayColor] setFill];
    NSRectFill(headerRect);
  }

  [super drawRect:rect];
}

- (void)addHeader:(NSString*)header withValue:(NSString*)value {
  NSTextField* headerView = labelNS(header);
  [headerView setTextColor:[NSColor grayColor]];

  NSTextField* valueView = labelNS(value);

  [self addSubview:headerView];
  [self addSubview:valueView];

  if (_lastHeader) {
    [self addConstraint:
              [NSLayoutConstraint constraintWithItem:headerView
                                           attribute:NSLayoutAttributeTop
                                           relatedBy:NSLayoutRelationEqual
                                              toItem:_lastHeader
                                           attribute:NSLayoutAttributeBottom
                                          multiplier:1.0
                                            constant:1]];
    [self addConstraint:
              [NSLayoutConstraint constraintWithItem:headerView
                                           attribute:NSLayoutAttributeRight
                                           relatedBy:NSLayoutRelationEqual
                                              toItem:_lastHeader
                                           attribute:NSLayoutAttributeRight
                                          multiplier:1.0
                                            constant:0]];
  } else {
    [self addConstraint:
              [NSLayoutConstraint constraintWithItem:headerView
                                           attribute:NSLayoutAttributeTop
                                           relatedBy:NSLayoutRelationEqual
                                              toItem:self
                                           attribute:NSLayoutAttributeTop
                                          multiplier:1.0
                                            constant:8]];
  }

  [self addConstraint:[NSLayoutConstraint
                          constraintWithItem:headerView
                                   attribute:NSLayoutAttributeLeft
                                   relatedBy:NSLayoutRelationGreaterThanOrEqual
                                      toItem:self
                                   attribute:NSLayoutAttributeLeft
                                  multiplier:1.0
                                    constant:8]];

  [self addConstraint:[NSLayoutConstraint
                          constraintWithItem:valueView
                                   attribute:NSLayoutAttributeLeft
                                   relatedBy:NSLayoutRelationGreaterThanOrEqual
                                      toItem:headerView
                                   attribute:NSLayoutAttributeRight
                                  multiplier:1.0
                                    constant:8]];

  [self addConstraint:
            [NSLayoutConstraint constraintWithItem:valueView
                                         attribute:NSLayoutAttributeBaseline
                                         relatedBy:NSLayoutRelationEqual
                                            toItem:headerView
                                         attribute:NSLayoutAttributeBaseline
                                        multiplier:1.0
                                          constant:0]];

  _lastHeader = headerView;
  _lastValue = valueView;
}

- (void)clear {
  for (;;) {
    NSArray* subviews = [self subviews];
    if ([subviews count] == 0)
      break;
    [[subviews objectAtIndex:0] removeFromSuperview];
  }
  _lastHeader = nil;
  _lastValue = nil;
}

- (void)setContents:(const uint8_t*)data withLength:(size_t)len {
  [self clear];

  size_t numHeaders = getU32(&data, &len);

  char* buf = NULL;
  size_t bufLength = 0;
  for (size_t i = 0; i < numHeaders; i++) {
    NSString* header = getString(&data, &len, &buf, &bufLength);
    NSString* value = getString(&data, &len, &buf, &bufLength);

    [self addHeader:header withValue:value];
  }

  [self setNeedsDisplay:YES];

  NSView* bottom = _lastValue;

  NSString* contents = getString(&data, &len, &buf, &bufLength);
  if ([contents length] > 0) {
    SizedTextField* body = multiLineLabelNS(contents, 0);
    [body setSelectable:YES];
    [self addSubview:body];

    autolayout(self,
               NSDictionaryOfVariableBindings(body),
               "|-8-[body]-8-|",
               "V:[body]-|",
               NULL);

    [self addConstraint:[NSLayoutConstraint
                            constraintWithItem:(bottom ? bottom : self)
                                     attribute:(bottom ? NSLayoutAttributeBottom
                                                       : NSLayoutAttributeTop)
                                     relatedBy:NSLayoutRelationEqual
                                        toItem:body
                                     attribute:NSLayoutAttributeTop
                                    multiplier:1.0
                                      constant:-16]];
    bottom = NULL;
  }

  if (bottom) {
    [self addConstraint:
              [NSLayoutConstraint constraintWithItem:bottom
                                           attribute:NSLayoutAttributeBottom
                                           relatedBy:NSLayoutRelationEqual
                                              toItem:self
                                           attribute:NSLayoutAttributeBottom
                                          multiplier:1.0
                                            constant:-16]];
  }

  if (len)
    abortWithMessage("trailing data in setContents");

  if (buf)
    free(buf);
}

@end

struct tableRow {
  unsigned indicator;
  NSString* name;
  NSString* extra;
  NSString* contents;
  uint64_t objId;
};

@interface TableSource : NSObject<NSTableViewDataSource> {
 @private
  unsigned _numRows;
  struct tableRow* _rows;
  NSMutableArray* _indicatorImages;
};

@end

@implementation TableSource

static void putNSString(uint8_t** inData, size_t* inLen, NSString* ns) {
  const char* s = [ns UTF8String];
  const size_t sLength = strlen(s);

  uint8_t* ptr = makeSpace(inData, inLen, 4 + sLength);
  ptr[0] = sLength;
  ptr[1] = sLength >> 8;
  ptr[2] = sLength >> 16;
  ptr[3] = sLength >> 24;
  memcpy(ptr + 4, s, sLength);
}

- (NSInteger)numberOfRowsInTableView:(NSTableView*)aTableView {
  return _numRows;
}

- (id)tableView:(NSTableView*)tableView
    objectValueForTableColumn:(NSTableColumn*)col
                          row:(NSInteger)rowIndex {
  NSString* colName = [col identifier];
  if ([colName isEqualToString:@"indicator"]) {
    NSTextAttachment* ta = [[NSTextAttachment alloc] init];
    [(NSCell*)[ta attachmentCell]
        setImage:[_indicatorImages objectAtIndex:_rows[rowIndex].indicator]];
    NSAttributedString* headerAS =
        [NSAttributedString attributedStringWithAttachment:ta];
    return headerAS;
  } else if ([colName isEqualToString:@"name"]) {
    return _rows[rowIndex].name;
  } else if ([colName isEqualToString:@"extra"]) {
    return _rows[rowIndex].extra;
  } else {
    NSString* contents = _rows[rowIndex].contents;
    NSColor* txtColor = [NSColor grayColor];
    NSDictionary* txtDict =
        [NSDictionary dictionaryWithObjectsAndKeys:
                          txtColor, NSForegroundColorAttributeName, nil];
    return
        [[NSAttributedString alloc] initWithString:contents attributes:txtDict];
  }
}

- (void)setIndicatorImages:(const uint8_t*)data withLength:(size_t)len {
  uint32_t numImages = getU32(&data, &len);
  _indicatorImages = [[NSMutableArray alloc] initWithCapacity:numImages];

  for (size_t i = 0; i < numImages; i++) {
    size_t pngLength = getU32(&data, &len);

    if (len < pngLength)
      abort();

    NSData* imageData = [[NSData alloc] initWithBytes:data length:pngLength];
    [_indicatorImages addObject:[[NSImage alloc] initWithData:imageData]];
    data += pngLength;
    len -= pngLength;
  }

  if (len)
    abort();
}

- (uint32_t)setContents:(const uint8_t*)data withLength:(size_t)len {
  if (_rows) {
    for (size_t i = 0; i < _numRows; i++) {
      [_rows[i].name release];
      [_rows[i].extra release];
      [_rows[i].contents release];
    }
    free(_rows);
    _rows = NULL;
    _numRows = 0;
  }

  _numRows = getU32(&data, &len);
  _rows = malloc(sizeof(struct tableRow) * _numRows);
  memset(_rows, 0, sizeof(struct tableRow) * _numRows);

  char* buf = NULL;
  size_t bufLength = 0;

  for (size_t i = 0; i < _numRows; i++) {
    uint32_t indicatorId = getU32(&data, &len);

    if (indicatorId >= [_indicatorImages count])
      abortWithMessage("indicator number out of range");

    _rows[i].indicator = indicatorId;

    _rows[i].name = getString(&data, &len, &buf, &bufLength);
    _rows[i].extra = getString(&data, &len, &buf, &bufLength);
    _rows[i].contents = getString(&data, &len, &buf, &bufLength);
    _rows[i].objId = getU64(&data, &len);
  }

  if (len)
    abortWithMessage("trailing data in setContents");

  if (buf)
    free(buf);

  return _numRows;
}

- (uint64_t)idForRow:(NSInteger)row {
  if (row < 0 || row > _numRows) {
    return 0;
  }
  return _rows[row].objId;
}

@end

@class PondGUI;

@interface PondOutline
    : NSObject<NSOutlineViewDataSource, NSOutlineViewDelegate> {
 @private
  NSArray* _topLevel;
  NSMutableDictionary* _dict;
  PondGUI* _pond;
}

- (PondOutline*)init;

@end

@implementation PondOutline

- (PondOutline*)init {
  [super init];

  _topLevel = [[NSArray arrayWithObjects:@"MAILBOXES", @"CLIENT", nil] retain];
  _dict = [NSMutableDictionary new];
  [_dict
      setObject:[NSArray arrayWithObjects:@"Inbox", @"Outbox", @"Drafts", nil]
         forKey:@"MAILBOXES"];
  [_dict
      setObject:[NSArray arrayWithObjects:@"Contacts", @"Identity", @"Log", nil]
         forKey:@"CLIENT"];
  return self;
}

- (NSString*)labelForRow:(NSInteger)row {
  NSInteger currentRow = 0;

  for (unsigned i = 0; i < [_topLevel count]; i++) {
    if (row == currentRow) {
      return nil;
    }
    currentRow++;

    NSArray* subArray = [_dict objectForKey:[_topLevel objectAtIndex:i]];
    for (unsigned j = 0; j < [subArray count]; j++) {
      if (row == currentRow) {
        return [subArray objectAtIndex:j];
      }
      currentRow++;
    }
  }

  return nil;
}

- (void)setGUI:(PondGUI*)pond {
  _pond = pond;
}

- (id)outlineView:(NSOutlineView*)outlineView
            child:(NSInteger)index
           ofItem:(id)item {
  if (item == nil)
    return [_topLevel objectAtIndex:index];

  return [[_dict objectForKey:item] objectAtIndex:index];
}

- (BOOL)outlineView:(NSOutlineView*)outlineView isItemExpandable:(id)item {
  if ([outlineView parentForItem:item] == nil) {
    return YES;
  }
  return NO;
}

- (NSInteger)outlineView:(NSOutlineView*)outlineView
    numberOfChildrenOfItem:(id)item {
  if (item == nil)
    return [_topLevel count];

  return [[_dict objectForKey:item] count];
}

- (BOOL)outlineView:(NSOutlineView*)outlineView
    shouldShowOutlineCellForItem:(id)item {
  return NO;
}

- (BOOL)outlineView:(NSOutlineView*)outlineView isGroupItem:(id)item {
  return [_topLevel containsObject:item];
}

- (BOOL)outlineView:(NSOutlineView*)outlineView shouldSelectItem:(id)item {
  if ([outlineView parentForItem:item] == nil)
    return NO;
  return YES;
}

- (id)outlineView:(NSOutlineView*)outlineView
    objectValueForTableColumn:(NSTableColumn*)theColumn
                       byItem:(id)item {
  return item;
}

- (id)inboxItem {
  return [[_dict objectForKey:@"MAILBOXES"] objectAtIndex:0];
}

- (void)outlineViewSelectionDidChange:(NSNotification*)notification {
  [_pond outlineSelectionChanged];
}

@end

@interface ComposeAttachment : NSObject
@property(retain) NSView* button;
@property(retain) NSView* field;
@property uint64_t ident;
@end

@implementation ComposeAttachment
@end

@interface Compose
    : NSObject<NSComboBoxDelegate, NSTextViewDelegate, NSWindowDelegate> {
 @private
  NSWindow* _window;
  NSComboBox* _toList;
  NSTextView* _edit;
  NSTextField* _sizeMsg;
  NSToolbarItem* _sendItem;
  uint64_t _id;
  NSScrollView* _editContainer;
  NSView* _window_view;
  NSMutableDictionary* _attachments;
  NSMutableDictionary* _detachments;
  NSWindow* _detachmentSheet;
  NSProgressIndicator* _detachmentProgress;
  NSTextField* _detachmentStatus;
  BOOL _detachmentError;
  BOOL _destinationSelected;
  BOOL _overSize;
}

@end

@implementation Compose

- (Compose*)init {
  _window = [[NSWindow alloc]
      initWithContentRect:NSMakeRect(0, 0, 400, 500)
                styleMask:NSTitledWindowMask | NSResizableWindowMask |
                          NSClosableWindowMask
                  backing:NSBackingStoreBuffered
                    defer:NO];
  _id = 0;
  _attachments = [[NSMutableDictionary alloc] init];
  _detachments = [[NSMutableDictionary alloc] init];
  _destinationSelected = NO;
  _overSize = NO;

  [_window cascadeTopLeftFromPoint:NSMakePoint(20, 20)];
  [_window setTitle:@"New Message"];

  id toolbar = [[NSToolbar alloc] initWithIdentifier:@"Compose"];
  [toolbar setDelegate:self];
  [toolbar setDisplayMode:NSToolbarDisplayModeIconOnly];
  [_window setToolbar:toolbar];

  _window_view = [_window contentView];

  NSTextField* to = label("To");
  [_window_view addSubview:to];

  _toList = [[NSComboBox alloc] init];
  [_toList setTranslatesAutoresizingMaskIntoConstraints:NO];
  [_toList setEditable:NO];
  [_toList setDelegate:self];
  [_window_view addSubview:_toList];

  _edit = [[NSTextView alloc] init];
  [_edit setFocusRingType:NSFocusRingTypeNone];
  [_edit setVerticallyResizable:YES];
  [_edit setHorizontallyResizable:NO];
  [_edit setAutoresizingMask:NSViewWidthSizable];
  [_edit setDelegate:self];
  [[_edit textContainer] setContainerSize:NSMakeSize(250, FLT_MAX)];
  [[_edit textContainer] setWidthTracksTextView:YES];

  _editContainer = [[NSScrollView alloc] init];
  [_editContainer setTranslatesAutoresizingMaskIntoConstraints:NO];
  [_editContainer setDocumentView:_edit];
  [_editContainer setHasVerticalScroller:YES];
  [_window_view addSubview:_editContainer];

  _sizeMsg = labelNS(nil);
  [_window_view addSubview:_sizeMsg];

  autolayout(
      _window_view,
      NSDictionaryOfVariableBindings(to, _toList, _editContainer, _sizeMsg),
      "|-[to]-[_toList(>=150)]",
      "V:|-[to]",
      "[_sizeMsg]-|",
      "V:|-[_sizeMsg]",
      "|[_editContainer(>=600)]|",
      "V:[_editContainer(>=400)]|",
      NULL);

  [_window_view addConstraint:[NSLayoutConstraint
                                  constraintWithItem:to
                                           attribute:NSLayoutAttributeBaseline
                                           relatedBy:NSLayoutRelationEqual
                                              toItem:_toList
                                           attribute:NSLayoutAttributeBaseline
                                          multiplier:1.0
                                            constant:0]];

  NSLayoutConstraint* cons =
      [NSLayoutConstraint constraintWithItem:to
                                   attribute:NSLayoutAttributeBottom
                                   relatedBy:NSLayoutRelationEqual
                                      toItem:_editContainer
                                   attribute:NSLayoutAttributeTop
                                  multiplier:1.0
                                    constant:-24];
  cons.priority = NSLayoutPriorityWindowSizeStayPut - 2;

  [_window_view addConstraint:cons];

  [_window makeKeyAndOrderFront:nil];

  return self;
}

- (void)windowWillClose:(NSNotification*)notification {
  sendCocoaEvent(COMPOSE_CLOSE, _id, NULL, 0);
}

- (void)textDidChange:(NSNotification*)notification {
  NSString* contents = [_edit string];
  const char* utf8 = [[_edit string] UTF8String];
  sendCocoaEvent(COMPOSE_TEXT, _id, (uint8_t*)strdup(utf8), strlen(utf8));
}

- (void)addContactName:(NSString*)name {
  [_toList addItemWithObjectValue:name];
}

- (void)setId:(uint64_t)ident {
  _id = ident;
}

- (void)updateSendButton {
  if (_overSize == NO && _destinationSelected == YES) {
    [_sendItem setEnabled:YES];
  } else {
    [_sendItem setEnabled:NO];
  }
}

- (void)updateUsage:(NSString*)msg isOversize:(BOOL)overSize {
  [_sizeMsg setStringValue:msg];
  _overSize = overSize;
  [self updateSendButton];
}

- (NSArray*)toolbarAllowedItemIdentifiers:(NSToolbar*)toolbar {
  return @[ @"Send", @"Attach" ];
}

- (NSArray*)toolbarDefaultItemIdentifiers:(NSToolbar*)toolbar {
  return [self toolbarAllowedItemIdentifiers:toolbar];
}

- (void)addAttachment:(NSString*)title withId:(uint64_t)ident {
  ComposeAttachment* att = [self addTachment:title];
  att.ident = ident;

  [_attachments setObject:att forKey:[NSNumber numberWithUnsignedLong:ident]];
}

- (ComposeAttachment*)addTachment:(NSString*)title {
  NSImage* image = [NSImage imageNamed:NSImageNameStopProgressTemplate];
  NSButton* b = [[NSButton alloc] init];
  [b setButtonType:NSMomentaryPushInButton];
  [b setBordered:YES];
  [b setBezelStyle:NSRoundedBezelStyle];
  [b setImage:image];
  [b setImagePosition:NSImageOnly];
  [b setTranslatesAutoresizingMaskIntoConstraints:NO];
  [b setTarget:self];
  [b setAction:@selector(removeTachment:)];
  [_window_view addSubview:b];

  NSTextField* field = labelNS(title);
  [_window_view addSubview:field];

  autolayout(_window_view,
             NSDictionaryOfVariableBindings(b, field),
             "|-[b]-[field]",
             NULL);

  [_window_view addConstraint:[NSLayoutConstraint
                                  constraintWithItem:field
                                           attribute:NSLayoutAttributeCenterY
                                           relatedBy:NSLayoutRelationEqual
                                              toItem:b
                                           attribute:NSLayoutAttributeCenterY
                                          multiplier:1.0
                                            constant:0]];

  NSLayoutConstraint* cons;
  cons = [NSLayoutConstraint constraintWithItem:field
                                      attribute:NSLayoutAttributeBottom
                                      relatedBy:NSLayoutRelationLessThanOrEqual
                                         toItem:_editContainer
                                      attribute:NSLayoutAttributeTop
                                     multiplier:1.0
                                       constant:-24];
  cons.priority = NSLayoutPriorityWindowSizeStayPut - 1;
  [_window_view addConstraint:cons];

  cons = [NSLayoutConstraint constraintWithItem:_toList
                                      attribute:NSLayoutAttributeBottom
                                      relatedBy:NSLayoutRelationLessThanOrEqual
                                         toItem:field
                                      attribute:NSLayoutAttributeTop
                                     multiplier:1.0
                                       constant:-24];
  cons.priority = NSLayoutPriorityWindowSizeStayPut - 1;
  [_window_view addConstraint:cons];

  NSArray* otherAttachments = [_attachments allValues];
  for (size_t i = 0; i < [otherAttachments count]; i++) {
    ComposeAttachment* otherAttachment = [otherAttachments objectAtIndex:i];

    cons =
        [NSLayoutConstraint constraintWithItem:otherAttachment.field
                                     attribute:NSLayoutAttributeBottom
                                     relatedBy:NSLayoutRelationLessThanOrEqual
                                        toItem:field
                                     attribute:NSLayoutAttributeTop
                                    multiplier:1.0
                                      constant:-8];
    cons.priority = NSLayoutPriorityWindowSizeStayPut - 1;
    [_window_view addConstraint:cons];
  }

  ComposeAttachment* att = [[ComposeAttachment alloc] init];
  att.button = b;
  att.field = field;
  return att;
  // [_window visualizeConstraints:[_editContainer
  // constraintsAffectingLayoutForOrientation:NSLayoutConstraintOrientationVertical]];
}

static uint8_t* dupIdent(uint64_t ident) {
  uint8_t* buf = malloc(sizeof(ident));
  memcpy(buf, &ident, sizeof(ident));
  return buf;
}

- (void)removeTachment:(id)sender {
  NSInteger attachmentsCount = [_attachments count];
  NSInteger detachmentsCount = [_detachments count];
  NSInteger max = attachmentsCount;
  if (detachmentsCount > max) {
    max = detachmentsCount;
  }
  id ids[max];
  id tachments[max];

  [_attachments getObjects:tachments andKeys:ids];

  for (NSInteger i = 0; i < attachmentsCount; i++) {
    ComposeAttachment* attachment = tachments[i];
    if (attachment.button == sender) {
      [attachment.button removeFromSuperview];
      [attachment.field removeFromSuperview];
      [_attachments removeObjectForKey:ids[i]];

      sendCocoaEvent(
          REMOVE_ATTACHMENT, _id, dupIdent(attachment.ident), sizeof(uint64_t));
      return;
    }
  }

  [_detachments getObjects:tachments andKeys:ids];

  for (NSInteger i = 0; i < detachmentsCount; i++) {
    ComposeAttachment* detachment = tachments[i];
    if (detachment.button == sender) {
      [detachment.button removeFromSuperview];
      [detachment.field removeFromSuperview];
      [_detachments removeObjectForKey:ids[i]];

      sendCocoaEvent(
          REMOVE_DETACHMENT, _id, dupIdent(detachment.ident), sizeof(uint64_t));
      return;
    }
  }
}

- (void)promptDetachment:(NSString*)contents {
  NSWindow* sheet = [[NSWindow alloc] init];

  NSTextField* header = label("Attachment too large");
  [header setFont:[NSFont boldSystemFontOfSize:0]];
  [[sheet contentView] addSubview:header];

  NSTextField* msg = multiLineLabelNS(contents, 400);
  [[sheet contentView] addSubview:msg];

  NSButton* cancel = button("Cancel");
  [[sheet contentView] addSubview:cancel];
  [cancel setKeyEquivalent:@"\E"];
  [cancel setTarget:self];
  [cancel setAction:@selector(cancelDetachment)];

  NSButton* save = button("Save Encrypted");
  [[sheet contentView] addSubview:save];
  [save setTarget:self];
  [save setAction:@selector(saveEncrypted)];

  NSButton* upload = button("Upload");
  [[sheet contentView] addSubview:upload];
  [upload setTarget:self];
  [upload setAction:@selector(upload)];

  autolayout([sheet contentView],
             NSDictionaryOfVariableBindings(header, msg, cancel, save, upload),
             "|-[header]",
             "V:|-[header]",
             "|-[msg(400)]-|",
             "|-[cancel]",
             "V:[cancel]-|",
             "[save]-[upload]-|",
             "V:[save]-|",
             "V:[upload]-|",
             NULL);

  [[sheet contentView]
      addConstraint:
          [NSLayoutConstraint constraintWithItem:header
                                       attribute:NSLayoutAttributeBottom
                                       relatedBy:NSLayoutRelationEqual
                                          toItem:msg
                                       attribute:NSLayoutAttributeTop
                                      multiplier:1.0
                                        constant:-16]];

  [[sheet contentView]
      addConstraint:
          [NSLayoutConstraint constraintWithItem:msg
                                       attribute:NSLayoutAttributeBottom
                                       relatedBy:NSLayoutRelationEqual
                                          toItem:cancel
                                       attribute:NSLayoutAttributeTop
                                      multiplier:1.0
                                        constant:-16]];

  _detachmentSheet = sheet;
  [_window beginSheet:sheet completionHandler:nil];
}

- (void)cancelDetachment {
  [_window endSheet:_detachmentSheet];
  _detachmentSheet = nil;
}

- (void)saveEncrypted {
  NSSavePanel* panel = [NSSavePanel savePanel];
  [panel setTitle:@"Save encrypted file"];
  [panel setPrompt:@"Save"];
  [panel setDirectoryURL:[NSURL fileURLWithPath:NSHomeDirectory()]];

  if ([panel runModal] == NSCancelButton) {
    return;
  }

  NSURL* url = [panel URL];
  const char* path = [url fileSystemRepresentation];

  sendCocoaEvent(SAVE_ENCRYPTED, _id, (uint8_t*)strdup(path), strlen(path));
  [self detachmentSheetWithTitle:"Saving Encrypted File"];
}

- (void)upload {
  sendCocoaEvent(UPLOAD, _id, NULL, 0);
  [self detachmentSheetWithTitle:"Uploading"];
}

- (void)detachmentSheetWithTitle:(const char*)title {
  NSWindow* const sheet = _detachmentSheet;
  clearSheet(_detachmentSheet);

  NSTextField* header = label(title);
  [header setFont:[NSFont boldSystemFontOfSize:0]];
  [[sheet contentView] addSubview:header];

  NSButton* cancel = button("Abort");
  [[sheet contentView] addSubview:cancel];
  [cancel setKeyEquivalent:@"\E"];
  [cancel setTarget:self];
  [cancel setAction:@selector(cancelBackgroundOperation)];

  NSProgressIndicator* progress = [[NSProgressIndicator alloc] init];
  [progress setStyle:NSProgressIndicatorBarStyle];
  [progress setDoubleValue:0];
  [progress setMinValue:0];
  [progress setMaxValue:1];
  [progress setUsesThreadedAnimation:YES];
  [progress setIndeterminate:NO];
  [progress startAnimation:self];
  [progress setTranslatesAutoresizingMaskIntoConstraints:NO];
  [[sheet contentView] addSubview:progress];

  NSTextField* status = labelNS(@"");
  [[sheet contentView] addSubview:status];

  autolayout([sheet contentView],
             NSDictionaryOfVariableBindings(header, cancel, progress, status),
             "|-[header]",
             "V:|-[header]",
             "|-[progress(400)]-|",
             "|-[status]",
             "|-[cancel]",
             "V:[cancel]-|",
             NULL);

  [[sheet contentView]
      addConstraint:
          [NSLayoutConstraint constraintWithItem:header
                                       attribute:NSLayoutAttributeBottom
                                       relatedBy:NSLayoutRelationEqual
                                          toItem:progress
                                       attribute:NSLayoutAttributeTop
                                      multiplier:1.0
                                        constant:-16]];

  [[sheet contentView]
      addConstraint:
          [NSLayoutConstraint constraintWithItem:progress
                                       attribute:NSLayoutAttributeBottom
                                       relatedBy:NSLayoutRelationEqual
                                          toItem:status
                                       attribute:NSLayoutAttributeTop
                                      multiplier:1.0
                                        constant:-8]];

  [[sheet contentView]
      addConstraint:
          [NSLayoutConstraint constraintWithItem:status
                                       attribute:NSLayoutAttributeBottom
                                       relatedBy:NSLayoutRelationEqual
                                          toItem:cancel
                                       attribute:NSLayoutAttributeTop
                                      multiplier:1.0
                                        constant:-16]];

  _detachmentProgress = progress;
  _detachmentStatus = status;
  _detachmentError = NO;
}

- (void)cancelBackgroundOperation {
  [_window endSheet:_detachmentSheet];
  _detachmentSheet = NULL;
  sendCocoaEvent(CANCEL_DETACHMENT, _id, NULL, 0);
}

- (void)detachmentError:(NSString*)msg {
  [_detachmentStatus setStringValue:msg];
  [_detachmentProgress stopAnimation:self];
  _detachmentError = YES;
}

- (void)detachmentUpdateBytes:(uint64_t)done
                           of:(uint64_t)total
                   withStatus:(NSString*)msg {
  [_detachmentStatus setStringValue:msg];

  if (total <= 0) {
    [_detachmentProgress setIndeterminate:YES];
    return;
  }

  double f = ((double)done) / ((double)total);
  if (f < 0) {
    f = 0;
  }
  if (f > 1) {
    f = 1;
  }
  [_detachmentProgress setIndeterminate:NO];
  [_detachmentProgress setDoubleValue:f];
}

- (void)addDetachment:(NSString*)label withId:(uint64_t)ident {
  [_window endSheet:_detachmentSheet];
  _detachmentSheet = NULL;

  ComposeAttachment* att = [self addTachment:label];
  att.ident = ident;

  [_detachments setObject:att forKey:[NSNumber numberWithUnsignedLong:ident]];
}

- (NSToolbarItem*)toolbar:(NSToolbar*)toolbar
        itemForItemIdentifier:(NSString*)itemIdentifier
    willBeInsertedIntoToolbar:(BOOL)flag {
  NSImage* image;
  if ([itemIdentifier isEqualToString:@"Send"]) {
    image = [NSImage imageNamed:NSImageNameGoRightTemplate];
  } else if ([itemIdentifier isEqualToString:@"Attach"]) {
    image = [NSImage imageNamed:NSImageNameAddTemplate];
  } else {
    printf("Unknown identifier %s\n", [itemIdentifier UTF8String]);
    abort();
  }

  NSButton* b = [[NSButton alloc] init];
  [b setButtonType:NSMomentaryPushInButton];
  [b setBordered:YES];
  [b setBezelStyle:NSRoundedBezelStyle];
  [b setImage:image];
  [b setImagePosition:NSImageOnly];
  if ([itemIdentifier isEqualToString:@"Send"]) {
    // The send button is disabled until a destination is selected.
    [b setEnabled:NO];
  }

  [[b cell] setControlTint:NSGraphiteControlTint];
  NSSize s = [b intrinsicContentSize];
  s.height += 8;

  NSToolbarItem* toolbarItem =
      [[NSToolbarItem alloc] initWithItemIdentifier:itemIdentifier];
  [toolbarItem setMinSize:s];
  [toolbarItem setMaxSize:s];
  [toolbarItem setView:b];
  [toolbarItem setTarget:self];

  if ([itemIdentifier isEqualToString:@"Send"]) {
    [toolbarItem setAction:@selector(send)];
    _sendItem = toolbarItem;
  } else if ([itemIdentifier isEqualToString:@"Attach"]) {
    [toolbarItem setAction:@selector(attach)];
  } else {
    abort();
  }

  return toolbarItem;
}

- (void)send {
  uint8_t* data = NULL;
  size_t len = 0;

  NSString* toName = [_toList objectValueOfSelectedItem];
  if (toName == nil) {
    return;
  }
  putNSString(&data, &len, toName);
  putNSString(&data, &len, [_edit string]);
  sendCocoaEvent(SEND_MESSAGE, 0, data, len);
}

- (void)attach {
  NSOpenPanel* panel = [NSOpenPanel openPanel];
  [panel setAllowsMultipleSelection:NO];
  [panel setCanChooseDirectories:NO];
  [panel setCanChooseFiles:YES];
  [panel setDirectoryURL:[NSURL fileURLWithPath:NSHomeDirectory()]];

  if ([panel runModal] == NSCancelButton) {
    return;
  }

  NSURL* url = [[panel URLs] objectAtIndex:0];
  const char* path = [url fileSystemRepresentation];

  sendCocoaEvent(ATTACH, _id, (uint8_t*)strdup(path), strlen(path));
}

- (void)comboBoxSelectionDidChange:(NSNotification*)notification {
  // The user selected a destination contact.
  _destinationSelected = YES;
  [self updateSendButton];
}

- (void)error:(NSString*)msg {
  NSAlert* alert = [[NSAlert alloc] init];
  [alert setMessageText:msg];
  [alert beginSheetModalForWindow:_window
                completionHandler:^(NSModalResponse r) {}];
}

@end

@interface PondGUI : NSObject<NSApplicationDelegate, NSTableViewDelegate> {
 @private
  PondOutline* _pondOutline;
  NSOutlineView* _outline;
  NSTableColumn* _titleColumn;
  NSSplitView* _vsplit;
  NSSplitView* _hsplit;
  ContentView* _content;
  NSTableView* _table;
  NSWindow* _window;
  NSWindow* _torSheet;
  NSWindow* _createAccountSheet;
  NSWindow* _passphraseSheet;
  NSTextField* _passphraseEntry;
  NSProgressIndicator* _spinner;
  NSTextField* _msg;
  NSButton* _button;
  TableSource* _tableSource;
  NSImage* _newContactImage;
  NSImage* _composeImage;
  NSTableColumn* _nameCol;
  NSTableColumn* _extraCol;
  NSTableColumn* _contentsCol;

  NSWindow* _newContactSheet;
  NSTextField* _secretEntry;
  NSTextField* _localNameEntry;
  NSButton* _add, *_cancel, *_random;
  CGFloat _oldSplitPosition;

  NSMutableDictionary* _composes;
}

- (PondGUI*)init;
@end

@implementation PondGUI

- (void)applicationDidFinishLaunching:(NSNotification*)aNotification {
  [_vsplit setPosition:100 ofDividerAtIndex:0];
  [_hsplit setPosition:250 ofDividerAtIndex:0];

  // Select the Inbox by default.
  NSInteger inboxRowIndex = [_outline rowForItem:[_pondOutline inboxItem]];
  [_outline selectRowIndexes:[[NSIndexSet alloc] initWithIndex:inboxRowIndex]
        byExtendingSelection:NO];
}

- (PondGUI*)init {
  [NSAutoreleasePool new];
  [NSApplication sharedApplication];
  [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
  [NSApp setDelegate:self];

  NSData* newContactImageData =
      [[NSData alloc] initWithBytes:newContactPDF length:sizeof(newContactPDF)];
  _newContactImage = [[NSImage alloc] initWithData:newContactImageData];
  NSSize newContactSize = {24, 12};
  [_newContactImage setSize:newContactSize];

  NSData* composeImageData =
      [[NSData alloc] initWithBytes:composePDF length:sizeof(composePDF)];
  _composeImage = [[NSImage alloc] initWithData:composeImageData];
  NSSize composeSize = {34, 12};
  [_composeImage setSize:composeSize];

  id menubar = [[NSMenu new] autorelease];
  id appMenuItem = [[NSMenuItem new] autorelease];
  [menubar addItem:appMenuItem];
  [NSApp setMainMenu:menubar];

  id appMenu = [[NSMenu new] autorelease];
  id appName = [[NSProcessInfo processInfo] processName];
  id quitTitle = [@"Quit " stringByAppendingString:appName];
  id quitMenuItem = [[[NSMenuItem alloc] initWithTitle:quitTitle
                                                action:@selector(terminate:)
                                         keyEquivalent:@"q"] autorelease];
  [appMenu addItem:quitMenuItem];
  [appMenuItem setSubmenu:appMenu];

  _window = [[[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 900, 500)
                                         styleMask:NSTitledWindowMask |
                                                   NSResizableWindowMask |
                                                   NSClosableWindowMask
                                           backing:NSBackingStoreBuffered
                                             defer:NO] autorelease];
  [_window cascadeTopLeftFromPoint:NSMakePoint(20, 20)];
  [_window setTitle:appName];

  id toolbar = [[NSToolbar alloc] initWithIdentifier:@"Main"];
  [toolbar setDelegate:self];
  //[toolbar setSizeMode:NSToolbarSizeModeSmall];
  [toolbar setDisplayMode:NSToolbarDisplayModeIconOnly];
  [_window setToolbar:toolbar];

  [[NSUserDefaults standardUserDefaults]
      setBool:YES
       forKey:@"NSConstraintBasedLayoutVisualizeMutuallyExclusiveConstraints"];

  NSView* window_view = [_window contentView];

  _vsplit = [[NSSplitView alloc] init];
  [_vsplit setVertical:YES];
  [_vsplit setTranslatesAutoresizingMaskIntoConstraints:NO];
  [_vsplit setDividerStyle:NSSplitViewDividerStyleThin];
  [window_view addSubview:_vsplit];
  [window_view
      addConstraints:
          [NSLayoutConstraint
              constraintsWithVisualFormat:@"|[_vsplit(>=200)]|"
                                  options:0
                                  metrics:nil
                                    views:NSDictionaryOfVariableBindings(
                                              _vsplit)]];
  [window_view
      addConstraints:
          [NSLayoutConstraint
              constraintsWithVisualFormat:@"V:|[_vsplit(>=200)]|"
                                  options:0
                                  metrics:nil
                                    views:NSDictionaryOfVariableBindings(
                                              _vsplit)]];

  [_vsplit setDelegate:[[SplitDelegate alloc] init]];

  NSScrollView* outlineContainer = [[NSScrollView alloc] init];
  NSOutlineView* outline = [[NSOutlineView alloc] init];
  _pondOutline = [[PondOutline alloc] init];
  [_pondOutline setGUI:self];
  [outline setDataSource:_pondOutline];
  [outline setDelegate:_pondOutline];
  [outline setTranslatesAutoresizingMaskIntoConstraints:NO];
  _titleColumn = [[NSTableColumn alloc] initWithIdentifier:@"title"];
  [outline sizeLastColumnToFit];
  [outline addTableColumn:_titleColumn];
  [outline setHeaderView:nil];
  [outline setOutlineTableColumn:_titleColumn];
  [outlineContainer setDocumentView:outline];
  [_vsplit addSubview:outlineContainer];
  _outline = outline;

  NSScrollView* tableContainer = [[NSScrollView alloc] init];
  _table = [[NSTableView alloc] init];
  _tableSource = [[TableSource alloc] init];
  [_table setDataSource:_tableSource];
  [_table setDelegate:self];

  NSData* imageData =
      [[NSData alloc] initWithBytes:bluePNG length:sizeof(bluePNG)];
  NSImage* headerImage = [[NSImage alloc] initWithData:imageData];
  NSTextAttachment* ta = [[NSTextAttachment alloc] init];
  [(NSCell*)[ta attachmentCell] setImage:headerImage];
  NSAttributedString* headerAS =
      [NSAttributedString attributedStringWithAttachment:ta];
  NSTableColumn* indicatorCol =
      [[NSTableColumn alloc] initWithIdentifier:@"indicator"];
  [indicatorCol.headerCell setAttributedStringValue:headerAS];
  [indicatorCol setWidth:8];
  [_table addTableColumn:indicatorCol];

  _nameCol = [[NSTableColumn alloc] initWithIdentifier:@"name"];
  [_nameCol.headerCell setStringValue:@"From"];
  [_table addTableColumn:_nameCol];

  _extraCol = [[NSTableColumn alloc] initWithIdentifier:@"extra"];
  [_extraCol.headerCell setStringValue:@"Received"];
  [_table addTableColumn:_extraCol];

  _contentsCol = [[NSTableColumn alloc] initWithIdentifier:@"contents"];
  [_extraCol.headerCell setStringValue:@""];
  [_table addTableColumn:_contentsCol];

  [_table sizeLastColumnToFit];
  [_table setFocusRingType:NSFocusRingTypeNone];
  [tableContainer setDocumentView:_table];
  [tableContainer setHasVerticalScroller:YES];

  _content = [[ContentView alloc] init];
  [_content setTranslatesAutoresizingMaskIntoConstraints:NO];
  //[_content setAutoresizingMask:NSViewWidthSizable|NSViewHeightSizable];

  [_content addHeader:@"TEST" withValue:@"v1"];

  _hsplit = [[NSSplitView alloc] init];
  [_hsplit setVertical:NO];
  //[_hsplit setDelegate:[[SplitDelegate alloc] init]];
  [_hsplit setTranslatesAutoresizingMaskIntoConstraints:NO];
  [_hsplit addSubview:tableContainer];
  NSScrollView* contentContainer = [[NSScrollView alloc] init];
  [contentContainer setDocumentView:_content];
  [contentContainer setHasVerticalScroller:YES];
  [contentContainer setTranslatesAutoresizingMaskIntoConstraints:NO];
  [_hsplit addSubview:contentContainer];
  _oldSplitPosition = 0;

  autolayout(contentContainer,
             NSDictionaryOfVariableBindings(_content),
             "|[_content]|",
             "V:|[_content]",
             NULL);

  [_vsplit addSubview:_hsplit];

  [outline reloadData];

  [NSAnimationContext beginGrouping];
  [[NSAnimationContext currentContext] setDuration:0];
  [outline expandItem:nil expandChildren:YES];
  [NSAnimationContext endGrouping];
  [outline setFloatsGroupRows:NO];
  [outline
      setSelectionHighlightStyle:NSTableViewSelectionHighlightStyleSourceList];

  _composes = [[NSMutableDictionary alloc] init];

  [_window makeKeyAndOrderFront:nil];
  [NSApp activateIgnoringOtherApps:YES];

  return self;
}

- (NSArray*)toolbarAllowedItemIdentifiers:(NSToolbar*)toolbar {
  return @[ @"New contact", @"Compose" ];
}

- (NSArray*)toolbarDefaultItemIdentifiers:(NSToolbar*)toolbar {
  return [self toolbarAllowedItemIdentifiers:toolbar];
}

- (NSToolbarItem*)toolbar:(NSToolbar*)toolbar
        itemForItemIdentifier:(NSString*)itemIdentifier
    willBeInsertedIntoToolbar:(BOOL)flag {
  NSToolbarItem* toolbarItem =
      [[[NSToolbarItem alloc]
           initWithItemIdentifier:itemIdentifier] autorelease];

  NSImage* image = NULL;
  if ([itemIdentifier isEqualToString:@"New contact"]) {
    image = _newContactImage;
  } else {
    image = _composeImage;
  }

  NSButton* b = [[NSButton alloc] init];
  [b setButtonType:NSMomentaryPushInButton];
  [b setBordered:YES];
  [b setBezelStyle:NSRoundedBezelStyle];
  [b setImage:image];
  [b setImagePosition:NSImageOnly];
  [b setEnabled:YES];
  [[b cell] setControlTint:NSGraphiteControlTint];
  NSSize s = [b intrinsicContentSize];
  s.height += 8;
  [toolbarItem setMinSize:s];
  [toolbarItem setMaxSize:s];
  [toolbarItem setView:b];
  [toolbarItem setTarget:self];

  if ([itemIdentifier isEqualToString:@"New contact"]) {
    [toolbarItem setAction:@selector(newContact)];
  } else {
    [toolbarItem setAction:@selector(compose)];
  }

  return toolbarItem;
}

- (void)newContact {
  NSWindow* sheet = [[NSWindow alloc] init];

  NSTextField* header = label("New contact");
  [header setFont:[NSFont boldSystemFontOfSize:0]];
  [[sheet contentView] addSubview:header];

  NSTextField* localName = label("Local name");
  [[sheet contentView] addSubview:localName];

  NSTextField* secret = label("Shared secret");
  [[sheet contentView] addSubview:secret];

  NSTextField* msg = label("");
  [[sheet contentView] addSubview:msg];

  NSButton* cancel = button("Cancel");
  [[sheet contentView] addSubview:cancel];
  [cancel setKeyEquivalent:@"\E"];
  [cancel setTarget:self];
  [cancel setAction:@selector(cancelNewContact)];

  NSButton* add = button("Add");
  [[sheet contentView] addSubview:add];
  [add setKeyEquivalent:@"\r"];
  [add setTarget:self];
  [add setAction:@selector(addNewContact)];

  NSButton* random = button("Generate");
  [[sheet contentView] addSubview:random];
  [random setTarget:self];
  [random setAction:@selector(randomSecret)];

  NSTextField* localNameEntry = [[NSTextField alloc] init];
  [localNameEntry setTranslatesAutoresizingMaskIntoConstraints:NO];
  [[localNameEntry cell] setPlaceholderString:@"John Smith"];
  [[sheet contentView] addSubview:localNameEntry];

  NSTextField* secretEntry = [[NSTextField alloc] init];
  [secretEntry setTranslatesAutoresizingMaskIntoConstraints:NO];
  [[sheet contentView] addSubview:secretEntry];

  autolayout([sheet contentView],
             NSDictionaryOfVariableBindings(header,
                                            localName,
                                            secret,
                                            msg,
                                            cancel,
                                            add,
                                            random,
                                            localNameEntry,
                                            secretEntry),
             "|-[header]",
             "V:|-[header]",
             "|-[localName]",
             "[localNameEntry(>=200)]-|",
             "|-[secret]-[secretEntry(>=250)]-|",
             "|-[msg]",
             "[random]-|",
             "|-[cancel]",
             "V:[cancel]-|",
             "[add]-|",
             "V:[add]-|",
             NULL);

  [[sheet contentView]
      addConstraint:
          [NSLayoutConstraint constraintWithItem:header
                                       attribute:NSLayoutAttributeBottom
                                       relatedBy:NSLayoutRelationEqual
                                          toItem:localName
                                       attribute:NSLayoutAttributeTop
                                      multiplier:1.0
                                        constant:-16]];

  [[sheet contentView]
      addConstraint:
          [NSLayoutConstraint constraintWithItem:localNameEntry
                                       attribute:NSLayoutAttributeBottom
                                       relatedBy:NSLayoutRelationEqual
                                          toItem:secretEntry
                                       attribute:NSLayoutAttributeTop
                                      multiplier:1.0
                                        constant:-8]];

  [[sheet contentView]
      addConstraint:
          [NSLayoutConstraint constraintWithItem:secretEntry
                                       attribute:NSLayoutAttributeBottom
                                       relatedBy:NSLayoutRelationEqual
                                          toItem:random
                                       attribute:NSLayoutAttributeTop
                                      multiplier:1.0
                                        constant:-8]];

  [[sheet contentView]
      addConstraint:
          [NSLayoutConstraint constraintWithItem:random
                                       attribute:NSLayoutAttributeBottom
                                       relatedBy:NSLayoutRelationEqual
                                          toItem:add
                                       attribute:NSLayoutAttributeTop
                                      multiplier:1.0
                                        constant:-24]];

  [[sheet contentView]
      addConstraint:
          [NSLayoutConstraint constraintWithItem:msg
                                       attribute:NSLayoutAttributeBaseline
                                       relatedBy:NSLayoutRelationEqual
                                          toItem:random
                                       attribute:NSLayoutAttributeBaseline
                                      multiplier:1.0
                                        constant:0]];

  [[sheet contentView]
      addConstraint:
          [NSLayoutConstraint constraintWithItem:localName
                                       attribute:NSLayoutAttributeBaseline
                                       relatedBy:NSLayoutRelationEqual
                                          toItem:localNameEntry
                                       attribute:NSLayoutAttributeBaseline
                                      multiplier:1.0
                                        constant:0]];

  [[sheet contentView]
      addConstraint:
          [NSLayoutConstraint constraintWithItem:secret
                                       attribute:NSLayoutAttributeBaseline
                                       relatedBy:NSLayoutRelationEqual
                                          toItem:secretEntry
                                       attribute:NSLayoutAttributeBaseline
                                      multiplier:1.0
                                        constant:0]];

  [[sheet contentView]
      addConstraint:[NSLayoutConstraint constraintWithItem:localNameEntry
                                                 attribute:NSLayoutAttributeLeft
                                                 relatedBy:NSLayoutRelationEqual
                                                    toItem:secretEntry
                                                 attribute:NSLayoutAttributeLeft
                                                multiplier:1.0
                                                  constant:0]];

  _newContactSheet = sheet;
  _localNameEntry = localNameEntry;
  _secretEntry = secretEntry;
  _msg = msg;
  _add = add;
  _cancel = cancel;
  _random = random;
  [_window beginSheet:sheet completionHandler:nil];
}

- (void)cancelNewContact {
  [_window endSheet:_newContactSheet];
  _newContactSheet = NULL;
}

- (void)addNewContact {
  NSString* localName = [_localNameEntry stringValue];
  if ([localName length] == 0) {
    shakeWindow(_newContactSheet);
    [_msg setStringValue:@"Name cannot be empty!"];
    return;
  }

  NSString* secret = [_secretEntry stringValue];
  if ([secret length] == 0) {
    shakeWindow(_newContactSheet);
    [_msg setStringValue:@"Secret cannot be empty!"];
    return;
  }

  [_localNameEntry setEnabled:NO];
  [_secretEntry setEnabled:NO];
  [_cancel setEnabled:NO];
  [_add setEnabled:NO];
  [_random setEnabled:NO];

  uint8_t* data = NULL;
  size_t len = 0;

  putNSString(&data, &len, localName);
  putNSString(&data, &len, secret);
  sendCocoaEvent(NEW_CONTACT, 0, data, len);
}

- (void)newContactRejected:(const char*)reasonStr {
  [_localNameEntry setEnabled:YES];
  [_secretEntry setEnabled:YES];
  [_cancel setEnabled:YES];
  [_add setEnabled:YES];
  [_random setEnabled:YES];

  shakeWindow(_newContactSheet);
  [_msg setStringValue:[[NSString alloc] initWithUTF8String:reasonStr]];
}

- (void)newContactAccepted {
  [_window endSheet:_newContactSheet];
  _newContactSheet = NULL;
}

extern char* randomHexSecret();

- (void)randomSecret {
  char* randHex = randomHexSecret();
  [_secretEntry setStringValue:[[NSString alloc] initWithUTF8String:randHex]];
  [_msg setStringValue:@"Make a note of it before clicking Add!"];
  free(randHex);
}

- (void)compose {
  sendCocoaEvent(COMPOSE, 0, NULL, 0);
}

- (void)setIndicatorImages:(const uint8_t*)data withLength:(size_t)len {
  [_tableSource setIndicatorImages:data withLength:len];
}

- (void)showTorWarning {
  NSWindow* sheet = [[NSWindow alloc] init];

  NSTextField* header = label("Tor not running");
  [header setFont:[NSFont boldSystemFontOfSize:0]];
  [[sheet contentView] addSubview:header];

  NSTextField* body = label(
      "Please start Tor or the Tor Browser Bundle.\nLooking for a SOCKS proxy "
      "on port 9050 or 9150...");
  [[sheet contentView] addSubview:body];

  [[sheet contentView]
      addConstraints:
          [NSLayoutConstraint
              constraintsWithVisualFormat:@"|-[header]"
                                  options:0
                                  metrics:nil
                                    views:NSDictionaryOfVariableBindings(
                                              header)]];
  [[sheet contentView]
      addConstraints:
          [NSLayoutConstraint
              constraintsWithVisualFormat:@"|-[body]-|"
                                  options:0
                                  metrics:nil
                                    views:NSDictionaryOfVariableBindings(
                                              body)]];
  [[sheet contentView]
      addConstraints:
          [NSLayoutConstraint
              constraintsWithVisualFormat:@"V:|-[header]-[body]"
                                  options:0
                                  metrics:nil
                                    views:NSDictionaryOfVariableBindings(
                                              header, body)]];

  _torSheet = sheet;
  [_window beginSheet:sheet completionHandler:nil];
}

- (void)destroyTorWarning {
  [_window endSheet:_torSheet];
  _torSheet = NULL;
}

- (void)showCreatePassphrase {
  NSWindow* sheet = [[NSWindow alloc] init];

  NSTextField* header = label("Create passphrase");
  [header setFont:[NSFont boldSystemFontOfSize:0]];
  [[sheet contentView] addSubview:header];

  NSTextField* body = label(
      "Pond keeps private keys, messages etc on disk for a limited amount of "
      "time and that information can be encrypted with a passphrase. If you "
      "are comfortable with the security of your home directory, this "
      "passphrase can be empty and you won't be prompted for it again. If you "
      "set a passphrase and forget it, it cannot be recovered. You will have "
      "to start afresh.");
  [body setPreferredMaxLayoutWidth:400];
  [[sheet contentView] addSubview:body];

  NSTextField* entry = [[NSTextField alloc] init];
  [entry setTranslatesAutoresizingMaskIntoConstraints:NO];
  [entry setTarget:self];
  [entry setAction:@selector(passphraseEntered)];
  [[sheet contentView] addSubview:entry];

  NSButton* next = button("Next");
  [next setKeyEquivalent:@"\r"];
  [next setTarget:self];
  [next setAction:@selector(passphraseEntered)];
  [[sheet contentView] addSubview:next];

  autolayout([sheet contentView],
             NSDictionaryOfVariableBindings(header, body, entry, next),
             "|-[header]",
             "|-[body]-|",
             "|-[entry]-|",
             "V:|-[header]-[body]-16-[entry]-16-[next]-|",
             "[next]-|",
             NULL);

  _passphraseSheet = sheet;
  _passphraseEntry = entry;
  _button = next;
  [_window beginSheet:sheet completionHandler:nil];
}

- (void)passphraseEntered {
  [_button setEnabled:NO];
  [_passphraseEntry setEnabled:NO];

  uint8_t* data = NULL;
  size_t len = 0;
  putNSString(&data, &len, [_passphraseEntry stringValue]);
  sendCocoaEvent(PASSPHRASE_ENTERED, 0, data, len);
}

- (void)showCreateAccount:(const char*)defaultAccount {
  // This this point, the create passphrase sheet is still active.
  NSWindow* sheet = _passphraseSheet;
  clearSheet(sheet);

  NSTextField* header = label("Create account");
  [header setFont:[NSFont boldSystemFontOfSize:0]];
  [[sheet contentView] addSubview:header];

  NSTextField* body = label(
      "In order to use Pond you have to have an account on a server. Servers "
      "may set their own account policies, but the default server allows "
      "anyone to create an account. If you want to use the default server, "
      "just click 'Create'.");
  [body setPreferredMaxLayoutWidth:400];
  [[sheet contentView] addSubview:body];

  NSTextField* entry = [[NSTextField alloc] init];
  [[entry cell] setUsesSingleLineMode:YES];
  [[entry cell] setLineBreakMode:NSLineBreakByTruncatingTail];
  [entry setTranslatesAutoresizingMaskIntoConstraints:NO];
  [entry setStringValue:[[NSString alloc] initWithUTF8String:defaultAccount]];
  //[entry setTarget: self];
  //[entry setAction: @selector(createAccount)];
  [[sheet contentView] addSubview:entry];

  NSButton* create = button("Create");
  [create setKeyEquivalent:@"\r"];
  [create setTarget:self];
  [create setAction:@selector(createAccount)];
  [[sheet contentView] addSubview:create];

  NSProgressIndicator* progress = [[NSProgressIndicator alloc] init];
  [progress setTranslatesAutoresizingMaskIntoConstraints:NO];
  [progress setStyle:NSProgressIndicatorSpinningStyle];
  [progress setControlSize:NSSmallControlSize];
  [progress setHidden:YES];
  [[sheet contentView] addSubview:progress];
  _spinner = progress;

  NSTextField* msg = label(NULL);
  [[sheet contentView] addSubview:msg];
  _msg = msg;

  autolayout([sheet contentView],
             NSDictionaryOfVariableBindings(
                 header, body, entry, progress, msg, create),
             "|-[header]",
             "|-[body]-|",
             "|-[entry]-|",
             "V:|-[header]-[body]-16-[entry]",
             "[create]-|",
             "V:[create]-|",
             NULL);

  [[sheet contentView]
      addConstraint:
          [NSLayoutConstraint constraintWithItem:entry
                                       attribute:NSLayoutAttributeBottom
                                       relatedBy:NSLayoutRelationLessThanOrEqual
                                          toItem:progress
                                       attribute:NSLayoutAttributeTop
                                      multiplier:1.0
                                        constant:-16]];

  [[sheet contentView]
      addConstraint:
          [NSLayoutConstraint constraintWithItem:progress
                                       attribute:NSLayoutAttributeBottom
                                       relatedBy:NSLayoutRelationLessThanOrEqual
                                          toItem:create
                                       attribute:NSLayoutAttributeTop
                                      multiplier:1.0
                                        constant:-8]];

  [[sheet contentView]
      addConstraint:[NSLayoutConstraint constraintWithItem:progress
                                                 attribute:NSLayoutAttributeTop
                                                 relatedBy:NSLayoutRelationEqual
                                                    toItem:msg
                                                 attribute:NSLayoutAttributeTop
                                                multiplier:1.0
                                                  constant:0]];

  [[sheet contentView]
      addConstraint:
          [NSLayoutConstraint constraintWithItem:progress
                                       attribute:NSLayoutAttributeLeft
                                       relatedBy:NSLayoutRelationLessThanOrEqual
                                          toItem:progress.superview
                                       attribute:NSLayoutAttributeLeft
                                      multiplier:1.0
                                        constant:16]];

  [[sheet contentView]
      addConstraint:
          [NSLayoutConstraint constraintWithItem:msg
                                       attribute:NSLayoutAttributeLeft
                                       relatedBy:NSLayoutRelationLessThanOrEqual
                                          toItem:progress
                                       attribute:NSLayoutAttributeRight
                                      multiplier:1.0
                                        constant:8]];

  _passphraseEntry = entry;
  _button = create;
  _createAccountSheet = sheet;
}

- (void)createAccount {
  [_button setEnabled:NO];
  [_passphraseEntry setEnabled:NO];
  [_spinner setHidden:NO];
  [_spinner startAnimation:self];
  [_msg setStringValue:@"Checking..."];

  uint8_t* data = NULL;
  size_t len = 0;
  putNSString(&data, &len, [_passphraseEntry stringValue]);
  sendCocoaEvent(CREATE_ACCOUNT_ENTERED, 0, data, len);
}

- (void)updateCreateAccount:(const char*)status treatAsError:(BOOL)isError {
  [_msg setStringValue:[[NSString alloc] initWithUTF8String:status]];

  if (isError) {
    // Account creation failed.
    [_button setEnabled:YES];
    [_passphraseEntry setEnabled:YES];
    [_spinner stopAnimation:self];
    [_spinner setHidden:YES];
  }
}

- (void)destroyCreateAccount {
  [_window endSheet:_createAccountSheet];
  _createAccountSheet = NULL;
}

- (void)setTableContents:(const uint8_t*)contents withLength:(size_t)len {
  uint8_t superfluous = getU8(&contents, &len);

  char* buf = NULL;
  size_t bufLength = 0;
  [[_nameCol headerCell]
      setStringValue:getString(&contents, &len, &buf, &bufLength)];
  [[_extraCol headerCell]
      setStringValue:getString(&contents, &len, &buf, &bufLength)];

  if (buf) {
    free(buf);
  }

  [_tableSource setContents:contents withLength:len];
  [_table reloadData];

  if (superfluous) {
    _oldSplitPosition = [[[_hsplit subviews] objectAtIndex:0] frame]
                            .size.height;
    [_hsplit setPosition:35 ofDividerAtIndex:0];
  } else if (_oldSplitPosition != 0) {
    [_hsplit setPosition:_oldSplitPosition ofDividerAtIndex:0];
    _oldSplitPosition = 0;
  }
}

- (void)setContents:(const uint8_t*)contents withLength:(size_t)len {
  [_content setContents:contents withLength:len];
}

- (void)outlineSelectionChanged {
  NSInteger row = [_outline selectedRow];
  NSString* label = [_pondOutline labelForRow:row];
  if (label == nil) {
    return;
  }

  uint8_t* data = NULL;
  size_t len = 0;
  putNSString(&data, &len, [_pondOutline labelForRow:row]);
  sendCocoaEvent(OUTLINE_CLICKED, 0, data, len);
}

- (void)tableViewSelectionDidChange:(NSNotification*)notification {
  NSInteger row = [_table selectedRow];
  uint64_t objId = [_tableSource idForRow:row];

  sendCocoaEvent(TABLE_CLICKED, objId, NULL, 0);
}

- (void)openCompose:(const uint8_t*)data withLength:(size_t)len {
  Compose* compose = [[Compose alloc] init];

  const uint64_t ident = getU64(&data, &len);
  [compose setId:ident];
  [_composes setObject:compose forKey:[NSNumber numberWithUnsignedLong:ident]];
  const size_t numHeaders = getU32(&data, &len);

  char* buf = NULL;
  size_t bufLength = 0;
  for (size_t i = 0; i < numHeaders; i++) {
    [compose addContactName:getString(&data, &len, &buf, &bufLength)];
  }
  if (buf) {
    free(buf);
  }
}

- (void)composeError:(const uint8_t*)data
          withLength:(size_t)len
               ident:(uint64_t)ident {
  Compose* compose =
      [_composes objectForKey:[NSNumber numberWithUnsignedLong:ident]];
  [compose error:getString(&data, &len, NULL, NULL)];
}

- (void)addAttachment:(const uint8_t*)data
           withLength:(size_t)len
                ident:(uint64_t)composeIdent {
  Compose* compose =
      [_composes objectForKey:[NSNumber numberWithUnsignedLong:composeIdent]];
  NSString* label = getString(&data, &len, NULL, NULL);
  uint64_t ident = getU64(&data, &len);
  [compose addAttachment:label withId:ident];
}

- (void)promptDetachment:(const uint8_t*)data
              withLength:(size_t)len
                   ident:(uint64_t)composeIdent {
  Compose* compose =
      [_composes objectForKey:[NSNumber numberWithUnsignedLong:composeIdent]];
  NSString* msg = getString(&data, &len, NULL, NULL);
  [compose promptDetachment:msg];
}

- (void)detachmentError:(const uint8_t*)data
             withLength:(size_t)len
                  ident:(uint64_t)composeIdent {
  Compose* compose =
      [_composes objectForKey:[NSNumber numberWithUnsignedLong:composeIdent]];
  NSString* msg = getString(&data, &len, NULL, NULL);
  [compose detachmentError:msg];
}

- (void)detachmentUpdate:(const uint8_t*)data
              withLength:(size_t)len
                   ident:(uint64_t)composeIdent {
  Compose* compose =
      [_composes objectForKey:[NSNumber numberWithUnsignedLong:composeIdent]];
  const uint64_t done = getU64(&data, &len);
  const uint64_t total = getU64(&data, &len);
  NSString* msg = getString(&data, &len, NULL, NULL);
  [compose detachmentUpdateBytes:done of:total withStatus:msg];
}

- (void)addDetachment:(const uint8_t*)data
           withLength:(size_t)len
                ident:(uint64_t)composeIdent {
  Compose* compose =
      [_composes objectForKey:[NSNumber numberWithUnsignedLong:composeIdent]];
  NSString* label = getString(&data, &len, NULL, NULL);
  uint64_t ident = getU64(&data, &len);
  [compose addDetachment:label withId:ident];
}

- (void)updateComposeUsage:(const uint8_t*)data
                withLength:(size_t)len
                     ident:(uint64_t)composeIdent {
  Compose* compose =
      [_composes objectForKey:[NSNumber numberWithUnsignedLong:composeIdent]];
  NSString* msg = getString(&data, &len, NULL, NULL);
  uint32_t overSizeFlag = getU32(&data, &len);
  [compose updateUsage:msg isOversize:(overSizeFlag > 0 ? YES : NO)];
}

@end

extern unsigned incomingSignalCallback(uint64_t* i, char** s, size_t* len);

struct incomingSignalCtx {
  PondGUI* gui;
};

void incomingSignalCallbackC(CFSocketRef sock,
                             CFSocketCallBackType event,
                             CFDataRef addr,
                             const void* data,
                             void* info) {
  struct incomingSignalCtx* ctx = (struct incomingSignalCtx*)info;

  uint64_t i;
  size_t len;
  char* s;
  unsigned command = incomingSignalCallback(&i, &s, &len);

  switch (command) {
    case SET_INDICATOR_IMAGES:
      [ctx->gui setIndicatorImages:(uint8_t*)s withLength:len];
      break;
    case SHOW_TOR_PROMPT:
      [ctx->gui showTorWarning];
      break;
    case DESTROY_TOR_PROMPT:
      [ctx->gui destroyTorWarning];
      break;
    case SHOW_CREATE_PASSPHRASE:
      [ctx->gui showCreatePassphrase];
      break;
    case SHOW_CREATE_ACCOUNT:
      [ctx->gui showCreateAccount:s];
      break;
    case UPDATE_CREATE_ACCOUNT:
      [ctx->gui updateCreateAccount:s treatAsError:i == 1];
      break;
    case DESTROY_CREATE_ACCOUNT:
      [ctx->gui destroyCreateAccount];
      break;
    case SET_TABLE_CONTENTS:
      [ctx->gui setTableContents:(uint8_t*)s withLength:len];
      break;
    case NEW_CONTACT_ACCEPTED:
      [ctx->gui newContactAccepted];
      break;
    case NEW_CONTACT_REJECTED:
      [ctx->gui newContactRejected:s];
      break;
    case SET_CONTENTS:
      [ctx->gui setContents:(uint8_t*)s withLength:len];
      break;
    case OPEN_COMPOSE:
      [ctx->gui openCompose:(uint8_t*)s withLength:len];
      break;
    case COMPOSE_ERROR:
      [ctx->gui composeError:(uint8_t*)s withLength:len ident:i];
      break;
    case ADD_ATTACHMENT:
      [ctx->gui addAttachment:(uint8_t*)s withLength:len ident:i];
      break;
    case PROMPT_DETACHMENT:
      [ctx->gui promptDetachment:(uint8_t*)s withLength:len ident:i];
      break;
    case DETACHMENT_ERROR:
      [ctx->gui detachmentError:(uint8_t*)s withLength:len ident:i];
      break;
    case DETACHMENT_UPDATE:
      [ctx->gui detachmentUpdate:(uint8_t*)s withLength:len ident:i];
      break;
    case ADD_DETACHMENT:
      [ctx->gui addDetachment:(uint8_t*)s withLength:len ident:i];
      break;
    case UPDATE_USAGE:
      [ctx->gui updateComposeUsage:(uint8_t*)s withLength:len ident:i];
      break;
    default:
      printf("UNHANDLED COMMAND\n");
      abort();
  }

  if (s)
    free(s);
}

void RunGUI(int incomingSignalFD) {
  PondGUI* gui = [[PondGUI alloc] init];

  struct incomingSignalCtx ctx;
  ctx.gui = gui;

  CFSocketContext incomingSockCtx;
  memset(&incomingSockCtx, 0, sizeof(incomingSockCtx));
  incomingSockCtx.info = &ctx;
  CFSocketRef incomingSock = CFSocketCreateWithNative(NULL,
                                                      incomingSignalFD,
                                                      kCFSocketReadCallBack,
                                                      incomingSignalCallbackC,
                                                      &incomingSockCtx);
  CFRunLoopSourceRef incomingSource =
      CFSocketCreateRunLoopSource(NULL, incomingSock, 0);
  CFRunLoopAddSource([[NSRunLoop currentRunLoop] getCFRunLoop],
                     incomingSource,
                     kCFRunLoopCommonModes);

  [NSApp run];
}
