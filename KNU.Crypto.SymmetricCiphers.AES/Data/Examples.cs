﻿namespace KNU.Crypto.SymmetricCiphers.AES.Data
{
    public static class Examples
    {
        public static byte[] AppendixA1_CipherKey => new byte[]
        {
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
        };

        public static byte[] AppendixB_CipherKey => new byte[]
        {
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
        };

        public static byte[] AppendixB_PlainText => new byte[]
        {
            0x32, 0x43, 0xf6, 0xa8,
            0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2,
            0xe0, 0x37, 0x07, 0x34
        };

        public static byte[] AppendixB_EncodedText => new byte[]
        {
            0x39, 0x25, 0x84, 0x1d,
            0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97,
            0x19, 0x6a, 0x0b, 0x32
        };

        public static byte[] AppendixC1_CipherKey => new byte[]
        {
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f
        };

        public static byte[] AppendixC1_EncodedText => new byte[]
        {
            0x69, 0xc4, 0xe0, 0xd8,
            0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80,
            0x70, 0xb4, 0xc5, 0x5a
        };

        public static byte[] AppendixC1_PlainText => new byte[]
        {
            0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff
        };

        public static byte[] AppendixC2_CipherKey => new byte[]
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 
            0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 
            0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17
        };

        public static byte[] AppendixC2_PlainText => new byte[]
        {
            0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff
        };

        public static byte[] AppendixC2_EncodedText => new byte[]
        {
            0xdd, 0xa9, 0x7c, 0xa4,
            0x86, 0x4c, 0xdf, 0xe0,
            0x6e, 0xaf, 0x70, 0xa0,
            0xec, 0x0d, 0x71, 0x91
        };

        public static byte[] AppendixC3_CipherKey => new byte[]
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };

        public static byte[] AppendixC3_PlainText => new byte[]
        {
            0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff
        };

        public static byte[] AppendixC3_EncodedText => new byte[]
        {
            0x8e, 0xa2, 0xb7, 0xca, 
            0x51, 0x67, 0x45, 0xbf, 
            0xea, 0xfc, 0x49, 0x90, 
            0x4b, 0x49, 0x60, 0x89
        };
    }
}
