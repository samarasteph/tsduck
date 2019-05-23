//----------------------------------------------------------------------------
//
// TSDuck - The MPEG Transport Stream Toolkit
// Copyright (c) 2005-2019, Thierry Lelegard
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//
//----------------------------------------------------------------------------
//
//  TSUnit test suite for ts::ByteBlock
//
//----------------------------------------------------------------------------

#include "tsByteBlock.h"
#include "tsSysUtils.h"
#include "tsunit.h"
TSDUCK_SOURCE;


//----------------------------------------------------------------------------
// The test fixture
//----------------------------------------------------------------------------

class ByteBlockTest: public tsunit::Test
{
public:
    ByteBlockTest();

    virtual void beforeTest() override;
    virtual void afterTest() override;

    void testAppend();
    void testFile();

    TSUNIT_TEST_BEGIN(ByteBlockTest);
    TSUNIT_TEST(testAppend);
    TSUNIT_TEST(testFile);
    TSUNIT_TEST_END();

private:
    ts::UString _tempFileName;
};

TSUNIT_REGISTER(ByteBlockTest);


//----------------------------------------------------------------------------
// Initialization.
//----------------------------------------------------------------------------

// Constructor.
ByteBlockTest::ByteBlockTest() :
    _tempFileName()
{
}

// Test suite initialization method.
void ByteBlockTest::beforeTest()
{
    if (_tempFileName.empty()) {
        _tempFileName = ts::TempFile(u".tmp.xml");
    }
    ts::DeleteFile(_tempFileName);
}

// Test suite cleanup method.
void ByteBlockTest::afterTest()
{
    ts::DeleteFile(_tempFileName);
}


//----------------------------------------------------------------------------
// Unitary tests.
//----------------------------------------------------------------------------

void ByteBlockTest::testAppend()
{
    ts::ByteBlock v;
    ts::ByteBlock valtemp;
    valtemp.push_back(0x42);
    valtemp.push_back(0x65);
    std::string strtemp("a string");

    v.clear();
    TSUNIT_ASSERT(v.empty());

    v.appendUInt8(0xAA);
    v.appendUInt16BE(0xAA55);
    v.appendUInt32BE(0xFFCCAA55);
    v.appendUInt64BE(0x87654321AABBCCDD);
    v.append(valtemp);
    v.append(strtemp);
    v.appendUInt8(0x3E);
    v.appendUInt16LE(0xAA55);
    v.appendUInt32LE(0xFFCCAA55);
    v.appendUInt64LE(0x87654321AABBCCDD);

    size_t idx = 0;
    TSUNIT_ASSERT(v.size() == (1+2+4+8+2+8+1+2+4+8));
    TSUNIT_ASSERT(v[idx++] == 0xAA);

    TSUNIT_ASSERT(v[idx++] == 0xAA);
    TSUNIT_ASSERT(v[idx++] == 0x55);

    TSUNIT_ASSERT(v[idx++] == 0xFF);
    TSUNIT_ASSERT(v[idx++] == 0xCC);
    TSUNIT_ASSERT(v[idx++] == 0xAA);
    TSUNIT_ASSERT(v[idx++] == 0x55);

    TSUNIT_ASSERT(v[idx++] == 0x87);
    TSUNIT_ASSERT(v[idx++] == 0x65);
    TSUNIT_ASSERT(v[idx++] == 0x43);
    TSUNIT_ASSERT(v[idx++] == 0x21);
    TSUNIT_ASSERT(v[idx++] == 0xAA);
    TSUNIT_ASSERT(v[idx++] == 0xBB);
    TSUNIT_ASSERT(v[idx++] == 0xCC);
    TSUNIT_ASSERT(v[idx++] == 0xDD);

    TSUNIT_ASSERT(v[idx++] == 0x42);
    TSUNIT_ASSERT(v[idx++] == 0x65);

    TSUNIT_ASSERT(v[idx++] == 'a');
    TSUNIT_ASSERT(v[idx++] == ' ');
    TSUNIT_ASSERT(v[idx++] == 's');
    TSUNIT_ASSERT(v[idx++] == 't');
    TSUNIT_ASSERT(v[idx++] == 'r');
    TSUNIT_ASSERT(v[idx++] == 'i');
    TSUNIT_ASSERT(v[idx++] == 'n');
    TSUNIT_ASSERT(v[idx++] == 'g');

    TSUNIT_ASSERT(v[idx++] == 0x3E);
    TSUNIT_ASSERT(v[idx++] == 0x55);

    TSUNIT_ASSERT(v[idx++] == 0xAA);
    TSUNIT_ASSERT(v[idx++] == 0x55);
    TSUNIT_ASSERT(v[idx++] == 0xAA);
    TSUNIT_ASSERT(v[idx++] == 0xCC);
    TSUNIT_ASSERT(v[idx++] == 0xFF);

    TSUNIT_ASSERT(v[idx++] == 0xDD);
    TSUNIT_ASSERT(v[idx++] == 0xCC);
    TSUNIT_ASSERT(v[idx++] == 0xBB);
    TSUNIT_ASSERT(v[idx++] == 0xAA);
    TSUNIT_ASSERT(v[idx++] == 0x21);
    TSUNIT_ASSERT(v[idx++] == 0x43);
    TSUNIT_ASSERT(v[idx++] == 0x65);
    TSUNIT_ASSERT(v[idx++] == 0x87);
}

void ByteBlockTest::testFile()
{
    const ts::ByteBlock bb({
        0x1B, 0x55, 0xF1, 0xA3, 0x59, 0x76, 0xC4, 0x0C, 0xBD, 0x13, 0xCB, 0x85, 0xE1, 0x28, 0xAE, 0x0B,
        0xA5, 0xE1, 0xB8, 0x43, 0x4C, 0x25, 0x8D, 0xFE, 0x6E, 0xFD, 0xD3, 0xCA, 0x90, 0xB4, 0x81, 0xA8,
        0x65, 0xAB, 0xCE, 0x0E, 0x5C, 0xA9, 0x30, 0x5F, 0x60, 0x8F, 0x6A, 0x3B, 0x6D, 0x4C, 0x91, 0x0B,
        0xA9, 0x7B, 0x28, 0x26, 0x9B, 0x6E, 0x76, 0x8E, 0x8C, 0x8E, 0x6A, 0x17, 0x38, 0x0C, 0xD0, 0x48,
        0x94, 0x1B, 0xB8, 0x9F, 0x41, 0x5D, 0xA0, 0xDF, 0xE8, 0x33, 0x63, 0x3A, 0x8A, 0x12, 0x9D, 0x07,
        0xAC, 0x8A, 0xEE, 0x2F, 0x55, 0x0F, 0x11, 0x5D, 0x2B, 0xCC, 0x5F, 0x2A, 0x1A, 0x14, 0x98, 0xC3,
        0x84, 0x01, 0x88, 0xAA, 0x8D, 0xE9, 0xBD, 0xC3, 0xB3, 0x6D, 0x4A, 0xE0, 0x48, 0x6F, 0x02, 0xE9,
        0xD5, 0xDA, 0xB7, 0x15, 0xE3, 0x78, 0x05, 0x38, 0x83, 0x31, 0x8D, 0xD8, 0x8F, 0x2A, 0xA5, 0xEE,
        0x41, 0x80, 0x18, 0xC2, 0xEA, 0x7F, 0x7F, 0x14, 0x61, 0x6B, 0xEF, 0x97, 0x77, 0x22, 0x82, 0xE3,
        0xBE, 0x08, 0x42, 0x86, 0xCE, 0xDC, 0xCF, 0x5B, 0xE5, 0xC0, 0xB9, 0x06, 0xA8, 0xF5, 0x22, 0x6C,
        0x8D, 0x36, 0xC3, 0xE2, 0x64, 0x72, 0xEF, 0x7D, 0x3B, 0xED, 0x3D, 0xC4, 0x74, 0x71, 0x95, 0x19,
        0x87, 0x12, 0xD9, 0x26, 0x37, 0xB9, 0xBA, 0x4C, 0x15, 0x22, 0xA9, 0xCE, 0xC9, 0xFC, 0x47, 0x35,
        0xEA, 0xCD, 0x9B, 0xF1, 0x3C, 0xC3, 0xEC, 0x01, 0xD9, 0xE9, 0x0A, 0xBD, 0x30, 0x1D, 0x49, 0x19,
        0x85, 0x60, 0x0C, 0x63, 0x32, 0x4F, 0x41, 0x97, 0xB0, 0xD5, 0x1F, 0xDA, 0xCC, 0xF5, 0x38, 0x47,
        0xEC, 0x1B, 0xFA, 0xD6, 0x87, 0x0A, 0x8C, 0x52, 0xF7, 0x27, 0xEC, 0x00, 0xD6, 0xCB, 0x9F, 0x30,
        0x60, 0x8B, 0x53, 0x6A, 0xF8, 0xC4, 0x98, 0x19, 0xAF, 0x67, 0x38, 0x88, 0x44, 0xD2, 0x50, 0xE6,
        0x83, 0x18, 0x83, 0xA1, 0x06, 0xC1, 0xCB, 0x31, 0x71, 0x18, 0x3F, 0x49, 0x2A, 0xB0, 0x59, 0x9D,
        0x58, 0x26, 0x8C, 0xB7, 0x2E, 0x0A, 0x54, 0x47, 0x95, 0xEA, 0x40, 0x9A, 0x02, 0xCD, 0xE9, 0xE5,
        0x62, 0x5B, 0xBF, 0xDE, 0xAE, 0x9D, 0xEC, 0x81, 0xFC, 0x9D, 0x8F, 0x81, 0x68, 0x2B, 0xC6, 0xA0,
        0x17, 0xB8, 0x75, 0x43, 0x0D, 0x15, 0xCF, 0x10, 0x71, 0xD0, 0xA1, 0xDD, 0x3B, 0xE1, 0xDB, 0x80,
        0xA5, 0x8A, 0x20, 0x1E, 0x86, 0xA6, 0x71, 0x1C, 0x5E, 0xD5, 0xB6, 0xBB, 0x11, 0x7E, 0x27, 0xF7,
        0x31, 0xEE, 0x6A, 0xD2, 0xF0, 0x0D, 0x10, 0xF0, 0x29, 0x4E, 0x04, 0x10, 0x72, 0x4C, 0xB9, 0x81,
        0x52, 0x73, 0x5F, 0xEC, 0x8F, 0x65, 0x18, 0x97, 0x64, 0x11, 0xD7, 0xC9, 0xE1, 0x21, 0xC5, 0x8C,
        0xD5, 0xBD, 0xD8, 0x10, 0x65, 0x5B, 0xAB, 0x92, 0x9A, 0x72, 0xC0, 0x58, 0xF4, 0xBF, 0x65, 0x5D,
        0x92, 0xE2, 0x57, 0xA7, 0xC2, 0x7B, 0xE1, 0xB2, 0x68, 0x70, 0xAF, 0x30, 0xB7, 0x38, 0xCB, 0x75,
        0xDB, 0x83, 0x7B, 0xA7, 0x03, 0x03, 0x60, 0xA5, 0x96, 0xB3, 0x35, 0x45, 0x72, 0xB7, 0xE5, 0x7D,
        0x17, 0xD3, 0xBC, 0x80, 0x62, 0x75, 0xE8, 0x59, 0xF0, 0x9B, 0x62, 0xA2, 0x5D, 0x15, 0x0D, 0x1D,
        0xC8, 0xED, 0x5D, 0xF2, 0x7B, 0xDE, 0x71, 0xB5, 0x06, 0x23, 0xAC, 0x63, 0x46, 0xD9, 0x96, 0x2F,
        0x0C, 0x65, 0x97, 0x01, 0x73, 0x95, 0x35, 0x9D, 0x3E, 0x41, 0xD6, 0x73, 0x1A, 0x34, 0x52, 0x2E,
        0xA5, 0x8C, 0x45, 0x60, 0x1B, 0x69, 0x58, 0xCA, 0x3D, 0x3E, 0x3B, 0xCE, 0xE2, 0xC2, 0xD3, 0x9E,
        0xB0, 0x8D, 0x3B, 0x8E, 0x4F, 0xD9, 0xD6, 0xCF, 0x1F, 0xC7, 0x28, 0x7C, 0xCA, 0xFB, 0x18, 0x8B,
        0xA4, 0xDC, 0x7E, 0x5E, 0x1F, 0x1E, 0x18, 0xBC, 0xF4, 0xFC, 0x43, 0x87, 0xE9, 0x1A, 0x1F, 0x7C,
        0xC4, 0x47, 0xB4, 0x57, 0xD6, 0xAE, 0xDF, 0x3B, 0x12, 0x11, 0x35, 0xDC, 0xA4, 0x9C, 0x66, 0x85,
        0x53, 0x62, 0x70, 0x8F, 0xD9, 0xED, 0x9F, 0x52, 0x0E, 0xDB, 0x02, 0x6B, 0x8E, 0xB5, 0x3E, 0xBC,
        0xD8, 0x04, 0xFD, 0x59, 0x0B, 0xA5, 0x30, 0x56, 0x31, 0x79, 0xEA, 0x5B, 0xF3, 0xFD, 0x3A, 0x6F,
        0x8E, 0xFE, 0xB5, 0xA0, 0x5E, 0xF4, 0x99, 0x2A, 0xBB, 0xE4, 0xE5, 0x29, 0xF5, 0xE0, 0x5C, 0xFA,
        0xA6, 0xE1, 0xDF, 0x04, 0x64, 0x23, 0x4D, 0xE6, 0x1B, 0xE2, 0x80, 0x2C, 0x97, 0x5A, 0x6A, 0x61,
        0x64, 0x4C, 0xE3, 0xAF, 0x68, 0xDC, 0x72, 0x7B, 0x53, 0xAD, 0x46, 0x06, 0x69, 0x43, 0xA1, 0x8B,
        0x30, 0x03, 0xEC, 0xCD, 0xCE, 0x83, 0x32, 0x71, 0x0C, 0x6C, 0x9A, 0x72, 0x6B, 0x5B, 0xA6, 0x81,
        0x4F, 0x1B, 0xED, 0x00, 0xB2, 0xA5, 0xC6, 0x6F, 0x3A, 0x79, 0x7E, 0x9B, 0x20, 0x48, 0x4C, 0x89,
        0xB4, 0x94, 0xB4, 0x2B, 0x4F, 0x64, 0x91, 0xC9, 0xC2, 0x3D, 0x45, 0x1C, 0xC7, 0xF7, 0x94, 0x29,
        0xAE, 0x88, 0x0C, 0x1E, 0x5A, 0xB4, 0x68, 0xBC, 0x4F, 0xDD, 0xE7, 0xA5, 0x2F, 0xF3, 0x26, 0x7D,
        0x43, 0x6D, 0x40, 0x70, 0x84, 0xC2, 0x8A, 0xC4, 0x86, 0x57, 0x57, 0xD8, 0xC6, 0xF8, 0xFD, 0x05,
        0xC1, 0xED, 0x5E, 0xBF, 0x2C, 0x8C, 0x56, 0x97, 0x82, 0x2C, 0xD1, 0xFC, 0x95, 0x94, 0x6D, 0x2C,
        0x51, 0x39, 0xC3, 0x4D, 0x48, 0x17, 0xF5, 0x19, 0x4F, 0xE7, 0x7A, 0xFC, 0x05, 0x00, 0xEA, 0x91,
        0x8B, 0x47, 0xF8, 0x16, 0x95, 0xC0, 0xAF, 0xC1, 0xC3, 0xA8, 0xB9, 0x67, 0xC4, 0x12, 0x67, 0x05,
        0xDC, 0x93, 0x7F, 0xEB, 0x54, 0x26, 0x55, 0x6B, 0x26, 0x6F, 0xCD, 0x31, 0xE8, 0xC2, 0x10, 0xCD,
        0xAB, 0xC8, 0xE5, 0xC6, 0x16, 0xFC, 0x3B, 0xE0, 0xEE, 0x6F, 0xC4, 0x5F, 0x68, 0x33, 0x1C, 0x03,
        0x63, 0xFC, 0x88, 0x98, 0x35, 0xE5, 0x01, 0x6A, 0x58, 0x41, 0xFB, 0x2C, 0x91, 0x21, 0xF5, 0x4D,
        0x57, 0xAE, 0xC6, 0x81, 0x5B, 0x2D, 0x14, 0xED, 0x05, 0xC2, 0x31, 0x2B, 0x55, 0x97, 0x6D, 0x44,
        0x21, 0xB7, 0x9A, 0xD5, 0x0D, 0xEB, 0x37, 0xE5, 0x55, 0x54, 0x5D, 0x2D, 0x10, 0x58, 0xB1, 0x1A,
        0xAF, 0x75, 0x81, 0xF5, 0x78, 0x1B, 0xEC, 0xFF, 0x30, 0xFB, 0xB4, 0x5C, 0x46, 0x5A, 0x27, 0x88,
        0x87, 0x03, 0xE7, 0xA9, 0xD0, 0x19, 0xCA, 0x2C, 0xCF, 0x42, 0x76, 0xD7, 0x37, 0xB2, 0xC4, 0x0F,
        0x38, 0x82, 0x4D, 0xA3, 0x56, 0x2B, 0xE3, 0x9A, 0x65, 0x26, 0xC0, 0x2B, 0xFD, 0x52, 0xED, 0x19,
        0x23, 0x70, 0xE8, 0x69, 0x6F, 0x0B, 0x76, 0xC1, 0x4D, 0x9E, 0x16, 0xF1, 0x2F, 0x2E, 0x9F, 0xAE,
        0xFC, 0x4D, 0xE2, 0x3E, 0xF1, 0x0B, 0x4F, 0x1E, 0xDA, 0xA6, 0xBA, 0x82, 0xA1, 0x51, 0x20, 0xB1,
        0xB8, 0x34, 0x28, 0x0B, 0xFC, 0xEF, 0x7D, 0x11, 0xFF, 0x40, 0x58, 0x15, 0xB9, 0xDA, 0x9D, 0xE7,
        0x22, 0xF5, 0x31, 0x43, 0xAF, 0x66, 0x7E, 0x29, 0x02, 0xF9, 0x48, 0x63, 0x72, 0xCB, 0x12, 0x96,
        0xD9, 0x6F, 0xD3, 0x39, 0x40, 0xA6, 0xD1, 0x3D, 0x01, 0x75, 0xEE, 0x8B, 0x80, 0xFA, 0x76, 0xDF,
        0x71, 0xBD, 0xA3, 0x17, 0x1F, 0xCA, 0x27, 0xB6, 0x3F, 0xBE, 0xCC, 0x81, 0x04, 0x24, 0x02, 0xBF,
        0x78, 0x8C, 0x9B, 0xE5, 0x05, 0xE4, 0x99, 0x5C, 0x28, 0xDD, 0x2D, 0xB2, 0xAD, 0x9A, 0x2C, 0x83,
        0x02, 0x9E, 0x0F, 0x07, 0x16, 0x8F, 0x4E, 0xC6, 0x1F, 0x51, 0xAA, 0x2C, 0x98, 0xCC, 0xDB, 0xB2,
        0x82, 0xED, 0xA0, 0xDA, 0xD0, 0xB2, 0xC6,
    });

    TSUNIT_EQUAL(999, bb.size());
    TSUNIT_ASSERT(bb.saveToFile(_tempFileName));

    ts::ByteBlock bb1;
    TSUNIT_ASSERT(bb1.loadFromFile(_tempFileName));

    TSUNIT_EQUAL(999, bb1.size());
    TSUNIT_ASSERT(bb1 == bb);
}
