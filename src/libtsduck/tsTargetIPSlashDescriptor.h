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
//!
//!  @file
//!  Representation of a target_IP_slash_descriptor (INT specific).
//!
//----------------------------------------------------------------------------

#pragma once
#include "tsAbstractDescriptor.h"
#include "tsIPAddress.h"
#include "tsIPUtils.h"

namespace ts {
    //!
    //! Representation of a target_IP_slash_descriptor (INT specific).
    //!
    //! This descriptor cannot be present in other tables than an INT
    //! because its tag reuses an MPEG-defined one.
    //!
    //! @see ETSI EN 301 192, 8.4.5.9
    //! @ingroup descriptor
    //!
    class TSDUCKDLL TargetIPSlashDescriptor : public AbstractDescriptor
    {
    public:
        //!
        //! Structure of an address entry in the descriptor.
        //!
        class Address
        {
        public:
            IPAddress IPv4_addr;         //!< IPv4 address.
            uint8_t   IPv4_slash_mask;   //!< Number of bits in network mask.

            //!
            //! Constructor
            //! @param [in] addr IPv4 address.
            //! @param [in] mask Number of bits in network mask.
            //!
            Address(const IPAddress& addr = IPAddress(), uint8_t mask = 0);
        };

        // TargetIPSlashDescriptor public members:
        std::vector<Address> addresses;  //!< IPv4 addresses

        //!
        //! Maximum number of entries to fit in 255 bytes.
        //!
        static const size_t MAX_ENTRIES = 51;

        //!
        //! Default constructor.
        //!
        TargetIPSlashDescriptor();

        //!
        //! Constructor from a binary descriptor.
        //! @param [in] bin A binary descriptor to deserialize.
        //! @param [in] charset If not zero, character set to use without explicit table code.
        //!
        TargetIPSlashDescriptor(const Descriptor& bin, const DVBCharset* charset = nullptr);

        // Inherited methods
        virtual void serialize(Descriptor&, const DVBCharset* = nullptr) const override;
        virtual void deserialize(const Descriptor&, const DVBCharset* = nullptr) override;
        virtual void buildXML(xml::Element*) const override;
        virtual void fromXML(const xml::Element*, const DVBCharset* = nullptr) override;
        DeclareDisplayDescriptor();
    };
}
