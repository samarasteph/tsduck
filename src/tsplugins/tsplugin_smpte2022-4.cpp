//----------------------------------------------------------------------------
//
// TSDuck - The MPEG Transport Stream Toolkit
// Copyright (c) 2005-2020, Thierry Lelegard
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
//
//----------------------------------------------------------------------------
//
//  Transport stream input shared library:
//  Gives support for SMPTE 2022-4 spec (Non-Piecewise Constant Variable Bit Rate TS).
//
//	links:
//	https://en.wikipedia.org/wiki/SMPTE_2022
//	https://www.smpte.org/sites/default/files/2017-08-17-ST-2022-Edwards-V4-Handout.pdf
//----------------------------------------------------------------------------
// make NOTEST=1 NODTAPI=1 NOCURL=1 NOPCSC=1 NOSRT=1 NOTELETEXT=1
#include <list>
#include <cstring>
#include <algorithm>
#include <memory>

#include "tsAbstractDatagramInputPlugin.h"
#include "tsPluginRepository.h"
#include "tsUDPReceiver.h"
TSDUCK_SOURCE;

namespace ts {

	class SMPTE_2022_4 final: public AbstractDatagramInputPlugin {
		TS_NOBUILD_NOCOPY(SMPTE_2022_4);
	public:
		SMPTE_2022_4(TSP*);
		virtual bool receiveDatagram(void* buffer, size_t buffer_size, size_t& ret_size, MicroSecond& timestamp) override;

		// Implementation of plugin API.
		virtual bool getOptions() override;
		virtual bool start() override;
		virtual bool stop() override;
		virtual bool abortInput() override;
		virtual bool setReceiveTimeout(MilliSecond timeout) override;

	private:

		size_t _rtpHeaderSize(uint8_t* bytes, size_t buffer_size) const;
		size_t _restoreAllPackets(uint8_t* dest, const size_t dest_max_size,
				const std::list<uint8_t*>& packets, const uint32_t* timedata, const uint timedata_count);

		uint8_t* 	_savepackets(const std::list<uint8_t*>& packets) const;
		uint32_t* 	_savetimedata(const uint32_t* timedata, const uint count) const;

	    UDPReceiver _sock; // Incoming socket with associated command line options.
	    uint8_t _byte_buffer [IP_MAX_PACKET_SIZE*2];
	    uint8_t _packet_per_Datagram_max;
	    uint8_t _running_ts_counter;
	};
}

TSPLUGIN_DECLARE_INPUT(u"smpte-2022-4", ts::SMPTE_2022_4)

ts::SMPTE_2022_4::SMPTE_2022_4(TSP* ptsp):
	AbstractDatagramInputPlugin(ptsp, IP_MAX_PACKET_SIZE, u"Receive TS packets from UDP/IP, multicast or unicast"
			, u"[options] [address:]port", u"kernel", u"A kernel-provided time-stamp for the packet, when available (Linux only)")
	, _sock(*ptsp), _packet_per_Datagram_max(0), _running_ts_counter(0) {

	// Add UDP receiver common options.
	_sock.defineArgs(*this);
}

//----------------------------------------------------------------------------
// Input command line options method
//----------------------------------------------------------------------------

bool ts::SMPTE_2022_4::getOptions()
{
    // Get command line arguments for superclass and socket.
    return AbstractDatagramInputPlugin::getOptions() && _sock.loadArgs(duck, *this);
}


//----------------------------------------------------------------------------
// Input start method
//----------------------------------------------------------------------------

bool ts::SMPTE_2022_4::start()
{
    // Initialize superclass and UDP socket.
    return AbstractDatagramInputPlugin::start() && _sock.open(*tsp);
}


//----------------------------------------------------------------------------
// Input stop method
//----------------------------------------------------------------------------

bool ts::SMPTE_2022_4::stop()
{
    _sock.close(*tsp);
    return AbstractDatagramInputPlugin::stop();
}


//----------------------------------------------------------------------------
// Input abort method
//----------------------------------------------------------------------------

bool ts::SMPTE_2022_4::abortInput()
{
    _sock.close(*tsp);
    return true;
}


//----------------------------------------------------------------------------
// Set receive timeout from tsp.
//----------------------------------------------------------------------------

bool ts::SMPTE_2022_4::setReceiveTimeout(MilliSecond timeout)
{
    if (timeout > 0) {
        _sock.setReceiveTimeoutArg(timeout);
    }
    return true;
}

//----------------------------------------------------------------------------
// Datagram reception method.
//----------------------------------------------------------------------------

bool ts::SMPTE_2022_4::receiveDatagram(void* buffer, size_t buffer_size, size_t& ret_size, MicroSecond& timestamp) {

	SocketAddress sender;
	SocketAddress destination;
	const bool valid = _sock.receive(buffer, buffer_size, ret_size, sender, destination, tsp, *tsp, &timestamp);

	if (valid){

		uint8_t* bytes = static_cast<u_char*>(buffer);
		size_t rtp_header_size = _rtpHeaderSize(bytes, buffer_size);

		if (rtp_header_size==0) // no RPT, let processing without modification
			return valid;

		if (rtp_header_size < buffer_size){
			const uint8_t* end = bytes + buffer_size;

			bytes+=rtp_header_size;

			uint8_t *packet = bytes;
			std::list<uint8_t*> packets;
			while (packet < end && packet[0] == SYNC_BYTE){
				packets.push_back(packet);
				packet += ts::PKT_SIZE;
			}

			if (packets.empty())
				tsp->log(Severity::Warning, u"No TS packet found in datagram");
			else{
				if (_packet_per_Datagram_max==0){
					_packet_per_Datagram_max = packet - bytes;
				}else{
					uint nbpackets = packets.size();
					if (nbpackets != _packet_per_Datagram_max){
						tsp->log(Severity::Warning,
								u"Nunmber of TS packet per RTP changed from %d to %d",
								{ _packet_per_Datagram_max, nbpackets });
					}
					_packet_per_Datagram_max = nbpackets;
				}

				// check payload extension header flag 0x10 for SMPTE timing data
				if (packet < end && (packet[0] & 0xc0) == 0x80){
					const uint time_data_desc = (packet[0] & 0x38) >> 3; // 3 bits
					const uint time_data_count = packet[0] & 0x07; // 3 bits
					packet += 1;

					//each time data is 4 bytes
					if(packet + time_data_count*4 <= end){
						if (time_data_desc == 0x01){ //running TS packet counter
							ret_size = _restoreAllPackets(reinterpret_cast<uint8_t*>(buffer), buffer_size, packets,
									reinterpret_cast<uint32_t*>(packet), time_data_count);

						} else if (time_data_desc == 0x10){ //27 Mhz clock
							tsp->log(Severity::Fatal, u"SMPTE 2022-4 with 27 Mhz clock time field is not implemented");
						}
					}
					else{
						tsp->log(Severity::Error, u"SMPTE Timing data not complete");
					}
				}
				else {
					tsp->log(Severity::Info, u"RTP packet has no SMPTE 2022-4 information");
				}
			}
		}
	}
	return valid;
}

size_t ts::SMPTE_2022_4::_rtpHeaderSize(uint8_t* bytes, size_t buffer_size) const{

	constexpr size_t RTP_HEADER_MIN_SIZE = 12;

	if (bytes[0] != SYNC_BYTE && buffer_size >= RTP_HEADER_MIN_SIZE) { //likely RTP header
		/*
		 * Header size 12 bytes + [4 * CSRC count (optional)] + [Extension Header (optional)]
		 *
		 */
		size_t header_size = RTP_HEADER_MIN_SIZE;
		//const u_char version = buffer[0] >> 6;
		//const u_char padding = (bytes[0] >> 5) & 0x01;

		const u_char extension_header = (bytes[0] >> 4) & 0x01;
		const u_char csrc_count = bytes[0] & 0x0f;

		header_size += (4 * csrc_count);
		if ( buffer_size >= header_size && extension_header ){

			// Extension header fields: Timestamp (2 bytes) | Ext header Length (2 bytes)
			header_size += 4;
			if (buffer_size >= header_size){
				header_size += * reinterpret_cast<uint16_t*>(bytes+header_size-2); //extension header len (2 bytes)
			}
		}
		return header_size;
	}
	return 0;
}

inline size_t ts::SMPTE_2022_4::_restoreAllPackets(uint8_t *dest, size_t dest_max_size,
		const std::list<uint8_t*>& packets, const uint32_t *timedata, const uint timedata_count) {

	if (timedata_count != packets.size()){
		tsp->log(Severity::Error, u"Timing counters number (%d) is different than number of TS packets(%d)",
				{ timedata_count, packets.size() });
		return 0;
	}
	//save counters as read buffer is going to be overwritten
	std::unique_ptr<uint32_t[]>  counter_ptr( _savetimedata(timedata, timedata_count) );
	//save packets as well
	std::unique_ptr<uint8_t[]> packets_buffer( _savepackets(packets) );

	//for the very begining, initialize running counter with first counter value
	if (_running_ts_counter == 0 and timedata_count > 0){
		_running_ts_counter = counter_ptr[0];
	}

	size_t ret_size = 0;
	const uint8_t* end_dest = dest + dest_max_size;
	uint index;

	for(index=0 ;index<timedata_count; index += 1){

		while( counter_ptr[index] > _running_ts_counter){
			//write null packets
			ret_size += ts::PKT_SIZE;
			if (dest+ret_size < end_dest){
				std::memcpy(dest, ts::NullPacket.b, ts::PKT_SIZE);
			}
			else{
				ret_size -= ts::PKT_SIZE;
				break;
			}
			_running_ts_counter += 1;
		}
		//write packet
		ret_size += ts::PKT_SIZE;
		if (dest+ret_size < end_dest){
			std::memcpy(dest+ret_size, packets_buffer.get()+(index*ts::PKT_SIZE), ts::PKT_SIZE);
		}
		else{
			ret_size -= ts::PKT_SIZE;
			break;
		}
	}
	//TODO: bufferize remaining data
	if (index<timedata_count){
		tsp->log(Severity::Error, u"Not all packets written (insufficient buffer size): %d out of %d",
				{index+1, timedata_count});
	}
	return ret_size;
}

inline uint8_t* ts::SMPTE_2022_4::_savepackets(const std::list<uint8_t*> &packets) const {
	uint8_t* packets_buffer = new uint8_t[packets.size()*ts::PKT_SIZE];
	size_t offset = 0;
	std::for_each(packets.begin(), packets.end(), [&offset, packets_buffer](uint8_t* p){
		std::memcpy(packets_buffer+offset, p, ts::PKT_SIZE);
		offset += ts::PKT_SIZE;
	});
	return packets_buffer;
}

inline uint32_t* ts::SMPTE_2022_4::_savetimedata(const uint32_t *timedata, const uint count) const {
	uint32_t *dest = new uint32_t[count];
	std::memcpy(dest, timedata, count*sizeof(uint32_t));
	return dest;
}
