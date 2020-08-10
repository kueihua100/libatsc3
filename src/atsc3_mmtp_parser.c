/*
 * mmtp_types.h
 *
 *  Created on: Jan 3, 2019
 *      Author: jjustman
 *
 *
 * parses the header of the MMTP packet, and invokes specific methods for MPU and signaling messages
 */
#include <assert.h>
#include <limits.h>

#include "atsc3_mmtp_parser.h"
#include "atsc3_mmt_mpu_parser.h"
#include "atsc3_mmt_mpu_utils.h"
#include "atsc3_mmt_signalling_message.h"
#include "atsc3_mmtp_packet_types.h"

int _MMTP_DEBUG_ENABLED = 0;
int _MMTP_TRACE_ENABLED = 0;


#if (DUMP_ENABLE & SLS_MMTP_DUMP)
int _SLS_MMTP_DUMP_ENABLED = 1;
FILE* __DUMP_SLS_MMTP_FILE = NULL;
bool  __DUMP_SLS_MMTP_AVAILABLE = true;

int sls_mmtp_dump(const char *format, ...)  {

  if(__DUMP_SLS_MMTP_AVAILABLE && !__DUMP_SLS_MMTP_FILE) {
    __DUMP_SLS_MMTP_FILE = fopen("sls_mmtp.dump", "w");
    if(!__DUMP_SLS_MMTP_FILE) {
      __DUMP_SLS_MMTP_AVAILABLE = false;
      __DUMP_SLS_MMTP_FILE = stderr;
    }
  }

    va_list argptr;
	va_start(argptr, format);
	vfprintf(__DUMP_SLS_MMTP_FILE, format, argptr);
    va_end(argptr);
    fflush(__DUMP_SLS_MMTP_FILE);
	return 0;
}

#define _SLS_MMTP_DUMPLN(...) sls_mmtp_dump(__VA_ARGS__);sls_mmtp_dump("%s%s","\r","\n")
#define _SLS_MMTP_DUMPT(...)  if(_SLS_MMTP_DUMP_ENABLED) { sls_mmtp_dump("%s:%d:[%.4f]: ",__FILE__,__LINE__, gt());_SLS_MMTP_DUMPLN(__VA_ARGS__); }
#define _SLS_MMTP_DUMPN(...)  if(_SLS_MMTP_DUMP_ENABLED) { _SLS_MMTP_DUMPLN(__VA_ARGS__); }
#endif //DUMP_ENABLE

/*
 * Open items:
 *
 *  The value of the timestamp field of an MMTP packet shall represent the UTC time when the first byte of the MMTP packet is passed to the UDP layer and shall be formatted in the “short format” as specified in Clause 6 of RFC 5905, NTP version 4 [23].
 *  The value of the RAP_flag of MMTP packets shall be set to 0 when the value of the FT field is equal to 0.
 */

mmtp_packet_header_t* mmtp_packet_header_parse_from_block_t(block_t* udp_packet) {

	if(block_Remaining_size(udp_packet) < 20) {
		//bail, the min header is at least 20 bytes
		__MMTP_PARSER_ERROR("mmtp_packet_header_parse_from_block_t: udp_raw_buf size is: %d, need at least 20 bytes, udp_packet ptr: %p", block_Remaining_size(udp_packet), udp_packet);
		return NULL;
	}

	mmtp_packet_header_t* mmtp_packet_header = mmtp_packet_header_new();

	int mmtp_payload_length = block_Remaining_size(udp_packet);
	uint8_t *raw_buf = block_Get(udp_packet);
	uint8_t *buf = raw_buf;

	__MMTP_PARSER_DEBUG("mmtp_packet_header_parse_from_block_t: udp_packet->i_pos: %d, udp_packet->p_size: %d, udp_packet->p_buffer: %p, mmtp_packet_header: %p",
			udp_packet->i_pos,
			udp_packet->p_size,
			raw_buf,
			mmtp_packet_header);


	uint8_t mmtp_packet_preamble[20];

	buf = extract(buf, mmtp_packet_preamble, 20);

	//A/331 Section 8.1.2.1.3 Constraints on MMTP
	// The value of the version field of MMTP packets shall be '01'.
#if !_ISO23008_1_MMTP_VERSION_0x00_SUPPORT_
	mmtp_packet_header->mmtp_packet_version = (mmtp_packet_preamble[0] & 0xC0) >> 6;
	if(mmtp_packet_header->mmtp_packet_version != 0x1) {
		__MMTP_PARSER_ERROR("mmtp_packet_header_parse_from_block_t: MMTP version field != 0x1, value is 0x%x, bailing!", mmtp_packet_header->mmtp_packet_version);
		goto error;
	}
#endif

	mmtp_packet_header->packet_counter_flag = (mmtp_packet_preamble[0] & 0x20) >> 5;
	mmtp_packet_header->fec_type = (mmtp_packet_preamble[0] & 0x18) >> 3;

#if _ISO23008_1_MMTP_VERSION_0x00_SUPPORT_

	if(mmtp_packet_header->mmtp_packet_version == 0x00) {
		//after fec_type, with v=0, next bitmask is 0x4 >>2
		//0000 0010
		//V0CF E-XR
		mmtp_packet_header->mmtp_header_extension_flag = (mmtp_packet_preamble[0] & 0x2) >> 1;
		mmtp_packet_header->mmtp_rap_flag = mmtp_packet_preamble[0] & 0x1;

		//6 bits right aligned
		mmtp_packet_header->mmtp_payload_type = mmtp_packet_preamble[1] & 0x3f;
		if(mmtp_packet_header->mmtp_header_extension_flag & 0x1) {
			mmtp_packet_header->mmtp_header_extension_type = (mmtp_packet_preamble[16]) << 8 | mmtp_packet_preamble[17];
			mmtp_packet_header->mmtp_header_extension_length = (mmtp_packet_preamble[18]) << 8 | mmtp_packet_preamble[19];
		} else {
			//walk back by 4 bytes
			buf-=4;
		}
	} else

#endif

	if(mmtp_packet_header->mmtp_packet_version == 0x01) {
		//bitmask is 0000 00
		//0000 0100
		//V1CF EXRQ
		mmtp_packet_header->mmtp_header_extension_flag = (mmtp_packet_preamble[0] & 0x4) >> 2;    //X
		mmtp_packet_header->mmtp_rap_flag = (mmtp_packet_preamble[0] & 0x2) >> 1;			    //RAP
        mmtp_packet_header->mmtp_qos_flag = mmtp_packet_preamble[0] & 0x1;					    //Q: QOS
		//0000 0000
		//FEBI TYPE
		//4 bits for preamble right aligned

		mmtp_packet_header->mmtp_flow_identifer_flag = ((mmtp_packet_preamble[1]) & 0x80) >> 7;			//F
		mmtp_packet_header->mmtp_flow_extension_flag = ((mmtp_packet_preamble[1]) & 0x40) >> 6;			//E
		mmtp_packet_header->mmtp_header_compression = ((mmtp_packet_preamble[1]) &  0x20) >> 5; 		//B
		mmtp_packet_header->mmtp_indicator_ref_header_flag = ((mmtp_packet_preamble[1]) & 0x10) >> 4;	//I

		mmtp_packet_header->mmtp_payload_type = mmtp_packet_preamble[1] & 0xF;
        
        if(!((mmtp_packet_preamble[16] >> 7) & 0x1)) {
        	__MMTP_PARSER_DEBUG("mmtp_demuxer: ISO23008-1: mmtp_packet_preamble byte[16] 'r' bit is not 1!");
        }
		//TB 2 bits
		mmtp_packet_header->mmtp_type_of_bitrate = ((mmtp_packet_preamble[16] & 0x40) >> 6) | ((mmtp_packet_preamble[16] & 0x20) >> 5);

		//DS 3 bits
        mmtp_packet_header->mmtp_delay_sensitivity = ((mmtp_packet_preamble[16] >> 2) & 0x7);
           
		//TP 3 bits
		mmtp_packet_header->mmtp_transmission_priority = ((mmtp_packet_preamble[16] & 0x03) << 1) | ((mmtp_packet_preamble[17] >> 7) & 0x1);

		mmtp_packet_header->flow_label = mmtp_packet_preamble[17] & 0x7f;

		//header extension is offset by 2 bytes in v=1, so an additional block chain read is needed to get extension length
		if(mmtp_packet_header->mmtp_header_extension_flag & 0x1) {
			mmtp_packet_header->mmtp_header_extension_type = (mmtp_packet_preamble[18] << 8) | mmtp_packet_preamble[19];

			__MMTP_PARSER_TRACE("mmtp_packet_header_parse_from_block_t: mmtp_demuxer - doing mmtp_header_extension_length_bytes: %d",  mmtp_packet_header->mmtp_header_extension_type);

			uint8_t mmtp_header_extension_length_bytes[2];
			buf = extract(buf, mmtp_header_extension_length_bytes, 2);

			mmtp_packet_header->mmtp_header_extension_length = mmtp_header_extension_length_bytes[0] << 8 | mmtp_header_extension_length_bytes[1];
		} else {
			//walk us back for mmtp payload type header parsing
			buf-=2;
		}
	} else {
		__MMTP_PARSER_ERROR("mmtp_demuxer - unknown packet version of 0x%X", mmtp_packet_header->mmtp_packet_version);
		goto error;
	}

	mmtp_packet_header->mmtp_packet_id			= mmtp_packet_preamble[2]  << 8  | mmtp_packet_preamble[3];

#if _ATSC3_MMT_PACKET_ID_MPEGTS_COMPATIBILITY_
	//exception for MMT signaling, See A/331 7.2.3.

	if(!(mmtp_packet_header->mmtp_packet_id == 0x0000 && mmtp_packet_header->mmtp_payload_type == 0x2)) {
		if(!(mmtp_packet_header->mmtp_packet_id >= 0x0010 && mmtp_packet_header->mmtp_packet_id <= 0x1FFE)) {
			__MMTP_PARSER_ERROR("mmtp_packet_header_parse_from_block_t: MMTP packet_id is not compliant with A/331 8.1.2.1.3 - MPEG2 conversion compatibility, packet_id: %-10hu (0x%04x)", mmtp_packet_header->mmtp_packet_id, mmtp_packet_header->mmtp_packet_id);
			goto error;
		}
	}
#endif
	mmtp_packet_header->mmtp_timestamp = mmtp_packet_preamble[4]  << 24 | mmtp_packet_preamble[5]  << 16 | mmtp_packet_preamble[6]   << 8 | mmtp_packet_preamble[7];
	compute_ntp32_to_seconds_microseconds(mmtp_packet_header->mmtp_timestamp, &mmtp_packet_header->mmtp_timestamp_s, &mmtp_packet_header->mmtp_timestamp_us);

	mmtp_packet_header->packet_sequence_number	= mmtp_packet_preamble[8]  << 24 | mmtp_packet_preamble[9]  << 16 | mmtp_packet_preamble[10]  << 8 | mmtp_packet_preamble[11];
   
    if(mmtp_packet_header->packet_counter_flag) {
        mmtp_packet_header->packet_counter = mmtp_packet_preamble[12] << 24 | mmtp_packet_preamble[13] << 16 | mmtp_packet_preamble[14]  << 8 | mmtp_packet_preamble[15];
    } else {
        //walk back our buff by 4 bytes, korean MMT may not set this.
        buf-=4;
    }

    if(mmtp_packet_header->mmtp_header_extension_flag & 0x1) {
    	//clamp mmtp_header_extension_length to max length of our mmtp packet
		mmtp_packet_header->mmtp_header_extension_length = __MIN(mmtp_packet_header->mmtp_header_extension_length, mmtp_payload_length - (buf - raw_buf));

		__MMT_MPU_PARSER_DEBUG("mmtp_mpu_packet_parse_from_block_t: mmtp_header_extension_flag, header extension size: %d, packet version: %d, payload_type: 0x%X, packet_id 0x%hu, timestamp: 0x%X, packet_sequence_number: 0x%X, packet_counter: 0x%X",
				mmtp_packet_header->mmtp_packet_version,
				mmtp_packet_header->mmtp_header_extension_length,
				mmtp_packet_header->mmtp_payload_type,
				mmtp_packet_header->mmtp_packet_id,
				mmtp_packet_header->mmtp_timestamp,
				mmtp_packet_header->packet_sequence_number,
				mmtp_packet_header->packet_counter);

		mmtp_packet_header->mmtp_header_extension = block_Alloc(mmtp_packet_header->mmtp_header_extension_length);
		block_Write(mmtp_packet_header->mmtp_header_extension, buf, mmtp_packet_header->mmtp_header_extension_length);
		buf += mmtp_packet_header->mmtp_header_extension_length;
		int32_t mmtp_payload_remaining_length = mmtp_payload_length - (buf - raw_buf);
		if(mmtp_payload_remaining_length < 1) {
			__MMT_MPU_PARSER_ERROR("mmtp_packet_header_parse_from_block_t: reading mmtp_header_extension_length, remaining size too small: %d", mmtp_payload_remaining_length);
			goto error;
		}
	}

    int32_t bytes_processed = (buf - raw_buf);
    __MMTP_PARSER_DEBUG("mmtp_packet_header_parse_from_block_t: completed header parse, consumed %d bytes, mmtp_packet_header is: %p",
    		bytes_processed,
			mmtp_packet_header);

    block_Seek_Relative(udp_packet, bytes_processed);

	return mmtp_packet_header;

error:
	mmtp_packet_header_free(&mmtp_packet_header);

	return NULL;
}


//TODO: purge
////think of this as castable to the base fields as they are the same size layouts
//mmtp_payload_fragments_union_t* mmtp_packet_create(block_t * raw_packet,
//												uint8_t mmtp_packet_version,
//												uint8_t mmtp_payload_type,
//												uint16_t mmtp_packet_id,
//												uint32_t packet_sequence_number,
//												uint32_t packet_counter,
//												uint32_t mmtp_timestamp) {
//	mmtp_payload_fragments_union_t *entry = NULL;
//
//	//pick the larger of the timed vs. non-timed fragment struct sizes
//	entry = calloc(1, sizeof(mmtp_payload_fragments_union_t));
//
//	if(!entry) {
//		abort();
//	}
//
//	entry->mmtp_packet_header->raw_packet = raw_packet;
//	entry->mmtp_packet_header->mmtp_packet_version = mmtp_packet_version;
//	entry->mmtp_packet_header->mmtp_payload_type = mmtp_payload_type;
//	entry->mmtp_packet_header->mmtp_packet_id = mmtp_packet_id;
//	entry->mmtp_packet_header->packet_sequence_number = packet_sequence_number;
//	entry->mmtp_packet_header->packet_counter = packet_counter;
//	entry->mmtp_packet_header->mmtp_timestamp = mmtp_timestamp;
//
//	return entry;
//}



void mmtp_packet_header_dump(mmtp_packet_header_t* mmtp_packet_header) {
	__MMTP_PARSER_DEBUG("------------------");
	__MMTP_PARSER_DEBUG("MMTP Packet Header (%p)", mmtp_packet_header);
	__MMTP_PARSER_DEBUG("------------------");
	__MMTP_PARSER_DEBUG(" packet version         : %-10d (0x%d%d)", 	mmtp_packet_header->mmtp_packet_version, ((mmtp_packet_header->mmtp_packet_version >> 1) & 0x1), mmtp_packet_header->mmtp_packet_version & 0x1);
	__MMTP_PARSER_DEBUG(" payload_type           : %-10d (0x%d%d)", 	mmtp_packet_header->mmtp_payload_type, ((mmtp_packet_header->mmtp_payload_type >> 1) & 0x1), mmtp_packet_header->mmtp_payload_type & 0x1);
	__MMTP_PARSER_DEBUG(" packet_id              : %-10hu (0x%04x)", mmtp_packet_header->mmtp_packet_id, mmtp_packet_header->mmtp_packet_id);
	__MMTP_PARSER_DEBUG(" timestamp              : %-10u (0x%08x)", 	mmtp_packet_header->mmtp_timestamp, mmtp_packet_header->mmtp_timestamp);
	__MMTP_PARSER_DEBUG(" packet_sequence_number : %-10u (0x%08x)",	mmtp_packet_header->packet_sequence_number,mmtp_packet_header->packet_sequence_number);
	__MMTP_PARSER_DEBUG(" packet counter         : %-10u (0x%04x)", 	mmtp_packet_header->packet_counter, mmtp_packet_header->packet_counter);
	__MMTP_PARSER_DEBUG("------------------");
}

#if (DUMP_ENABLE & SLS_MMTP_DUMP)
void mmtp_signal_packet_dump(mmtp_signalling_packet_t* mmtp_signalling_packet) {
	if(mmtp_signalling_packet->mmtp_payload_type != 0x02) {
		__MMSM_ERROR("signalling_message_dump, payload_type 0x%x != 0x02", mmtp_signalling_packet->mmtp_payload_type);
		return;
	}

	//dump mmtp packet header
	mmtp_signal_packet_header_dump((mmtp_packet_header_t*)mmtp_signalling_packet);

	_SLS_MMTP_DUMPN("Signalling Message");
	_SLS_MMTP_DUMPN("------------------------------------------------------");
	/**
	 * dump si payload header fields
	 * 	uint8_t		si_fragmentation_indiciator; //2 bits,
		uint8_t		si_additional_length_header; //1 bit
		uint8_t		si_aggregation_flag; 		 //1 bit
		uint8_t		si_fragmentation_counter;    //8 bits
		uint16_t	si_aggregation_message_length;
	 */
	_SLS_MMTP_DUMPN(" fragmentation_indiciator   : %d", 	mmtp_signalling_packet->si_fragmentation_indiciator);
	_SLS_MMTP_DUMPN(" additional_length_header   : %d", 	mmtp_signalling_packet->si_additional_length_header);
	_SLS_MMTP_DUMPN(" aggregation_flag           : %d",	mmtp_signalling_packet->si_aggregation_flag);
	_SLS_MMTP_DUMPN(" fragmentation_counter      : %d",	mmtp_signalling_packet->si_fragmentation_counter);
	_SLS_MMTP_DUMPN(" aggregation_message_length : %hu",	mmtp_signalling_packet->si_aggregation_message_length);

	for(int i=0; i < mmtp_signalling_packet->mmt_signalling_message_header_and_payload_v.count; i++) {
		mmt_signalling_message_header_and_payload_t* mmt_signalling_message_header_and_payload = mmtp_signalling_packet->mmt_signalling_message_header_and_payload_v.data[i];

		_SLS_MMTP_DUMPN("+++++++++++++++++++++++++++++");
		_SLS_MMTP_DUMPN(" Message ID: %hu (0x%04x)", 	mmt_signalling_message_header_and_payload->message_header.message_id, mmt_signalling_message_header_and_payload->message_header.message_id);
		_SLS_MMTP_DUMPN(" Version   : %d", 			mmt_signalling_message_header_and_payload->message_header.version);
		_SLS_MMTP_DUMPN(" Length    : %u", 			mmt_signalling_message_header_and_payload->message_header.length);
		_SLS_MMTP_DUMPN("+++++++++++++++++++++++++++++");
		_SLS_MMTP_DUMPN(" Payload   : %p", 			&mmt_signalling_message_header_and_payload->message_payload);
		_SLS_MMTP_DUMPN("+++++++++++++++++++++++++++++");


		if(mmt_signalling_message_header_and_payload->message_header.message_id == PA_message) {
			mmtp_signal_pa_dump(mmt_signalling_message_header_and_payload);
		} else if(mmt_signalling_message_header_and_payload->message_header.message_id >= MPI_message_start && mmt_signalling_message_header_and_payload->message_header.message_id <= MPI_message_end) {
			mmtp_signal_mpi_dump(mmt_signalling_message_header_and_payload);
		} else if(mmt_signalling_message_header_and_payload->message_header.message_id >= MPT_message_start && mmt_signalling_message_header_and_payload->message_header.message_id <= MPT_message_end) {
			mmtp_signal_mpt_dump(mmt_signalling_message_header_and_payload);
		} else if(mmt_signalling_message_header_and_payload->message_header.message_id == MMT_ATSC3_MESSAGE_ID) {
			mmtp_signal_atsc3_payload_dump(mmt_signalling_message_header_and_payload);
		}
	}
}

void mmtp_signal_packet_header_dump(mmtp_packet_header_t* mmtp_packet_header) {
	_SLS_MMTP_DUMPN("------------------------------------------------------");
	_SLS_MMTP_DUMPN("MMTP Packet Header: Signalling Message: ptr: %p", mmtp_packet_header);
	_SLS_MMTP_DUMPN("------------------------------------------------------");
	_SLS_MMTP_DUMPN(" packet version         : %-10d (0x%d%d)", 	mmtp_packet_header->mmtp_packet_version, ((mmtp_packet_header->mmtp_packet_version >> 1) & 0x1), mmtp_packet_header->mmtp_packet_version & 0x1);
	_SLS_MMTP_DUMPN(" payload_type           : %-10d (0x%d%d)", 	mmtp_packet_header->mmtp_payload_type, ((mmtp_packet_header->mmtp_payload_type >> 1) & 0x1), mmtp_packet_header->mmtp_payload_type & 0x1);
	_SLS_MMTP_DUMPN(" packet_id              : %-10hu (0x%04x)", 	mmtp_packet_header->mmtp_packet_id, mmtp_packet_header->mmtp_packet_id);
	_SLS_MMTP_DUMPN(" timestamp              : %-10u (0x%08x)",	mmtp_packet_header->mmtp_timestamp, mmtp_packet_header->mmtp_timestamp);
	_SLS_MMTP_DUMPN(" packet_sequence_number : %-10u (0x%08x)", 	mmtp_packet_header->packet_sequence_number,mmtp_packet_header->packet_sequence_number);
	_SLS_MMTP_DUMPN(" packet counter         : %-10u (0x%04x)", 	mmtp_packet_header->packet_counter, mmtp_packet_header->packet_counter);
	_SLS_MMTP_DUMPN("------------------------------------------------------");
}

void mmtp_signal_pa_dump(mmt_signalling_message_header_and_payload_t* mmt_signalling_message_header_and_payload) {
	_SLS_MMTP_DUMPN(" pa_message");
	_SLS_MMTP_DUMPN("      NOT IMPLEMENT     ");
	_SLS_MMTP_DUMPN("      NOT IMPLEMENT     ");
	_SLS_MMTP_DUMPN("      NOT IMPLEMENT     ");
	_SLS_MMTP_DUMPN("------------------------------------------------------");

}

void mmtp_signal_mpi_dump(mmt_signalling_message_header_and_payload_t* mmt_signalling_message_header_and_payload) {
	_SLS_MMTP_DUMPN(" mpi_message");
	_SLS_MMTP_DUMPN("      NOT IMPLEMENT     ");
	_SLS_MMTP_DUMPN("      NOT IMPLEMENT     ");
	_SLS_MMTP_DUMPN("      NOT IMPLEMENT     ");	
	_SLS_MMTP_DUMPN("------------------------------------------------------");

}

void mmtp_signal_mpt_dump(mmt_signalling_message_header_and_payload_t* mmt_signalling_message_header_and_payload) {
	_SLS_MMTP_DUMPN(" mpt_message");
	_SLS_MMTP_DUMPN("------------------------------------------------------");

	mp_table_t* mp_table = &mmt_signalling_message_header_and_payload->message_payload.mp_table;

	_SLS_MMTP_DUMPN(" table_id                    : %u", mp_table->table_id);
	_SLS_MMTP_DUMPN(" version                     : %u", mp_table->version);
	_SLS_MMTP_DUMPN(" length                      : %u", mp_table->length);
	_SLS_MMTP_DUMPN(" mp_table_mode               : %u", mp_table->mp_table_mode);
	_SLS_MMTP_DUMPN(" mmt_package_id.length:      : %u", mp_table->mmt_package_id.mmt_package_id_length);
	if(mp_table->mmt_package_id.mmt_package_id_length) {
		_SLS_MMTP_DUMPN(" mmt_package_id.val:       : %s", mp_table->mmt_package_id.mmt_package_id);
	}
	_SLS_MMTP_DUMPN(" mp_table_descriptors.length : %u", mp_table->mp_table_descriptors.mp_table_descriptors_length);
	if(mp_table->mp_table_descriptors.mp_table_descriptors_length) {
		_SLS_MMTP_DUMPN(" mp_table_descriptors.val    : %s", mp_table->mp_table_descriptors.mp_table_descriptors_byte);
	}
	_SLS_MMTP_DUMPN(" number_of_assets            : %u", mp_table->number_of_assets);

	for(int i=0; i < mp_table->number_of_assets; i++) {
		mp_table_asset_row_t* mp_table_asset_row = &mp_table->mp_table_asset_row[i];
		_SLS_MMTP_DUMPN(" asset identifier type       : %u", mp_table_asset_row->identifier_mapping.identifier_type);
		if(mp_table_asset_row->identifier_mapping.identifier_type == 0x00) {
			_SLS_MMTP_DUMPN(" asset id                    : %s", mp_table_asset_row->identifier_mapping.asset_id.asset_id);

		}
		_SLS_MMTP_DUMPN(" asset type                  : %s", mp_table_asset_row->asset_type);
		_SLS_MMTP_DUMPN(" asset_clock_relation_flag   : %u", mp_table_asset_row->asset_clock_relation_flag);
		_SLS_MMTP_DUMPN(" asset_clock_relation_id     : %u", mp_table_asset_row->asset_clock_relation_id);
		_SLS_MMTP_DUMPN(" asset_timescale_flag        : %u", mp_table_asset_row->asset_timescale_flag);
		_SLS_MMTP_DUMPN(" asset_timescale             : %u", mp_table_asset_row->asset_timescale);
		_SLS_MMTP_DUMPN(" location_count              : %u", mp_table_asset_row->location_count);
//		for(int j=0; j < mp_table_asset_row->location_count; j++) {
//
//		}
		_SLS_MMTP_DUMPN(" mmt_general_location_info location_type  : %u", mp_table_asset_row->mmt_general_location_info.location_type);
		_SLS_MMTP_DUMPN(" mmt_general_location_info pkt_id         : %u", mp_table_asset_row->mmt_general_location_info.packet_id);
		_SLS_MMTP_DUMPN(" mmt_general_location_info ipv4 src addr  : %u", mp_table_asset_row->mmt_general_location_info.ipv4_src_addr);
		_SLS_MMTP_DUMPN(" mmt_general_location_info ipv4 dest addr : %u", mp_table_asset_row->mmt_general_location_info.ipv4_dst_addr);
		_SLS_MMTP_DUMPN(" mmt_general_location_info ipv4 dest port : %u", mp_table_asset_row->mmt_general_location_info.dst_port);
		_SLS_MMTP_DUMPN(" mmt_general_location_info message id     : %u", mp_table_asset_row->mmt_general_location_info.message_id);

		//first entry
		_SLS_MMTP_DUMPN(" asset_descriptors_length                 : %u", mp_table_asset_row->asset_descriptors_length);
		if(mp_table_asset_row->asset_descriptors_length) {
            if(mp_table_asset_row->mmt_signalling_message_mpu_timestamp_descriptor) {
                for(int i=0; i < mp_table_asset_row->mmt_signalling_message_mpu_timestamp_descriptor->mpu_tuple_n; i++) {
                    _SLS_MMTP_DUMPN("   mpu_timestamp_descriptor %u, mpu_sequence_number: %u", i, mp_table_asset_row->mmt_signalling_message_mpu_timestamp_descriptor->mpu_tuple[i].mpu_sequence_number);
                    _SLS_MMTP_DUMPN("   mpu_timestamp_descriptor %u, mpu_presentation_time: %llu", i, mp_table_asset_row->mmt_signalling_message_mpu_timestamp_descriptor->mpu_tuple[i].mpu_presentation_time);
                }
            }
		}
	}

}

void mmtp_signal_atsc3_payload_dump(mmt_signalling_message_header_and_payload_t* mmt_signalling_message_header_and_payload) {

	mmt_atsc3_message_payload_t* mmt_atsc3_message_payload = &mmt_signalling_message_header_and_payload->message_payload.mmt_atsc3_message_payload;

	_SLS_MMTP_DUMPN("mmt_atsc3_message");
	_SLS_MMTP_DUMPN("------------------------------------------------------");
	_SLS_MMTP_DUMPN("service_id:                        %u", mmt_atsc3_message_payload->service_id);
	_SLS_MMTP_DUMPN("atsc3_message_content_type:        %u", mmt_atsc3_message_payload->atsc3_message_content_type);
	_SLS_MMTP_DUMPN("atsc3_message_content_version:     %u", mmt_atsc3_message_payload->atsc3_message_content_version);
	_SLS_MMTP_DUMPN("atsc3_message_content_compression: %u", mmt_atsc3_message_payload->atsc3_message_content_compression);
	_SLS_MMTP_DUMPN("URI_length:                        %u", mmt_atsc3_message_payload->URI_length);
	_SLS_MMTP_DUMPN("URI_payload:                       %s", mmt_atsc3_message_payload->URI_payload);
	if(mmt_atsc3_message_payload->atsc3_message_content_compression == 0x02) {
		_SLS_MMTP_DUMPN("atsc3_message_content_length_compressed:      %u", mmt_atsc3_message_payload->atsc3_message_content_length_compressed);
	}
	_SLS_MMTP_DUMPN("atsc3_message_content_length:      %u", mmt_atsc3_message_payload->atsc3_message_content_length);
	_SLS_MMTP_DUMPN("atsc3_message_content:             \n%s", mmt_atsc3_message_payload->atsc3_message_content);

}

void mmtp_mpu_packet_dump(mmtp_mpu_packet_t* mmtp_mpu_packet) {

	//dump mmtp packet header
	mmtp_mpu_packet_header_dump((mmtp_packet_header_t*)mmtp_mpu_packet);

	_SLS_MMTP_DUMPN("MPU mode ");
	_SLS_MMTP_DUMPN("------------------------------------------------------");
	/**
	 * dump si payload header fields
	 * 	uint8_t		si_fragmentation_indiciator; //2 bits,
		uint8_t		si_additional_length_header; //1 bit
		uint8_t		si_aggregation_flag; 		 //1 bit
		uint8_t		si_fragmentation_counter;    //8 bits
		uint16_t	si_aggregation_message_length;
	 */
	_SLS_MMTP_DUMPN(" length                       : %hu", mmtp_mpu_packet->data_unit_length);
	_SLS_MMTP_DUMPN(" mpu_fragment_type            : %d", mmtp_mpu_packet->mpu_fragment_type);
	_SLS_MMTP_DUMPN(" mpu_timed_flag               : %d", mmtp_mpu_packet->mpu_timed_flag);
	_SLS_MMTP_DUMPN(" mpu_fragmentation_indicator  : %d", mmtp_mpu_packet->mpu_fragmentation_indicator);
	_SLS_MMTP_DUMPN(" mpu_aggregation_flag         : %d", mmtp_mpu_packet->mpu_aggregation_flag);
	_SLS_MMTP_DUMPN(" mpu_fragment_counter         : %d", mmtp_mpu_packet->mpu_fragment_counter);
	_SLS_MMTP_DUMPN(" mpu_sequence_number          : %d", mmtp_mpu_packet->mpu_sequence_number);

	if (mmtp_mpu_packet->mpu_timed_flag) {
		_SLS_MMTP_DUMPN("mmt_mpu_packet (timed), packet: %p", mmtp_mpu_packet);
		_SLS_MMTP_DUMPN("-----------------");
		_SLS_MMTP_DUMPN(" mpu_fragment_type: %d", mmtp_mpu_packet->mpu_fragment_type);
		_SLS_MMTP_DUMPN(" mpu_fragmentation_indicator: %d", mmtp_mpu_packet->mpu_fragmentation_indicator);
		_SLS_MMTP_DUMPN(" movie_fragment_seq_num: %u", mmtp_mpu_packet->movie_fragment_sequence_number);
		_SLS_MMTP_DUMPN(" sample_num: %u", mmtp_mpu_packet->sample_number);
		_SLS_MMTP_DUMPN(" offset: %u", mmtp_mpu_packet->offset);
		_SLS_MMTP_DUMPN(" pri: %d", mmtp_mpu_packet->priority);
		_SLS_MMTP_DUMPN(" mpu_sequence_number: %u",mmtp_mpu_packet->mpu_sequence_number);
	}



}

void mmtp_mpu_packet_header_dump(mmtp_packet_header_t* mmtp_packet_header) {
	_SLS_MMTP_DUMPN("------------------------------------------------------");
	_SLS_MMTP_DUMPN("MMTP Packet Header: MPU mode: ptr: %p", mmtp_packet_header);
	_SLS_MMTP_DUMPN("------------------------------------------------------");
	_SLS_MMTP_DUMPN(" packet version         : %-10d (0x%d%d)", 	mmtp_packet_header->mmtp_packet_version, ((mmtp_packet_header->mmtp_packet_version >> 1) & 0x1), mmtp_packet_header->mmtp_packet_version & 0x1);
	_SLS_MMTP_DUMPN(" payload_type           : %-10d (0x%d%d)", 	mmtp_packet_header->mmtp_payload_type, ((mmtp_packet_header->mmtp_payload_type >> 1) & 0x1), mmtp_packet_header->mmtp_payload_type & 0x1);
	_SLS_MMTP_DUMPN(" packet_id              : %-10hu (0x%04x)", 	mmtp_packet_header->mmtp_packet_id, mmtp_packet_header->mmtp_packet_id);
	_SLS_MMTP_DUMPN(" timestamp              : %-10u (0x%08x)",	mmtp_packet_header->mmtp_timestamp, mmtp_packet_header->mmtp_timestamp);
	_SLS_MMTP_DUMPN(" packet_sequence_number : %-10u (0x%08x)", 	mmtp_packet_header->packet_sequence_number,mmtp_packet_header->packet_sequence_number);
	_SLS_MMTP_DUMPN(" packet counter         : %-10u (0x%04x)", 	mmtp_packet_header->packet_counter, mmtp_packet_header->packet_counter);
	_SLS_MMTP_DUMPN("------------------------------------------------------");
}

#endif //DUMP_ENABLE

