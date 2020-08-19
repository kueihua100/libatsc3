/*
 * atsc3_alc_utils.h
 *
 *  Created on: Feb 6, 2019
 *      Author: jjustman
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <inttypes.h>


#include "atsc3_utils.h"
#include "atsc3_alc_rx.h"
#include "atsc3_player_ffplay.h"
#include "atsc3_lls_types.h"
#include "atsc3_lls_sls_monitor_output_buffer.h"
#include "atsc3_route_sls_processor.h"


#ifndef ATSC3_ALC_UTILS_H_
#define ATSC3_ALC_UTILS_H_


#if defined (__cplusplus)
extern "C" {
#endif
  
extern int _ALC_UTILS_DEBUG_ENABLED;
extern int _ALC_UTILS_TRACE_ENABLED;

//zero out this slab of memory for a single TOI when pre-allocating
#define  __TO_PREALLOC_ZERO_SLAB_SIZE 8192000


//ALC dump object output path
#define __ALC_DUMP_OUTPUT_PATH__ "route/"
/**
 * deubg toi dump methods
 */


//this must be set to 1 for dumps to be written to disk
extern int _ALC_PACKET_DUMP_TO_OBJECT_ENABLED;

int atsc3_alc_packet_persist_to_toi_resource_process_sls_mbms_and_emit_callback(udp_flow_t* udp_flow, alc_packet_t** alc_packet_ptr, lls_sls_alc_monitor_t* lls_sls_alc_monitor);

char* alc_packet_dump_to_object_get_s_tsid_filename(udp_flow_t* udp_flow, alc_packet_t* alc_packet, lls_sls_alc_monitor_t* lls_sls_alc_monitor);
char* alc_packet_dump_to_object_get_temporary_filename(udp_flow_t* udp_flow, alc_packet_t* alc_packet);

FILE* alc_object_pre_allocate(char* file_name, alc_packet_t* alc_packet);
int alc_packet_write_fragment(FILE* f, char* file_name, uint32_t offset, alc_packet_t* alc_packet);
FILE* alc_object_open_or_pre_allocate(char* file_name, alc_packet_t* alc_packet);

void alc_recon_file_ptr_set_tsi_toi(FILE* file_ptr, uint32_t tsi, uint32_t toi_init);
char* alc_packet_dump_to_object_get_filename_tsi_toi(udp_flow_t* udp_flow, uint32_t tsi, uint32_t toi);

block_t* alc_get_payload_from_filename(char*);

void atsc3_alc_persist_route_ext_attributes_per_lls_sls_alc_monitor_essence(alc_packet_t* alc_packet, lls_sls_alc_monitor_t* lls_sls_alc_monitor);
void atsc3_alc_packet_check_monitor_flow_for_toi_wraparound_discontinuity(alc_packet_t* alc_packet, lls_sls_alc_monitor_t* lls_sls_alc_monitor);

//jjustman-2020-03-11
//deprecated - used for isobmff de-fragmentation to handoff a standalone media presentation unit from alc media fragment
void alc_recon_file_buffer_struct_set_tsi_toi(pipe_ffplay_buffer_t* pipe_ffplay_buffer, uint32_t tsi, uint32_t toi_init);
void alc_recon_file_ptr_fragment_with_init_box(FILE* output_file_ptr, udp_flow_t* udp_flow, alc_packet_t* alc_packet, uint32_t to_match_toi_init);
void alc_recon_file_buffer_struct_fragment_with_init_box(pipe_ffplay_buffer_t* pipe_ffplay_buffer, udp_flow_t* udp_flow, alc_packet_t* alc_packet);
void alc_recon_file_buffer_struct_monitor_fragment_with_init_box(udp_flow_t* udp_flow, alc_packet_t* alc_packet, lls_sls_alc_monitor_t* lls_slt_monitor);
void __alc_prepend_fragment_with_init_box(char* file_name, alc_packet_t* alc_packet);
void __alc_recon_fragment_with_init_box(char* file_name, alc_packet_t* alc_packet, uint32_t tsi, uint32_t toi_init, const char* to_write_filename);
//end deprecated

extern int _MEDIA_DUMP;
//pack distinct recovering files into one file
void dump_media_from_recover_file(udp_flow_t* udp_flow, alc_packet_t* alc_packet, lls_sls_alc_monitor_t* lls_sls_alc_monitor);
//pack media alc packet into one file
void dump_media_from_alc_packet(udp_flow_t* udp_flow, alc_packet_t* alc_packet, lls_sls_alc_monitor_t* lls_sls_alc_monitor);

#if defined (__cplusplus)
}
#endif

#define __ALC_UTILS_ERROR(...)   __LIBATSC3_TIMESTAMP_ERROR(__VA_ARGS__);
#define __ALC_UTILS_WARN(...)    __LIBATSC3_TIMESTAMP_WARN(__VA_ARGS__);
#define __ALC_UTILS_INFO(...)    __LIBATSC3_TIMESTAMP_INFO(__VA_ARGS__);

#define __ALC_UTILS_DEBUG(...)   if(_ALC_UTILS_DEBUG_ENABLED) { __LIBATSC3_TIMESTAMP_DEBUG(__VA_ARGS__); }
#define __ALC_UTILS_TRACE(...)   if(_ALC_UTILS_TRACE_ENABLED) { __LIBATSC3_TIMESTAMP_TRACE(__VA_ARGS__); }
#define __ALC_UTILS_IOTRACE(...) if(_ALC_UTILS_IOTRACE_ENABLED) { __LIBATSC3_TIMESTAMP_TRACE(__VA_ARGS__); }


#endif /* ATSC3_ALC_UTILS_H_ */
