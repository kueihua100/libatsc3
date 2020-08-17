
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <ncurses.h>
#include <limits.h>
#include <strings.h>

//#include "../bento4/ISOBMFFTrackJoiner.h"
#include "../atsc3_isobmff_tools.h"

#include "../atsc3_listener_udp.h"
#include "../atsc3_utils.h"

#include "../atsc3_lls.h"
#include "../atsc3_lls_alc_utils.h"

#include "../atsc3_lls_slt_parser.h"
#include "../atsc3_lls_sls_monitor_output_buffer_utils.h"

#include "../atsc3_mmtp_packet_types.h"
#include "../atsc3_mmtp_parser.h"
#include "../atsc3_mmtp_ntp32_to_pts.h"
#include "../atsc3_mmt_mpu_utils.h"
#include "../atsc3_mmt_reconstitution_from_media_sample.h"

#include "../atsc3_alc_rx.h"
#include "../atsc3_alc_utils.h"

//#include "../atsc3_bandwidth_statistics.h"
#include "../atsc3_packet_statistics.h"

//#include "../atsc3_output_statistics_ncurses.h"

#include "../atsc3_logging_externs.h"


#define _ENABLE_DEBUG true

//commandline stream filtering

uint32_t* dst_ip_addr_filter = NULL;
uint16_t* dst_ip_port_filter = NULL;
uint16_t* dst_packet_id_filter = NULL;

// lls and alc glue for slt, contains lls_table_slt and lls_slt_alc_session

lls_slt_monitor_t* lls_slt_monitor;

#if _PATCH_2_WORK_
atsc3_mmt_mfu_context_t* atsc3_mmt_mfu_context = NULL;

mmtp_flow_t* mmtp_flow;
lls_sls_mmt_monitor_t* lls_sls_mmt_monitor = NULL;

lls_sls_alc_monitor_t* lls_sls_alc_monitor = NULL;
#endif

udp_flow_latest_mpu_sequence_number_container_t* udp_flow_latest_mpu_sequence_number_container;

int route_processing(udp_packet_t *udp_packet)
{
    alc_packet_t* alc_packet = NULL;
    lls_sls_alc_session_t* matching_lls_slt_alc_session = NULL;
    int ret = -1;

    matching_lls_slt_alc_session = lls_slt_alc_session_find_from_udp_packet(
        lls_slt_monitor, udp_packet->udp_flow.src_ip_addr, 
        udp_packet->udp_flow.dst_ip_addr, udp_packet->udp_flow.dst_port);

    if (NULL == matching_lls_slt_alc_session) {
        __ERROR("Can't find matched lls_slt_alc_session!!");
        return ret;
    }
    
    if (lls_slt_monitor && (NULL == lls_slt_monitor->lls_sls_alc_monitor))
    {
        lls_sls_alc_monitor = lls_sls_alc_monitor_create();
        lls_sls_alc_monitor->lls_alc_session = matching_lls_slt_alc_session;
        lls_sls_alc_monitor->atsc3_lls_slt_service = matching_lls_slt_alc_session->atsc3_lls_slt_service;
        lls_sls_alc_monitor->lls_sls_monitor_output_buffer_mode.file_dump_enabled = true;
        lls_slt_monitor->lls_sls_alc_monitor = lls_sls_alc_monitor;
    }
   
    //process ALC streams
    int retval = alc_rx_analyze_packet_a331_compliant((char*)block_Get(udp_packet->data), block_Remaining_size(udp_packet->data), &alc_packet);
    if (!retval)
    {
        //check our alc_packet for a wrap-around TOI value, if it is a monitored TSI, and re-patch the MBMS MPD for updated availabilityStartTime and startNumber with last closed TOI values
        atsc3_alc_packet_check_monitor_flow_for_toi_wraparound_discontinuity(alc_packet, lls_slt_monitor->lls_sls_alc_monitor);

        //keep track of our EXT_FTI and update last_toi as needed for TOI length and manual set of the close_object flag
        atsc3_alc_persist_route_ext_attributes_per_lls_sls_alc_monitor_essence(alc_packet, lls_slt_monitor->lls_sls_alc_monitor);

        //persist to disk, process sls mbms and/or emit ROUTE media_delivery_event complete to the application tier if
        //the full packet has been recovered (e.g. no missing data units in the forward transmission)
        atsc3_alc_packet_persist_to_toi_resource_process_sls_mbms_and_emit_callback(
            &udp_packet->udp_flow, &alc_packet, lls_slt_monitor->lls_sls_alc_monitor);
    
#if (DUMP_ENABLE & MEDIA_DUMP)
        //pack distinct recovering files into one file
        //dump_media_from_recover_file(udp_flow, *alc_packet, lls_slt_monitor->lls_sls_alc_monitor);
        //pack media alc packet into one file
        dump_media_from_alc_packet(&udp_packet->udp_flow, alc_packet, lls_slt_monitor->lls_sls_alc_monitor);
#endif
        //free alc packet
        alc_packet_free(&alc_packet);

        ret = 0;
    }
    else
    {
        __ERROR("Err in alc_rx_analyze_packet_a331_compliant()!!");
    }

    return ret;
}

int mmtp_processing(udp_packet_t *udp_packet)
{
    mmtp_packet_header_t* mmtp_packet_header = NULL;
    lls_sls_mmt_session_t* matching_lls_slt_mmt_session = NULL;
    int ret = -1;

    matching_lls_slt_mmt_session = lls_slt_mmt_session_find_from_udp_packet(
        lls_slt_monitor, udp_packet->udp_flow.src_ip_addr,
        udp_packet->udp_flow.dst_ip_addr, udp_packet->udp_flow.dst_port);

    if (NULL == matching_lls_slt_mmt_session) {
        __ERROR("Can't find matched lls_slt_mmt_session!!");
        return ret;
    }

    __TRACE("data len: %d", udp_packet->data_length);

    if (lls_slt_monitor && (NULL == lls_slt_monitor->lls_sls_mmt_monitor))
    {
        lls_sls_mmt_monitor = lls_sls_mmt_monitor_create();
        lls_sls_mmt_monitor->lls_mmt_session = matching_lls_slt_mmt_session;
        lls_sls_mmt_monitor->atsc3_lls_slt_service = matching_lls_slt_mmt_session->atsc3_lls_slt_service;
        //lls_sls_mmt_monitor->video_packet_id = matching_lls_slt_mmt_session->video_packet_id;
        //lls_sls_mmt_monitor->audio_packet_id = matching_lls_slt_mmt_session->audio_packet_id;
        //lls_sls_mmt_monitor->lls_sls_monitor_output_buffer.has_written_init_box = false;
        lls_slt_monitor->lls_sls_mmt_monitor = lls_sls_mmt_monitor;
        lls_slt_monitor_add_lls_sls_mmt_monitor(lls_slt_monitor, lls_sls_mmt_monitor);

        atsc3_mmt_mfu_context = atsc3_mmt_mfu_context_new();
        atsc3_mmt_mfu_context->matching_lls_sls_mmt_session = matching_lls_slt_mmt_session;
        atsc3_mmt_mfu_context->lls_slt_monitor = lls_slt_monitor;

        mmtp_flow = mmtp_flow_new();
        atsc3_mmt_mfu_context->mmtp_flow = mmtp_flow;
        
        udp_flow_latest_mpu_sequence_number_container = udp_flow_latest_mpu_sequence_number_container_t_init();
        atsc3_mmt_mfu_context->udp_flow_latest_mpu_sequence_number_container = udp_flow_latest_mpu_sequence_number_container;
    }

    //parsing mmtp packet
    mmtp_packet_header = mmtp_packet_header_parse_from_block_t(udp_packet->data);

    if (NULL == mmtp_packet_header)
    {
        __ERROR("mmtp_packet_header is NULL!!");
        return ret;
    }

    if (mmtp_packet_header->mmtp_payload_type == 0x0)
    {
        mmtp_mpu_packet_t* mmtp_mpu_packet = mmtp_mpu_packet_parse_and_free_packet_header_from_block_t(&mmtp_packet_header, udp_packet->data);
        if (NULL == mmtp_mpu_packet) {
            __ERROR("mmtp_mpu_packet is NULL!!");
            goto cleanup;
        }

        //dump mmtp packet header
        //mmtp_packet_header_dump(mmtp_packet_header);

        if (mmtp_mpu_packet->mpu_timed_flag == 1)
        {
            //dump mpu header 
            mmtp_mpu_packet_dump(mmtp_mpu_packet);

            mmtp_mfu_process_from_payload_with_context(udp_packet, mmtp_mpu_packet, atsc3_mmt_mfu_context);

            atsc3_packet_statistics_mmt_stats_populate(udp_packet, mmtp_mpu_packet);
        }
        else
        {
            //non-timed
            __WARN("Non-timed payload: packet_id: %u", mmtp_packet_header->mmtp_packet_id);
        }

        if (mmtp_mpu_packet)
            mmtp_mpu_packet_free(&mmtp_mpu_packet);
    }
    else if (mmtp_packet_header->mmtp_payload_type == 0x2)
    {
        mmtp_signalling_packet_t* mmtp_signalling_packet = mmtp_signalling_packet_parse_and_free_packet_header_from_block_t(&mmtp_packet_header, udp_packet->data);

        if (NULL == mmtp_signalling_packet)
        {
            __ERROR("mmtp_signalling_packet is NULL!!");
            goto cleanup;
        }

        uint8_t parsed_count = mmt_signalling_message_parse_packet(mmtp_signalling_packet, udp_packet->data);

        if (parsed_count)
        {
            //dump signal packet
            mmtp_signal_packet_dump(mmtp_signalling_packet);

            __TRACE("process_packet: calling mmt_signalling_message_process_with_context with udp_packet: %p, mmtp_signalling_packet: %p, atsc3_mmt_mfu_context: %p,",
                    udp_packet, mmtp_signalling_packet, atsc3_mmt_mfu_context);

            //looks like call to the callback process functions that been inited at atsc3_mmt_mfu_context:
            mmt_signalling_message_process_with_context(udp_packet, mmtp_signalling_packet, atsc3_mmt_mfu_context);

            //TODO: jjustman-2019-10-03 - if signalling_packet == MP_table, set atsc3_mmt_mfu_context->mp_table_last;
            mmtp_asset_flow_t* mmtp_asset_flow = mmtp_flow_find_or_create_from_udp_packet(mmtp_flow, udp_packet);
            mmtp_asset_t* mmtp_asset = mmtp_asset_flow_find_or_create_asset_from_lls_sls_mmt_session(mmtp_asset_flow, atsc3_mmt_mfu_context->matching_lls_sls_mmt_session);
            
            //TODO: FIX ME!!! HACK - jjustman-2019-09-05
            mmtp_mpu_packet_t* mmtp_mpu_packet = mmtp_mpu_packet_new();
            mmtp_mpu_packet->mmtp_packet_id = mmtp_signalling_packet->mmtp_packet_id;
            
            mmtp_packet_id_packets_container_t* mmtp_packet_id_packets_container = mmtp_asset_find_or_create_packets_container_from_mmt_mpu_packet(mmtp_asset, mmtp_mpu_packet);
            mmtp_packet_id_packets_container_add_mmtp_signalling_packet(mmtp_packet_id_packets_container, mmtp_signalling_packet);
            
            //TODO: FIX ME!!! HACK - jjustman-2019-09-05
            mmtp_mpu_packet_free(&mmtp_mpu_packet);
            
            //update our sls_mmt_session info
            mmt_signalling_message_update_lls_sls_mmt_session(mmtp_signalling_packet, atsc3_mmt_mfu_context->matching_lls_sls_mmt_session);
            
            //TODO - remap this
            //add in flows              lls_sls_mmt_session_t* lls_sls_mmt_session = lls_slt_mmt_session_find_from_service_id(lls_slt_monitor, lls_sls_mmt_monitor->lls_mmt_session->service_id);
            
            if (lls_sls_mmt_monitor && lls_sls_mmt_monitor->lls_mmt_session && atsc3_mmt_mfu_context->matching_lls_sls_mmt_session)
            {
                __TRACE("mmt_signalling_information: from atsc3 service_id: %u, patching: seting audio_packet_id/video_packet_id/stpp_packet_id: %u, %u, %u",
                        atsc3_mmt_mfu_context->matching_lls_sls_mmt_session->atsc3_lls_slt_service->service_id,
                        atsc3_mmt_mfu_context->matching_lls_sls_mmt_session->audio_packet_id,
                        atsc3_mmt_mfu_context->matching_lls_sls_mmt_session->video_packet_id,
                        atsc3_mmt_mfu_context->matching_lls_sls_mmt_session->stpp_packet_id);
            
                if(atsc3_mmt_mfu_context->matching_lls_sls_mmt_session->audio_packet_id) {
                    lls_sls_mmt_monitor->audio_packet_id = atsc3_mmt_mfu_context->matching_lls_sls_mmt_session->audio_packet_id;
                }

                if(atsc3_mmt_mfu_context->matching_lls_sls_mmt_session->video_packet_id) {
                    lls_sls_mmt_monitor->video_packet_id = atsc3_mmt_mfu_context->matching_lls_sls_mmt_session->video_packet_id;
                }

                if(atsc3_mmt_mfu_context->matching_lls_sls_mmt_session->stpp_packet_id) {
                    lls_sls_mmt_monitor->stpp_packet_id = atsc3_mmt_mfu_context->matching_lls_sls_mmt_session->stpp_packet_id;
                }
            }

            //update ret
            ret = 0;
        }

        if (mmtp_signalling_packet)
            mmtp_signalling_packet_free(&mmtp_signalling_packet);
    }
    else
    {
        __WARN("Unknown mmtp_payload_type: 0x%x", mmtp_packet_header->mmtp_payload_type);
    }

cleanup:
    if (mmtp_packet_header)
        mmtp_packet_header_free(&mmtp_packet_header);

    return ret;
}


void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    //mmtp_packet_header_t* mmtp_packet_header = NULL;
    lls_sls_mmt_session_t* matching_lls_slt_mmt_session = NULL;

    //get udp packet
    udp_packet_t* udp_packet = process_packet_from_pcap(user, pkthdr, packet);

    if (!udp_packet) {
        __ERROR("process_packet_from_pcap() return error!!");
        return;
    }

    //skip mdNS packet
    if (udp_packet->udp_flow.dst_ip_addr == UDP_FILTER_MDNS_IP_ADDRESS && udp_packet->udp_flow.dst_port == UDP_FILTER_MDNS_PORT)
    {
        goto cleanup;
    }

    //check for LLS packet
    if (udp_packet->udp_flow.dst_ip_addr == LLS_DST_ADDR && udp_packet->udp_flow.dst_port == LLS_DST_PORT) {
        lls_table_t* lls_table = lls_table_create_or_update_from_lls_slt_monitor(lls_slt_monitor, udp_packet->data);
        
        if (lls_table) {
            if (lls_table->lls_table_id == SLT) {
                //capture SLT services into alc and mmt session flows
                lls_slt_table_perform_update(lls_table, lls_slt_monitor);
            }
        }

        goto cleanup;
    }

    //ROUTE (ALC) prcessing
    route_processing(udp_packet);

    //MMTP processing
    mmtp_processing(udp_packet);
    
cleanup:
	if (udp_packet)
        udp_packet_free(&udp_packet);

    return;
}


void* pcap_loop_run_thread(void* file_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;
    bpf_u_int32 maskp;
    bpf_u_int32 netp;

    descr = pcap_open_offline((char*)file_name, errbuf);

    if (descr == NULL) {
        printf("Failed at pcap_open_offline(): %s", errbuf);
        exit(1);
    }

    char filter[] = "udp";
    if (pcap_compile(descr, &fp, filter, 0, netp) == -1) {
        fprintf(stderr,"Error calling pcap_compile");
        exit(1);
    }

    if (pcap_setfilter(descr, &fp) == -1) {
        fprintf(stderr,"Error setting filter");
        exit(1);
    }

    pcap_loop(descr, -1, process_packet, NULL);

    return 0;
}


void dbg_flag_and_data_init()
{
    //to turn needed debug flags here
    _LLS_INFO_ENABLED  = 1;
    _LLS_DEBUG_ENABLED = 1;
    _LLS_TRACE_ENABLED = 1;

    _LLS_SLT_PARSER_INFO_ENABLED = 1;
    _LLS_SLT_PARSER_INFO_MMT_ENABLED = 1;
    _LLS_SLT_PARSER_INFO_ROUTE_ENABLED = 1;

    _LLS_SLT_PARSER_DEBUG_ENABLED = 1;
    _LLS_SLT_PARSER_TRACE_ENABLED = 1;

    _ALC_RX_DEBUG_ENABLED = 1;
    _ALC_RX_TRACE_ENABLED = 1;
    _ALC_RX_TRACE_TAB_ENABLED = 1;

    _LLS_ALC_UTILS_INFO_ENABLED = 1;
    _LLS_ALC_UTILS_DEBUG_ENABLED = 1;
    _LLS_ALC_UTILS_TRACE_ENABLED = 1;

    _LLS_MMT_UTILS_INFO_ENABLED = 1;
    _LLS_MMT_UTILS_DEBUG_ENABLED = 1;
    _LLS_MMT_UTILS_TRACE_ENABLED = 1;

    _MMT_SIGNALLING_MESSAGE_DEBUG_ENABLED = 1;
    _MMT_SIGNALLING_MESSAGE_TRACE_ENABLED = 1;

    //enable flag to dump lls/sls table
    _LLS_DUMP_ENABLED  = 1; //dump lls tables to lls.dump

    //global variables initial
    lls_slt_monitor = lls_slt_monitor_create();

    return;
}

int main(int argc,char **argv)
{
    char *file_name;
    if(argc == 2) {
        file_name = argv[1];
        __INFO("reading the file: %s", file_name);
    } else {
        println("----------------------------------------------------");
        println(" !!! ERROR !!!");
        println("Please specify a pcap/alp file as input argument!!");
        println("----------------------------------------------------");

        exit(1);
    }

    //set debug flag and global variables init
    dbg_flag_and_data_init();

    //run pcap thread:
    pthread_t global_pcap_thread_id;
    int pcap_ret = pthread_create(&global_pcap_thread_id, NULL, pcap_loop_run_thread, (void*)file_name);
    assert(!pcap_ret);

    pthread_join(global_pcap_thread_id, NULL);

    return 0;
}


