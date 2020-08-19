/*
 * atsc3_alc_utils.c
 *
 *  Created on: Feb 6, 2019
 *      Author: jjustman
 *
 *	< https://tools.ietf.org/html/rfc5775 >
 *      4.4.  Receiver Operation

   The receiver operation, when using ALC, includes all the points made
   about the receiver operation when using the LCT building block
   [RFC5651], the FEC building block [RFC5052], and the multiple rate
   congestion control building block.

   To be able to participate in a session, a receiver needs to obtain
   the required Session Description as listed in Section 2.4.  How
   receivers obtain a Session Description is outside the scope of this
   document.

   As described in Section 2.3, a receiver needs to obtain the required
   FEC Object Transmission Information for each object for which the
   receiver receives and processes packets.




Luby, et al.                 Standards Track                   [Page 15]

RFC 5775               ALC Protocol Instantiation             April 2010


   Upon receipt of each packet, the receiver proceeds with the following
   steps in the order listed.

   1.  The receiver MUST parse the packet header and verify that it is a
       valid header.  If it is not valid, then the packet MUST be
       discarded without further processing.

   2.  The receiver MUST verify that the sender IP address together with
       the TSI carried in the header matches one of the (sender IP
       address, TSI) pairs that was received in a Session Description
       and to which the receiver is currently joined.  If there is not a
       match, then the packet MUST be silently discarded without further
       processing.  The remaining steps are performed within the scope
       of the (sender IP address, TSI) session of the received packet.

   3.  The receiver MUST process and act on the CCI field in accordance
       with the multiple rate congestion control building block.

   4.  If more than one object is carried in the session, the receiver
       MUST verify that the TOI carried in the LCT header is valid.  If
       the TOI is not valid, the packet MUST be discarded without
       further processing.

   5.  The receiver SHOULD process the remainder of the packet,
       including interpreting the other header fields appropriately, and
       using the FEC Payload ID and the encoding symbol(s) in the
       payload to reconstruct the corresponding object.

   It is RECOMMENDED that packet authentication be used.  If packet
   authentication is used, then it is RECOMMENDED that the receiver
   immediately check the authenticity of a packet before proceeding with
   step (3) above.  If immediate checking is possible and if the packet
   fails the check, then the receiver MUST silently discard the packet.
 */

#include "atsc3_alc_utils.h"

#include "atsc3_lls_sls_monitor_output_buffer_utils.h"
//shortcut hack
#include "atsc3_isobmff_tools.h"

int _ALC_UTILS_DEBUG_ENABLED=0;
int _ALC_UTILS_TRACE_ENABLED=0;
int _ALC_UTILS_IOTRACE_ENABLED=0;

bool __ALC_RECON_FILE_PTR_HAS_WRITTEN_INIT_BOX = false;

pipe_ffplay_buffer_t* __ALC_RECON_FILE_BUFFER_STRUCT = NULL;
uint32_t* __ALC_RECON_FILE_PTR_TSI = NULL;
uint32_t* __ALC_RECON_FILE_PTR_TOI_INIT = NULL;

FILE* __ALC_RECON_FILE_PTR = NULL; //deprecated

block_t* alc_get_payload_from_filename(char* file_name) {
	if( access(file_name, F_OK ) == -1 ) {
		__ALC_UTILS_ERROR("alc_get_payload_from_filename: unable to open file: %s", file_name);
		return NULL;
	}

	struct stat st;
	stat(file_name, &st);

	//uint8_t* payload = (uint8_t*)calloc(st.st_size, sizeof(uint8_t));
	block_t* payload = block_Alloc(st.st_size);

	FILE* fp = fopen(file_name, "r");
	if(!fp || st.st_size == 0) {
		__ALC_UTILS_ERROR("alc_get_payload_from_filename: size: 0 file: %s", file_name);
		return NULL;
	}

	fread(payload->p_buffer, st.st_size, 1, fp);
	payload->i_pos = st.st_size;
	fclose(fp);

	return payload;

}

/* jjustman-2019-09-17: TODO - free temporary filename when done */

char* alc_packet_dump_to_object_get_temporary_recovering_filename(udp_flow_t *udp_flow, alc_packet_t *alc_packet) {
	char* temporary_file_name = (char *)calloc(255, sizeof(char));
	if(alc_packet->def_lct_hdr) {
		snprintf(temporary_file_name, 255, "%s%u.%u.%u.%u.%u.%u-%u.recovering",
			__ALC_DUMP_OUTPUT_PATH__,
			__toipandportnonstruct(udp_flow->dst_ip_addr, udp_flow->dst_port),
			alc_packet->def_lct_hdr->tsi,
			alc_packet->def_lct_hdr->toi);
	}

	return temporary_file_name;
}


/* jjustman-2019-09-17: TODO - free temporary filename when done */
char* alc_packet_dump_to_object_get_filename_tsi_toi(udp_flow_t* udp_flow, uint32_t tsi, uint32_t toi) {
    char* temporary_file_name = (char *)calloc(255, sizeof(char));
    snprintf(temporary_file_name, 255, "%s%u.%u.%u.%u.%u.%u-%u",
             __ALC_DUMP_OUTPUT_PATH__,
             __toipandportnonstruct(udp_flow->dst_ip_addr, udp_flow->dst_port),
             tsi,
             toi);
    
    return temporary_file_name;
}


/**
 * todo:
 * 	write out header metadata for future app-cache use cases
 *
 *				Content-Location="sgdd.xml"
 * 				Transfer-Length="21595"
                Content-Length="450384"
                Content-Type="application/vnd.oma.bcast.sgdd+xml"
                Content-Encoding="gzip"

and for ATSC A/344:2019 ATSC 3.0 Interactive Content use cases, extend this path mapping with:

		FDT-Instance@appContextIdList

...ESG files available through its HTTP server. The Broadcaster Application should make no assumptions regarding the URL path and simply use it to access the fragment data directly.

The referenced service guide files, in this example, Service.xml, Schedule.xml and Content.xml, shall contain the Service, Schedule and Content XML fragments as described in A/332 [2], respectively.
The Receiver shall extract each XML fragment from the binary SGDU structure before making it available to the Broadcaster Application.
To associate ESG files with Broadcaster Applications, the corresponding Application Context Identifiers shall be provided in the Extended FDT (EFDT) element,
< FDT-Instance@appContextIdList > defined when sending the ESG files in the LCT channel of the ESG Service ROUTE session. Descriptions of the FDT extensions and the ESG Service can be found in A/331 [1].

Application Context Identifiers need not be included in the EFDT if the ESG data is not needed by the Broadcaster Application.
 *
 *
 *
A.3.3.2.6. Extended FDT Instance Semantics
 * *
 *
 *The Extended FDT Instance shall conform to an FDT Instance according to RFC 6726 [30], with the following rules.
 ??At least one File element must be present, with the following additional constraints:
 *
 o When exactly one File element is present in an Extended FDT Instance that is embedded in the S-TSID, and the Extended FDT Instance describes DASH Segments as the delivery objects carried by a source flow, that File element will strictly contain the metadata for the Initialization Segment. In other words, no File element instances
 are present for the purpose of describing Media Segments.
 *
 o When more than one File element is present in an Extended FDT Instance that is  embedded in the S-TSID, and the
 * Extended FDT Instance describes NRT content files as the delivery objects carried by a source flow, each of those
 * File elements will contain the metadata for an individual NRT file.
 *
 o When more than one File element is present in an Extended FDT Instance that is transported as TOI=0 in the same
 * LCT channel carrying the associated source flow, the delivery objects transported by the source flow are NRT content
 * files whereby each of those File elements will contain the metadata for an individual NRT file.
 *
 ??The @Expires attribute must be present.
 
 When a @fileTemplate attribute is present, then the sender shall operate as follows:
 ??The TOI field in the ROUTE packet header shall be set such that Content-Location can be derived according to Section A.3.3.2.7.
 ??After sending the first packet with a given TOI value, none of the packets pertaining to this TOI shall be sent later
 * than the wall clock time as derived from @maxExpiresDelta.
 *
 * In addition, the EXT_TIME header with Expected Residual Time (ERT) may be used in order to convey more accurate expiry time,
 * if considered useful. When @maxExpiresDelta is not present, then the EXT_TIME header with Expected Residual Time (ERT)
 * shall be used to derive the value of FDT-Instance@Expires, according to the procedure described below in Section A.3.3.2.7.
 
 When a @fileTemplate attribute is present, an Extended FDT Instance is produced at the receiver as follows:
 ??Any data that is contained in the EFDT may be used as is in generating an Extended FDT Instance.
 ??The data in the @fileTemplate attribute is used to generate the file URI (equivalent to the File@Content-Location in the FDT)
 * as documented in Section A.3.3.2.7 with the reception of an LCT packet with a specific TOI value.
 *
 *
 * A.3.3.2.7. File Template
  When an LCT packet with a new TOI is received for this transport session, then an Extended FDT Instance is
 generated with a new File entry as follows:
 
 ??The TOI is used to generate File@Content-Location using the mechanism defined in Section A.3.3.2.8.
 ??All other attributes that are present in the EFDT.FDT-Instance element are applicable to the File.
 ??Either the EXT_FTI header (per RFC 5775 [27]) or the EXT_TOL header (per Section A.3.8.1), when present,
    shall be used to signal the Transport Object Length (TOL) of the File.
 *
 * If the File@Transfer-Length parameter in the Extended FDT Instance is not present,
 * then the EXT_TOL header or the or EXT_FTI header shall be present.
 *
 * Note that a header containing the transport object length (EXT_TOL or EXT_FTI) need not be present in each packet header.
 *
 * If the broadcaster does not know the length of the transport object at the beginning of the transfer,
 * an EXT_TOL or EXT_FTI header shall be included in at least the last packet of the file and should be included in the last
 * few packets of the transfer.
 *
 ??When present, the @maxExpiresDelta shall be used to generate the value of the FDT- Instance@Expires attribute.
 * The receiver is expected to add this value to its wall clock time when acquiring the first ROUTE packet carrying the
 * data of a given delivery object to obtain the value for @Expires.
 *
 * When @maxExpiresDelta is not present, the* EXT_TIME header with Expected Residual Time (ERT) shall be used to derive the
 * expiry time of the Extended FDT Instance.
 *
 * When both @maxExpiresDelta and the ERT of EXT_TIME are present, the smaller of the two values should be used as the
 * incremental time interval to be added to the receiver?�s current time to generate the effective value for @Expires.
 *
 * When neither @maxExpiresDelta nor the ERT field of the EXT_TIME header is present, then the expiration time of the
 * Extended FDT Instance is given by its @Expires attribute.

 A.3.3.2.8. Substitution
 The @fileTemplate attribute, when present, shall include the ??TOI$??identifier.
 After parameter substitution using the TOI number in this transport session, the
 @fileTemplate shall be a valid URL corresponding to the Content-Location attribute of the associated file.
 Excluding the TOI values associated with any files listed in FDT-Instance.File elements, the
 @fileTemplate attribute generates a one-to-one mapping between the TOI and the Content-Location value.
 When the @fileTemplate is used to identify a sequence of DASH Media Segments, the Segment number is equal to the TOI value
 
 In each URI, the identifiers from Table A.3.5 shall be replaced by the substitution parameter defined in Table A.3.5.
 
 Identifier matching is case-sensitive. If the URI contains unescaped $ symbols which do not enclose a valid identifier,
 then the result of URI formation is undefined.
 
 The format of the identifier is also specified in Table A.3.5.
 
 Each identifier may be suffixed, within the enclosing ????characters following this prototype:
    %0[width]d
 
 The width parameter is an unsigned integer that provides the minimum number of characters to be printed.
 If the value to be printed is shorter than this number, the result shall be padded with leading zeroes.
 The value is not truncated even if the result is larger.
 *
 An example @fileTemplate using a width of 5 is: fileTemplate="myVideo$TOI%05d$.mps",
 resulting in file names with exactly five digits in the number portion.
 
 The Media Segment file name for TOI=33 using this template is myVideo00033.mps.
 
 The @fileTemplate shall be authored such that the application of the substitution process results in valid URIs.
 Strings outside identifiers shall only contain characters that are permitted within URIs according to RFC 3986 [19].
 *
 *
    Table A.3.5 Identifiers for File Templates
    ----------------------------------------------------------------------------------
    $<Identifier>$           Substitution Parameter                             Format
    --------------           ------------------------------------------------   ------
    $$                       Is an escape sequence, i.e. "$$" is non-           not applicable
                             recursively replaced with a single "$"

    $TOI$                    This identifier is substituted with the TOI.       The format tag may be present.
                                                                                When no format tag is present, a default format
                                                                                tag with width=1 shall be used.
    
 *
 *TODO: check codepoint if we are in entity mode...
 */

char* alc_packet_dump_to_object_get_s_tsid_filename(udp_flow_t* udp_flow, alc_packet_t* alc_packet, lls_sls_alc_monitor_t* lls_sls_alc_monitor) {

	//jjustman-2019-09-07: TODO: expand context for application cache and header attributes for object caching
	char* content_location = NULL;
	char* content_type = NULL;
	char* content_encoding = NULL;
	uint32_t content_length;
	uint32_t transfer_length;

	if(lls_sls_alc_monitor->atsc3_sls_metadata_fragments && lls_sls_alc_monitor->atsc3_sls_metadata_fragments->atsc3_route_s_tsid && lls_sls_alc_monitor->atsc3_sls_metadata_fragments->atsc3_route_s_tsid->atsc3_route_s_tsid_RS_v.count) {
		for(int i=0; i < lls_sls_alc_monitor->atsc3_sls_metadata_fragments->atsc3_route_s_tsid->atsc3_route_s_tsid_RS_v.count; i++) {
			atsc3_route_s_tsid_RS_t* atsc3_route_s_tsid_RS = lls_sls_alc_monitor->atsc3_sls_metadata_fragments->atsc3_route_s_tsid->atsc3_route_s_tsid_RS_v.data[i];

			if(atsc3_route_s_tsid_RS->dest_ip_addr == udp_flow->dst_ip_addr && atsc3_route_s_tsid_RS->dest_port == udp_flow->dst_port && atsc3_route_s_tsid_RS->atsc3_route_s_tsid_RS_LS_v.count) {
				for(int j=0; j < atsc3_route_s_tsid_RS->atsc3_route_s_tsid_RS_LS_v.count; j++) {
					atsc3_route_s_tsid_RS_LS_t* atsc3_route_s_tsid_RS_LS = atsc3_route_s_tsid_RS->atsc3_route_s_tsid_RS_LS_v.data[j];

					if(atsc3_route_s_tsid_RS_LS->tsi == alc_packet->def_lct_hdr->tsi && atsc3_route_s_tsid_RS_LS->atsc3_route_s_tsid_RS_LS_SrcFlow) {
					    //Assume SrcFlow_Payload.format_id == 1 for file mode:

					    if(atsc3_route_s_tsid_RS_LS->atsc3_route_s_tsid_RS_LS_SrcFlow->atsc3_route_s_tsid_RS_LS_SrcFlow_Payload->format_id != 2) {
                            //try to find our matching toi and content-location value
                            if(atsc3_route_s_tsid_RS_LS->atsc3_route_s_tsid_RS_LS_SrcFlow->atsc3_fdt_instance && atsc3_route_s_tsid_RS_LS->atsc3_route_s_tsid_RS_LS_SrcFlow->atsc3_fdt_instance->atsc3_fdt_file_v.count) {
                                atsc3_fdt_instance_t* atsc3_fdt_instance = atsc3_route_s_tsid_RS_LS->atsc3_route_s_tsid_RS_LS_SrcFlow->atsc3_fdt_instance;
                                for(int k=0; k < atsc3_fdt_instance->atsc3_fdt_file_v.count; k++) {
                                    atsc3_fdt_file_t* atsc3_fdt_file = atsc3_fdt_instance->atsc3_fdt_file_v.data[k];

                                    //if not in entity mode, and toi matches, then use this mapping, otherwise, fallback to file_template
                                    if(atsc3_fdt_file->toi == alc_packet->def_lct_hdr->toi && atsc3_fdt_file->content_location && strlen(atsc3_fdt_file->content_location)) {
                                        size_t content_location_length = strlen(atsc3_fdt_file->content_location);
                                        content_location = calloc(content_location_length + 1, sizeof(char));
                                        strncpy(content_location, atsc3_fdt_file->content_location, content_location_length);

                                        //TODO: jjustman-2019-09-18 -  apply mappings from FLUTE to HTTP object caching here
    //                                    atsc3_fdt_file->content_type;
    //                                    atsc3_fdt_file->content_length;
    //                                    atsc3_fdt_file->content_encoding;
    //                                    atsc3_fdt_file->transfer_length;

                                    }
                                }

                                if(!content_location) {
                                    //fallback to instance template
                                    if(atsc3_fdt_instance->file_template) {
                                        int file_template_strlen = strlen(atsc3_fdt_instance->file_template);
                                        char intermediate_file_name[1025] = { 0 }; //include null padding
                                        int intermediate_pos = 0;
                                        char* final_file_name = calloc(1025, sizeof(char));

                                        //replace $$ to $
                                        //replace $TOI$ (and width formatting, e.g. $TOI%05d$) with our TOI
                                        for(int i=0; i < file_template_strlen && i < 1024; i++) {
                                            if(atsc3_fdt_instance->file_template[i] == '$') {
                                                if(atsc3_fdt_instance->file_template[i+1] == '$') {
                                                    //escape
                                                    intermediate_file_name[intermediate_pos++] = '$';
                                                    i++;
                                                } else if(i+4 < file_template_strlen &&
                                                          atsc3_fdt_instance->file_template[i+1] == 'T' &&
                                                          atsc3_fdt_instance->file_template[i+2] == 'O' &&
                                                          atsc3_fdt_instance->file_template[i+3] == 'I') { //next 3 chars should be TOI at least
                                                    if(atsc3_fdt_instance->file_template[i+4] == '$') {
                                                        //close out with just a %d value
                                                        intermediate_file_name[intermediate_pos++] = '%';
                                                        intermediate_file_name[intermediate_pos++] = 'd';
                                                        i += 4;
                                                        __ALC_UTILS_DEBUG("intermediate file template name after TOI property substituion is: %s", intermediate_file_name);

                                                    } else if(atsc3_fdt_instance->file_template[i+4] == '%') {
                                                        i += 4;
                                                        //copy over our formatting until we get to a $
                                                        //e.g. myVideo$TOI%05d$.mps
                                                        while(i < file_template_strlen && atsc3_fdt_instance->file_template[i] != '$') {
                                                            intermediate_file_name[intermediate_pos++] = atsc3_fdt_instance->file_template[i++];
                                                        }
                                                        __ALC_UTILS_DEBUG("intermediate file template name after TOI width substitution is: %s", intermediate_file_name);

                                                    } else {
                                                        __ALC_UTILS_WARN("file template name at pos: %d doesn't match template value of TOI: %s, ignoring...", i, atsc3_fdt_instance->file_template);
                                                    }
                                                } else {
                                                    __ALC_UTILS_WARN("file template name at pos: %d doesn't match template value of TOI: %s, ignoring...", i, atsc3_fdt_instance->file_template);
                                                }
                                            } else {
                                                intermediate_file_name[intermediate_pos++] = atsc3_fdt_instance->file_template[i];
                                            }
                                        }

                                        //perform final replacement
                                        snprintf(final_file_name, 1024, intermediate_file_name, alc_packet->def_lct_hdr->toi);
                                        content_location = final_file_name;
                                        __ALC_UTILS_DEBUG("final file template name after TOI substitution is: %s", content_location);
                                        if(alc_packet->def_lct_hdr->tsi == lls_sls_alc_monitor->audio_tsi) {
                                           lls_sls_alc_monitor->last_closed_audio_toi = alc_packet->def_lct_hdr->toi;
                                        } else if(alc_packet->def_lct_hdr->tsi == lls_sls_alc_monitor->video_tsi) {
                                           lls_sls_alc_monitor->last_closed_video_toi = alc_packet->def_lct_hdr->toi;
                                        } else if(alc_packet->def_lct_hdr->tsi == lls_sls_alc_monitor->text_tsi) {
                                            lls_sls_alc_monitor->last_closed_text_toi = alc_packet->def_lct_hdr->toi;
                                        }
                                    }
                                }
                            }
					    }

						if(!content_location) {
                            //alternative strategies for content-location here?

						    //assume entity or package mode delivery here...
						    if(atsc3_route_s_tsid_RS_LS->atsc3_route_s_tsid_RS_LS_SrcFlow->atsc3_route_s_tsid_RS_LS_SrcFlow_Payload) {
                                __ALC_UTILS_DEBUG("processing ALC MDE as delivery object format id: %d", atsc3_route_s_tsid_RS_LS->atsc3_route_s_tsid_RS_LS_SrcFlow->atsc3_route_s_tsid_RS_LS_SrcFlow_Payload->format_id);

                                if(atsc3_route_s_tsid_RS_LS->atsc3_route_s_tsid_RS_LS_SrcFlow->atsc3_route_s_tsid_RS_LS_SrcFlow_Payload->format_id == 2) {
                                    //extract out our content_location from the ALC payload headers here
                                    char* temp_content_location = alc_packet_dump_to_object_get_temporary_recovering_filename(udp_flow, alc_packet);

                                    struct stat st;
                                    stat(temp_content_location, &st);

                                    //jjustman-2020-01-16 - parse first block of rfc 7231 headers...
                                    char* temp_content_header = calloc(8193, sizeof(char)); //over-allocate for null pad at end
                                    FILE* temp_fp = fopen(temp_content_location, "r+");
                                    if(temp_fp) {
                                        //jjustman-2020-01-16 - refactor me to proper RFC 7231 header handling
                                        int read_len = fread(temp_content_header, 1, 8192, temp_fp); //try and get actual bytes read just in case
                                        //"content-location: "
                                        // 12345678901234567 = 18 bytes (w/ whitespace?)

                                        char* location_found = strcasestr(temp_content_header, "content-location: ");

                                        if(location_found) {
                                            location_found += 18; //move us forward 18 bytes for content-location: literal
                                            //find newline char (either 0x0d|0x0a)
                                            char* endofline = NULL;
                                            int pos = 0;
                                            while(true) {
                                                if(!location_found[pos]) {
                                                    __ALC_UTILS_DEBUG("ALC MDE: no content-location found after pos: %d", pos);

                                                    break;
                                                } else if(location_found[pos] == 0x0d || location_found[pos] == 0x0a) {
                                                    endofline = location_found + (pos-1);
                                                    content_location = strndup(location_found, pos);
                                                    __ALC_UTILS_DEBUG("ALC MDE: local entity mode filename is: %s", content_location);

                                                    bool has_additional_headers = false;
                                                    int newline_count = 1;
                                                    while(true) {
                                                        pos++;

                                                        //now we need to chomp off the remaining entity header(s) until we get to an empty newline
                                                        //happy path
                                                        if(location_found[pos] == 0x0d || location_found[pos] == 0x0a) {
                                                            newline_count++;
                                                            if(newline_count > 3) {
                                                                pos++; //and get rid of our last linebreak..
                                                                //break out and trim our file
                                                                int trim_size = (location_found + pos) - temp_content_header;
                                                                int new_mde_payload_size = st.st_size - trim_size;
                                                                __ALC_UTILS_INFO("ALC MDE: entity mode, original size: %d, header cut is: %d bytes, new mde size is: %d", st.st_size, trim_size, new_mde_payload_size);

                                                                if(trim_size > 0 && new_mde_payload_size > 0) {
                                                                    uint8_t* to_trim_payload = calloc(new_mde_payload_size, sizeof(uint8_t));

                                                                    fseek(temp_fp, trim_size, SEEK_SET);
                                                                    fread(to_trim_payload, new_mde_payload_size, 1, temp_fp);
                                                                    int ret = ftruncate(fileno(temp_fp), new_mde_payload_size);
                                                                    //printf("ftruncate for fd: %d, ret is: %d", fileno(temp_fp), ret);
                                                                    fsync(fileno(temp_fp));
                                                                    fseek(temp_fp, 0, SEEK_SET);
                                                                    fwrite(to_trim_payload, new_mde_payload_size, 1, temp_fp);
                                                                   /* for(int i=0; i < 32; i++) {
                                                                        printf("to_trim_payload[%d]: 0x%02x (%c)", i, to_trim_payload[i], to_trim_payload[i]);
                                                                    }*/

                                                                    fsync(fileno(temp_fp));

                                                                    free(to_trim_payload);
                                                                    to_trim_payload = NULL;

                                                                    //mark this toi as close
                                                                    if(alc_packet->def_lct_hdr->tsi == lls_sls_alc_monitor->audio_tsi) {
                                                                        lls_sls_alc_monitor->last_closed_audio_toi = alc_packet->def_lct_hdr->toi;
                                                                    } else if(alc_packet->def_lct_hdr->tsi == lls_sls_alc_monitor->video_tsi) {
                                                                        lls_sls_alc_monitor->last_closed_video_toi = alc_packet->def_lct_hdr->toi;
                                                                    }
                                                                    break; //done
                                                                }
                                                            }
                                                        } else {
                                                            has_additional_headers = true;
                                                            newline_count = 0;
                                                        }
                                                    }



                                                    break;
                                                }
                                                pos++;
                                            }
                                        }
                                    }

                                    if(temp_fp) {
                                        fclose(temp_fp);
                                        temp_fp = NULL;
                                    }
                                    if(temp_content_location) {
                                        free(temp_content_location);
                                        temp_content_location = NULL;
                                    }
                                    if(temp_content_header) {
                                        free(temp_content_header);
                                        temp_content_header = NULL;
                                    }
                                }

						    } else {
                                __ALC_UTILS_WARN("processing ALC MDE - but no atsc3_route_s_tsid_RS_LS_SrcFlow_Payload!");

                            }
						}
					}
				}
			}
		}
	}

	if(!content_location) {
		if(alc_packet->def_lct_hdr) {
            content_location = alc_packet_dump_to_object_get_filename_tsi_toi(udp_flow, alc_packet->def_lct_hdr->tsi, alc_packet->def_lct_hdr->toi);
			__ALC_UTILS_INFO("alc_packet_dump_to_object_get_s_tsid_filename: no content_location to return for alc_packet: %p, falling back to %s", alc_packet, content_location);
		} else {
			__ALC_UTILS_ERROR("alc_packet_dump_to_object_get_s_tsid_filename: no content_location to return for alc_packet: %p, falling back to null string!", alc_packet);
		}
	}

	return content_location;
}

//todo - build this in memory first...

FILE* alc_object_open_or_pre_allocate(char* file_name, alc_packet_t* alc_packet) {
    if( access( file_name, F_OK ) != -1 ) {
        FILE* f = fopen(file_name, "r+");
        if(f) {
            return f;
        }
    }
    
    //otherwise, pre_allocate this object
    return alc_object_pre_allocate(file_name, alc_packet);
    
}

//nothing to see here...
uint8_t* __TO_PREALLOC_ZERO_SLAB_PTR = NULL;
FILE* alc_object_pre_allocate(char* file_name, alc_packet_t* alc_packet) {
	if(!__TO_PREALLOC_ZERO_SLAB_PTR) {
		__TO_PREALLOC_ZERO_SLAB_PTR = (uint8_t*)malloc(__TO_PREALLOC_ZERO_SLAB_SIZE);
		memset(__TO_PREALLOC_ZERO_SLAB_PTR, 0, __TO_PREALLOC_ZERO_SLAB_SIZE);
	}

    if( access( file_name, F_OK ) != -1 ) {
    	__ALC_UTILS_IOTRACE("pre_allocate: file %s exists, removing", file_name);
        //__ALC_UTILS_WARN("pre_allocate: file %s exists, removing", file_name);
        // file exists
        remove(file_name);
    }
    
    FILE* f = fopen(file_name, "w");
    if(!f) {
        __ALC_UTILS_WARN("pre_allocate: unable to open %s", file_name);
        return NULL;
    }
    
    uint32_t to_allocate_size = alc_packet->transfer_len;
    if(to_allocate_size) {
    	__ALC_UTILS_IOTRACE("pre_allocate: before: file %s to size: %d", file_name, to_allocate_size);
        uint32_t alloc_offset = 0;
        uint32_t blocksize;
        uint32_t loop_count = 0;
        while(alloc_offset < to_allocate_size) {
        	blocksize = __MIN(__TO_PREALLOC_ZERO_SLAB_SIZE, to_allocate_size - alloc_offset);
            fwrite(__TO_PREALLOC_ZERO_SLAB_PTR, blocksize, 1, f);
            alloc_offset += blocksize;
            loop_count++;
        }
        __ALC_UTILS_IOTRACE("pre_allocate: after: file %s to size: %d, wrote out: %u in %u fwrite", file_name, to_allocate_size, alloc_offset, loop_count);

    } else {
        __ALC_UTILS_WARN("pre_allocate: file %s, transfer_len is 0, not pre allocating", file_name);
    }
    fclose(f);
    f = fopen(file_name, "r+");
   
    return f;
}

int alc_packet_write_fragment(FILE* f, char* file_name, uint32_t offset, alc_packet_t* alc_packet) {
    
	__ALC_UTILS_IOTRACE("write fragment: tsi: %u, toi: %u, sbn: %x, esi: %x len: %d, complete: %d, file: %p, file name: %s, offset: %u, size: %u",  alc_packet->def_lct_hdr->tsi, alc_packet->def_lct_hdr->toi,
        alc_packet->sbn, alc_packet->esi, alc_packet->alc_len, alc_packet->close_object_flag,
        f, file_name, offset, alc_packet->alc_len);

    fseek(f, offset, SEEK_SET);
    int blocks_written = fwrite(alc_packet->alc_payload, alc_packet->alc_len, 1, f);
   
    if(blocks_written != 1) {
        __ALC_UTILS_WARN("short packet write: blocks: %u", blocks_written);
        return 0;
    }
    
    return alc_packet->alc_len;
}


/* atsc3_alc_packet_persist_to_toi_resource_process_sls_mbms_and_emit_callback
 *
 * persist to disk, process sls mbms and/or emit ROUTE media_delivery_event complete to the application tier if
 * the full packet has been recovered (e.g. no missing data units in the forward transmission)
 * Notes:
 *
 *      TOI size:     uint32_t to_allocate_size = alc_packet->transfer_len;
 */

int atsc3_alc_packet_persist_to_toi_resource_process_sls_mbms_and_emit_callback(udp_flow_t *udp_flow, alc_packet_t **alc_packet_ptr, lls_sls_alc_monitor_t *lls_sls_alc_monitor) {

	alc_packet_t* alc_packet = *alc_packet_ptr;
	int bytesWritten = 0;

    if(lls_sls_alc_monitor && !lls_sls_alc_monitor->lls_sls_monitor_output_buffer_mode.file_dump_enabled) {
        return -1;
    }

    char* temporary_filename = alc_packet_dump_to_object_get_temporary_recovering_filename(udp_flow, alc_packet);
    char* s_tsid_content_location = NULL;
    
    mkdir("route", 0777);

    FILE *f = NULL;

    if(alc_packet->use_sbn_esi) {
        //raptor fec, use the esi to see if we should write out to a new file vs append
        if(!alc_packet->esi) {
            f = alc_object_pre_allocate(temporary_filename, alc_packet);
            __ALC_UTILS_IOTRACE("raptor_fec: done creating new pre-allocation for temporary_filename: %s, size: %llu", temporary_filename, alc_packet->transfer_len);
        } else {
            f = alc_object_open_or_pre_allocate(temporary_filename, alc_packet);
        }
        if(!f) {
            __ALC_UTILS_WARN("atsc3_alc_packet_persist_to_toi_resource_process_sls_mbms_and_emit_callback, unable to open temporary_filename: %s", temporary_filename);
            return -2;
        }
        alc_packet_write_fragment(f, temporary_filename, alc_packet->esi, alc_packet);
        __ALC_UTILS_IOTRACE("raptor_fec: done writing out fragment for %s", temporary_filename);

    } else if(alc_packet->use_start_offset) {
        if(!alc_packet->start_offset) {
            f = alc_object_pre_allocate(temporary_filename, alc_packet);
            __ALC_UTILS_IOTRACE("ALC: tsi: %u, toi: %u, done creating new pre-allocation temporary_filename %s, size: %llu",
            		alc_packet->def_lct_hdr->tsi,
					alc_packet->def_lct_hdr->toi,
					temporary_filename,
					alc_packet->transfer_len);

        } else {
            __ALC_UTILS_IOTRACE("ALC: tsi: %u, toi: %u, using existing pre-alloc temporary_filename %s, offset: %u, size: %llu",
            		alc_packet->def_lct_hdr->tsi,
					alc_packet->def_lct_hdr->toi,
					temporary_filename,
					alc_packet->start_offset,
					alc_packet->transfer_len);

            f = alc_object_open_or_pre_allocate(temporary_filename, alc_packet);
        }
        if(!f) {
            __ALC_UTILS_WARN("atsc3_alc_packet_persist_to_toi_resource_process_sls_mbms_and_emit_callback, unable to open file: %s", temporary_filename);
            return -2;
        }
        
        alc_packet_write_fragment(f, temporary_filename, alc_packet->start_offset, alc_packet);
        __ALC_UTILS_IOTRACE("done writing out temporary_filename for %s", temporary_filename);

    } else {
        __ALC_UTILS_WARN("atsc3_alc_packet_persist_to_toi_resource_process_sls_mbms_and_emit_callback, no alc offset strategy for temporary_filename: %s", temporary_filename);
    }
	
    if(f) {
        fclose(f);
        f = NULL;
    }
    
    //both codepoint=0 and codepoint=128 will set close_object_flag when we have finished delivery of the object
    //jjustman-2020-02-28 - atsc3_alc_rx.c will also set close_object implicity if:
    //  SB_LB_E_FEC_ENC_ID                             : transfer_len >0 && transfer_len == alc_packet->alc_len + alc_packet->esi
    //  all others (e.g. alc_packet->use_start_offset) : transfer_len >0 && transfer_len == alc_packet->alc_len + alc_packet->start_offset

	if(alc_packet->close_object_flag) {

        //update our sls here if we have a service we are listenting to
        if(lls_sls_alc_monitor && lls_sls_alc_monitor->atsc3_lls_slt_service &&  alc_packet->def_lct_hdr->tsi == 0) {

            char* final_mbms_toi_filename = alc_packet_dump_to_object_get_filename_tsi_toi(udp_flow, 0, alc_packet->def_lct_hdr->toi);
            rename(temporary_filename, final_mbms_toi_filename);

            __ALC_UTILS_IOTRACE("ALC: service_id: %u, ------ TSI of 0, TOI: %d, transfer_len: %d, final object name: %s, calling atsc3_route_sls_process_from_alc_packet_and_file",
            		lls_sls_alc_monitor->atsc3_lls_slt_service->service_id,
            		alc_packet->def_lct_hdr->toi,
            		alc_packet->transfer_len,
            		final_mbms_toi_filename);

            atsc3_route_sls_process_from_alc_packet_and_file(udp_flow, alc_packet, lls_sls_alc_monitor);

        } else {
            s_tsid_content_location = alc_packet_dump_to_object_get_s_tsid_filename(udp_flow, alc_packet, lls_sls_alc_monitor);
     
            if(strncmp(temporary_filename, s_tsid_content_location, __MIN(strlen(temporary_filename), strlen(s_tsid_content_location))) !=0) {
                char new_file_name_raw_buffer[1024] = { 0 };
                char* new_file_name = &new_file_name_raw_buffer;
                snprintf(new_file_name_raw_buffer, 1024, __ALC_DUMP_OUTPUT_PATH__"%d/%s", lls_sls_alc_monitor->atsc3_lls_slt_service->service_id, s_tsid_content_location);
                
                //todo: jjustman-2019-11-15: sanatize path parameter for .. or other traversal attacks
                bool is_traversal = new_file_name[0] == '.';
                
                for(int i=0; i < strlen(new_file_name) && is_traversal; i++) {
                    new_file_name++;
                    is_traversal = new_file_name[0] == '.';
                }
                
                //iterate over occurances of '/' and create directory hierarchy
                char* path_slash_position = new_file_name;
                char* first_path_slash_position = new_file_name;
                while((path_slash_position = strstr(path_slash_position + 1, "/"))) {
                    if(path_slash_position - first_path_slash_position > 0) {
                        //hack
                        *path_slash_position = '\0';
                        mkdir(first_path_slash_position, 0777);
                        *path_slash_position = '/';
                    }
                }
                
               
                //rename(temporary_filename, new_file_name);
                //__ALC_UTILS_IOTRACE("tsi: %u, toi: %u, moving from to temporary_filename: %s to: %s, is complete: %d", alc_packet->def_lct_hdr->tsi, alc_packet->def_lct_hdr->toi,  temporary_filename, new_file_name, alc_packet->close_object_flag);

                if (access(new_file_name, F_OK) == -1) //copy if not exist
                {
                    //rename(temporary_filename, new_file_name);
                    //open temporary_filename and new_file_name
                    FILE* p_tmp_file = fopen(temporary_filename, "r");
                    FILE* p_new_file = fopen(new_file_name, "w+");

                    //check file ptr
                    if (NULL == p_tmp_file || NULL == p_new_file) {
                        __ALC_UTILS_IOTRACE("Error to open temporary_filename or new_file_name: %s to: %s", temporary_filename, new_file_name);
                    }
                    
                    struct stat st;
                    stat(temporary_filename, &st);
                    uint8_t* data_payload = (uint8_t*)calloc(st.st_size, sizeof(uint8_t));

                    fread(data_payload, st.st_size, 1, p_tmp_file);
                    fclose(p_tmp_file);

                    fwrite(data_payload, st.st_size, 1, p_new_file);
                    fclose(p_new_file);
                    free(data_payload);
                    //read temporary_filename data and write to new_file_name
                    __ALC_UTILS_IOTRACE("tsi: %u, toi: %u, copy from temporary_filename to new_file_name: %s to: %s, is complete: %d", alc_packet->def_lct_hdr->tsi, alc_packet->def_lct_hdr->toi,  temporary_filename, new_file_name, alc_packet->close_object_flag);
                }

                //emit lls alc context callback
                if(lls_sls_alc_monitor->atsc3_lls_sls_alc_on_object_close_flag_s_tsid_content_location) {
					lls_sls_alc_monitor->atsc3_lls_sls_alc_on_object_close_flag_s_tsid_content_location(alc_packet->def_lct_hdr->tsi, alc_packet->def_lct_hdr->toi, s_tsid_content_location);

                }
            }
        }
	} else {
		__ALC_UTILS_IOTRACE("dumping to file step: %s, is complete: %d", temporary_filename, alc_packet->close_object_flag);
	}

	__ALC_UTILS_IOTRACE("checking tsi: %u, toi: %u, close_object_flag: %d", alc_packet->def_lct_hdr->tsi, alc_packet->def_lct_hdr->toi, alc_packet->close_object_flag);

cleanup:
	if(temporary_filename) {
		free(temporary_filename);
	}

	if(s_tsid_content_location) {
		free(s_tsid_content_location);
	}

	return bytesWritten;
}


void __alc_prepend_fragment_with_init_box(char* file_name, alc_packet_t* alc_packet) {

#if defined(__TESTING_PREPEND_TSI__) && defined(__TESTING_PREPEND_TOI_INIT__)

	char* tsi_init = __TESTING_PREPEND_TSI__;
	char* toi_init = __TESTING_PREPEND_TOI_INIT__;

	char* init_file_name = calloc(255, sizeof(char));
	char* fm4v_file_name = calloc(255, sizeof(char)); //.m4v == 4

	__ALC_UTILS_DEBUG(" - concat %s, %s,  %d", alc_packet->tsi_c, alc_packet->toi_c, alc_packet->close_object_flag);

	snprintf(init_file_name, 255, "%s%s-%s", __ALC_DUMP_OUTPUT_PATH__, tsi_init, toi_init);
	snprintf(fm4v_file_name, 255, "%s%s-%s.m4v", __ALC_DUMP_OUTPUT_PATH__, alc_packet->tsi_c, alc_packet->toi_c);

	if( access( init_file_name, F_OK ) == -1 ) {
		__ALC_UTILS_ERROR("unable to open init file: %s", init_file_name);
		goto cleanup;
	}
	struct stat st;
	stat(init_file_name, &st);

	uint8_t* init_payload = calloc(st.st_size, sizeof(uint8_t));
	FILE* init_file = fopen(init_file_name, "r");
	if(!init_file) {
		__ALC_UTILS_ERROR("unable to open init file: %s", init_file_name);
		goto cleanup;
	}

	fread(init_payload, st.st_size, 1, init_file);
	fclose(init_file);

	FILE* fm4v_output_file = fopen(fm4v_file_name, "w");
	if(!fm4v_output_file) {
		__ALC_UTILS_ERROR("unable to open fm4v output file: %s", fm4v_file_name);
		goto cleanup;
	}

	fwrite(init_payload, st.st_size, 1, fm4v_output_file);
	uint64_t block_size = 8192;

	FILE* m4v_fragment_input_file = fopen(file_name, "r");
	uint8_t* m4v_payload = calloc(block_size, sizeof(uint8_t));
	if(!m4v_fragment_input_file) {
		__ALC_UTILS_ERROR("unable to open m4v fragment input: %s", file_name);
		goto cleanup;
	}
	struct stat fragment_input_stat;
	stat(file_name, &fragment_input_stat);
	uint64_t write_count=0;
	bool has_eof = false;
	while(!has_eof) {
		int read_size = fread(m4v_payload, block_size, 1, m4v_fragment_input_file);
		uint64_t read_bytes = read_size * block_size;
		if(!read_bytes && feof(m4v_fragment_input_file)) {
			read_bytes = fragment_input_stat.st_size - (block_size * write_count);
			has_eof = true;
		}
		__ALC_UTILS_TRACE("read bytes: %llu", read_bytes);

		int write_size = fwrite(m4v_payload, read_bytes, 1, fm4v_output_file);
		if(has_eof) {
			__ALC_UTILS_TRACE("write bytes: %u", write_size);

			fclose(m4v_fragment_input_file);
			fclose(fm4v_output_file);
			break;
		}
		write_count++;
	}
cleanup:
	return;
#endif

}

bool __ALC_RECON_HAS_WRITTEN_INIT_BOX = false;

void __alc_recon_fragment_with_init_box(char* file_name, alc_packet_t* alc_packet, uint32_t tsi, uint32_t toi_init, const char* to_write_filename) {


	char* init_file_name = (char*)calloc(255, sizeof(char));
	char* recon_file_name = (char*)calloc(255, sizeof(char)); //.m4v == 4
	FILE* recon_output_file = NULL;

	__ALC_UTILS_DEBUG(" alc_recon_fragment_with_init_box: %u, %u,  %d", alc_packet->def_lct_hdr->tsi, alc_packet->def_lct_hdr->toi, alc_packet->close_object_flag);

	snprintf(init_file_name, 255, "%s%u-%u", __ALC_DUMP_OUTPUT_PATH__, tsi, toi_init);
	snprintf(recon_file_name, 255, "%s%s", __ALC_DUMP_OUTPUT_PATH__, to_write_filename );

	if(!__ALC_RECON_HAS_WRITTEN_INIT_BOX) {


		if( access( init_file_name, F_OK ) == -1 ) {
			__ALC_UTILS_ERROR("unable to open init file: %s", init_file_name);
			return;
		}

		struct stat st;
		stat(init_file_name, &st);

		uint8_t* init_payload = (uint8_t*)calloc(st.st_size, sizeof(uint8_t));
		FILE* init_file = fopen(init_file_name, "r");
		if(!init_file || st.st_size == 0) {
			__ALC_UTILS_ERROR("unable to open init file: %s", init_file_name);
			return;
		}

		fread(init_payload, st.st_size, 1, init_file);
		fclose(init_file);
		recon_output_file = fopen(recon_file_name, "w");
		if(!recon_output_file) {
			__ALC_UTILS_ERROR("unable to open recon_output_file for writing: %s", recon_file_name);
			return;
		}
		fwrite(init_payload, st.st_size, 1, recon_output_file);
		__ALC_RECON_HAS_WRITTEN_INIT_BOX = true;

	} else {
		recon_output_file = fopen(recon_file_name, "a");
		if(!recon_output_file) {
		__ALC_UTILS_ERROR("unable to open recon_output_file for append: %s", recon_file_name);
		return;
		}
	}

	uint64_t block_size = 8192;

	FILE* m4v_fragment_input_file = fopen(file_name, "r");
	uint8_t* m4v_payload = (uint8_t*)calloc(block_size, sizeof(uint8_t));
	if(!m4v_fragment_input_file) {
		__ALC_UTILS_ERROR("unable to open m4v fragment input: %s", file_name);
		return;
	}
	struct stat fragment_input_stat;
	stat(file_name, &fragment_input_stat);
	uint64_t write_count=0;
	bool has_eof = false;
	while(!has_eof) {
		int read_size = fread(m4v_payload, block_size, 1, m4v_fragment_input_file);
		uint64_t read_bytes = read_size * block_size;
		if(!read_bytes && feof(m4v_fragment_input_file)) {
			read_bytes = fragment_input_stat.st_size - (block_size * write_count);
			has_eof = true;
		}
		__ALC_UTILS_TRACE("read bytes: %" PRIu64, read_bytes);

		int write_size = fwrite(m4v_payload, read_bytes, 1, recon_output_file);
		if(has_eof) {
			__ALC_UTILS_TRACE("write bytes: %u", write_size);

			fclose(m4v_fragment_input_file);
			fclose(recon_output_file);
			break;
		}
		write_count++;
	}
cleanup:
	return;
}

//watch out for leaks...
void alc_recon_file_ptr_set_tsi_toi(FILE* file_ptr, uint32_t tsi, uint32_t toi_init) {
	__ALC_RECON_FILE_PTR = file_ptr;
	if(!__ALC_RECON_FILE_PTR_TSI) {
		__ALC_RECON_FILE_PTR_TSI = (uint32_t*)calloc(1, sizeof(uint32_t));
	}
	*__ALC_RECON_FILE_PTR_TSI = tsi;


	if(!__ALC_RECON_FILE_PTR_TOI_INIT) {
		__ALC_RECON_FILE_PTR_TOI_INIT = (uint32_t*)calloc(1, sizeof(uint32_t));
		}
	*__ALC_RECON_FILE_PTR_TOI_INIT = toi_init;
}

void alc_recon_file_ptr_fragment_with_init_box(FILE* output_file_ptr, udp_flow_t* udp_flow, alc_packet_t* alc_packet, uint32_t to_match_toi_init) {
	int flush_ret = 0;
	if(!__ALC_RECON_FILE_PTR_TSI || !__ALC_RECON_FILE_PTR_TOI_INIT) {
		__ALC_UTILS_WARN("alc_recon_file_ptr_fragment_with_init_box - NULL: tsi: %p, toi: %p", __ALC_RECON_FILE_PTR_TSI, __ALC_RECON_FILE_PTR_TOI_INIT);
		return;
	}

	char* file_name = alc_packet_dump_to_object_get_temporary_recovering_filename(udp_flow,
                                                                                  alc_packet);
	uint32_t toi_init = to_match_toi_init;

	char* init_file_name = (char* )calloc(255, sizeof(char));

	__ALC_UTILS_DEBUG("recon %u, %u, %d", alc_packet->def_lct_hdr->tsi, alc_packet->def_lct_hdr->toi, alc_packet->close_object_flag);

	snprintf(init_file_name, 255, "%s%u-%u", __ALC_DUMP_OUTPUT_PATH__, *__ALC_RECON_FILE_PTR_TSI, toi_init);

	if(!__ALC_RECON_FILE_PTR_HAS_WRITTEN_INIT_BOX) {
		if( access( init_file_name, F_OK ) == -1 ) {
			__ALC_UTILS_ERROR("unable to open init file: %s", init_file_name);
			return;
		}

		struct stat st;
		stat(init_file_name, &st);

		uint8_t* init_payload = (uint8_t*)calloc(st.st_size, sizeof(uint8_t));
		FILE* init_file = fopen(init_file_name, "r");
		if(!init_file || st.st_size == 0) {
			__ALC_UTILS_ERROR("unable to open init file: %s", init_file_name);
			return;
		}

		fread(init_payload, st.st_size, 1, init_file);
		fclose(init_file);

		fwrite(init_payload, st.st_size, 1, output_file_ptr);
		__ALC_RECON_HAS_WRITTEN_INIT_BOX = true;

	} else {
		//noop here
	}

	uint64_t block_size = 8192;

	FILE* m4v_fragment_input_file = fopen(file_name, "r");
	uint8_t* m4v_payload = (uint8_t*)calloc(block_size, sizeof(uint8_t));
	if(!m4v_fragment_input_file) {
		__ALC_UTILS_ERROR("unable to open m4v fragment input: %s", file_name);
		return;
	}
	struct stat fragment_input_stat;
	stat(file_name, &fragment_input_stat);
	uint64_t write_count=0;
	bool has_eof = false;
	while(!has_eof) {
		int read_size = fread(m4v_payload, block_size, 1, m4v_fragment_input_file);
		uint64_t read_bytes = read_size * block_size;
		if(!read_bytes && feof(m4v_fragment_input_file)) {
			read_bytes = fragment_input_stat.st_size - (block_size * write_count);
			has_eof = true;
		}
		__ALC_UTILS_TRACE("read bytes: %" PRIu64, read_bytes);

		if(feof(output_file_ptr)) {
			goto broken_pipe;
		}

		int write_size = fwrite(m4v_payload, read_bytes, 1, output_file_ptr);
		if(has_eof) {
			__ALC_UTILS_TRACE("write bytes: %u", write_size);

			fclose(m4v_fragment_input_file);
			flush_ret = fflush(output_file_ptr);
			if(flush_ret || feof(output_file_ptr)) {
				goto broken_pipe;
			}
			break;
		}
		write_count++;
	}
	goto cleanup;

broken_pipe:
	__ALC_UTILS_ERROR("flush returned: %d, closing pipe", flush_ret);
	fclose(__ALC_RECON_FILE_PTR);
	__ALC_RECON_FILE_PTR = NULL;

cleanup:
	if(m4v_payload) {
		free(m4v_payload);
		m4v_payload = NULL;
	}
	if(file_name) {
		free(file_name);
		file_name = NULL;
	}


	return;
}

/*
 * mutex buffer writer
 */

void alc_recon_file_buffer_struct_set_tsi_toi(pipe_ffplay_buffer_t* pipe_ffplay_buffer, uint32_t tsi, uint32_t toi_init) {
	__ALC_RECON_FILE_BUFFER_STRUCT = pipe_ffplay_buffer;

	if(!__ALC_RECON_FILE_PTR_TSI) {
		__ALC_RECON_FILE_PTR_TSI = (uint32_t*)calloc(1, sizeof(uint32_t));
	}

	if(!__ALC_RECON_FILE_PTR_TOI_INIT) {
		__ALC_RECON_FILE_PTR_TOI_INIT = (uint32_t*)calloc(1, sizeof(uint32_t));
	}

	*__ALC_RECON_FILE_PTR_TSI = tsi;
	*__ALC_RECON_FILE_PTR_TOI_INIT = toi_init;
}



/*** we take this off of disk for the reassembeled fragment metadta and mpu
 *
 *
 */
void alc_recon_file_buffer_struct_fragment_with_init_box(pipe_ffplay_buffer_t* pipe_ffplay_buffer, udp_flow_t* udp_flow, alc_packet_t* alc_packet) {
	int flush_ret = 0;
	if(!__ALC_RECON_FILE_PTR_TSI || !__ALC_RECON_FILE_PTR_TOI_INIT) {
		__ALC_UTILS_WARN("alc_recon_file_ptr_fragment_with_init_box - NULL: tsi: %p, toi: %p", __ALC_RECON_FILE_PTR_TSI, __ALC_RECON_FILE_PTR_TOI_INIT);
		return;
	}

	char* file_name = alc_packet_dump_to_object_get_temporary_recovering_filename(udp_flow,
                                                                                  alc_packet);
	uint32_t toi_init = *__ALC_RECON_FILE_PTR_TOI_INIT;
	char* init_file_name = (char*)calloc(255, sizeof(char));

	__ALC_UTILS_DEBUG("alc_recon_file_buffer_struct_fragment_with_init_box - ENTER - %u, %u,  %d", alc_packet->def_lct_hdr->tsi, alc_packet->def_lct_hdr->toi, alc_packet->close_object_flag);

	snprintf(init_file_name, 255, "%s%u-%u", __ALC_DUMP_OUTPUT_PATH__, *__ALC_RECON_FILE_PTR_TSI, toi_init);

	pipe_buffer_reader_mutex_lock(pipe_ffplay_buffer);

	if(!pipe_ffplay_buffer->has_written_init_box) {
		if( access( init_file_name, F_OK ) == -1 ) {
			__ALC_UTILS_ERROR("unable to open init file: %s", init_file_name);
			return;
		}

		struct stat st;
		stat(init_file_name, &st);

		uint8_t* init_payload = (uint8_t*)calloc(st.st_size, sizeof(uint8_t));
		FILE* init_file = fopen(init_file_name, "r");
		if(!init_file || st.st_size == 0) {
			__ALC_UTILS_ERROR("unable to open init file: %s", init_file_name);
			return;
		}

		fread(init_payload, st.st_size, 1, init_file);
		fclose(init_file);

		pipe_buffer_unsafe_push_block(pipe_ffplay_buffer, init_payload, st.st_size);
		pipe_ffplay_buffer->has_written_init_box = true;

	} else {
		//noop here
	}

	uint64_t block_size = __PLAYER_FFPLAY_PIPE_WRITER_BLOCKSIZE;

	FILE* m4v_fragment_input_file = fopen(file_name, "r");
	uint8_t* m4v_payload = (uint8_t*)calloc(block_size, sizeof(uint8_t));
	if(!m4v_fragment_input_file) {
		__ALC_UTILS_ERROR("unable to open m4v fragment input: %s", file_name);
		return;
	}
	struct stat fragment_input_stat;
	stat(file_name, &fragment_input_stat);
	uint64_t write_count = 0;
	uint64_t total_bytes_written = 0;
	bool has_eof = false;

	while(!has_eof) {
		int read_size = fread(m4v_payload, block_size, 1, m4v_fragment_input_file);
		uint64_t read_bytes = read_size * block_size;
		if(!read_bytes && feof(m4v_fragment_input_file)) {
			read_bytes = fragment_input_stat.st_size - (block_size * write_count);
			has_eof = true;
		}
		total_bytes_written += read_bytes;
		__ALC_UTILS_TRACE("read bytes: %" PRIu64 ", bytes written: %" PRIu64 ", total filesize: %" PRIu64 ", has eof input: %d", read_bytes, total_bytes_written, fragment_input_stat.st_size, has_eof);

		pipe_buffer_unsafe_push_block(pipe_ffplay_buffer, m4v_payload, read_bytes);

		if(has_eof) {
			fclose(m4v_fragment_input_file);
			break;
		}
		write_count++;

	}

	//signal and then unlock, docs indicate the only way to ensure a signal is not lost is to send it while holding the lock
	__ALC_UTILS_DEBUG("alc_recon_file_buffer_struct_fragment_with_init_box - SIGNALING - %u, %u,  %d", alc_packet->def_lct_hdr->tsi, alc_packet->def_lct_hdr->toi, alc_packet->close_object_flag);

	pipe_buffer_notify_semaphore_post(pipe_ffplay_buffer);

	//check to see if we have shutdown
	pipe_buffer_reader_check_if_shutdown(&pipe_ffplay_buffer);

	pipe_buffer_reader_mutex_unlock(pipe_ffplay_buffer);
	__ALC_UTILS_DEBUG("alc_recon_file_buffer_struct_fragment_with_init_box - RETURN - %u, %u,  %d", alc_packet->def_lct_hdr->tsi, alc_packet->def_lct_hdr->toi, alc_packet->close_object_flag);

	goto cleanup;

broken_pipe:
	__ALC_UTILS_ERROR("flush returned: %d, closing pipe", flush_ret);
	fclose(__ALC_RECON_FILE_PTR);
	__ALC_RECON_FILE_PTR = NULL;

cleanup:
	if(m4v_payload) {
		free(m4v_payload);
		m4v_payload = NULL;
	}
	if(file_name) {
		free(file_name);
		file_name = NULL;
	}


	return;
}


void alc_recon_file_buffer_struct_monitor_fragment_with_init_box(udp_flow_t* udp_flow, alc_packet_t* alc_packet, lls_sls_alc_monitor_t* lls_sls_alc_monitor) {
	int flush_ret = 0;
	char* audio_init_file_name = NULL;
	char* video_init_file_name = NULL;
	char* audio_fragment_file_name = NULL;
	char* video_fragment_file_name = NULL;
	block_t* audio_fragment_payload = NULL;
	block_t* video_fragment_payload = NULL;
	block_t* audio_init_payload = NULL;
	block_t* video_init_payload = NULL;

	//tsi matching for audio and video fragments
	if(alc_packet->def_lct_hdr->tsi == lls_sls_alc_monitor->audio_tsi) {
		//don't flush out init boxes here..
		if(alc_packet->def_lct_hdr->toi == lls_sls_alc_monitor->audio_toi_init) {
			__ALC_UTILS_DEBUG("alc_recon_file_buffer_struct_monitor_fragment_with_init_box, got audio init box: tsi: %u, toi: %u, ignoring", alc_packet->def_lct_hdr->tsi, alc_packet->def_lct_hdr->toi);
			return;
		}

		lls_sls_alc_monitor->last_closed_audio_toi = alc_packet->def_lct_hdr->toi;
		if(alc_packet->ext_route_presentation_ntp_timestamp_set && !lls_sls_alc_monitor->lls_sls_monitor_output_buffer.audio_output_buffer_isobmff.mpu_presentation_time_set) {
			lls_sls_alc_monitor->lls_sls_monitor_output_buffer.audio_output_buffer_isobmff.mpu_presentation_time = alc_packet->ext_route_presentation_ntp_timestamp;
			compute_ntp64_to_seconds_microseconds(lls_sls_alc_monitor->lls_sls_monitor_output_buffer.audio_output_buffer_isobmff.mpu_presentation_time, &lls_sls_alc_monitor->lls_sls_monitor_output_buffer.audio_output_buffer_isobmff.mpu_presentation_time_s, &lls_sls_alc_monitor->lls_sls_monitor_output_buffer.audio_output_buffer_isobmff.mpu_presentation_time_us);
			lls_sls_alc_monitor->lls_sls_monitor_output_buffer.audio_output_buffer_isobmff.mpu_presentation_time_set = true;
		}
	}

	if(alc_packet->def_lct_hdr->tsi == lls_sls_alc_monitor->video_tsi) {
		if(alc_packet->def_lct_hdr->toi == lls_sls_alc_monitor->video_toi_init) {
			__ALC_UTILS_DEBUG("alc_recon_file_buffer_struct_monitor_fragment_with_init_box, got video init box: tsi: %u, toi: %u, ignoring", alc_packet->def_lct_hdr->tsi, alc_packet->def_lct_hdr->toi);
			return;
		}

		lls_sls_alc_monitor->last_closed_video_toi = alc_packet->def_lct_hdr->toi;
		if(alc_packet->ext_route_presentation_ntp_timestamp_set && !lls_sls_alc_monitor->lls_sls_monitor_output_buffer.video_output_buffer_isobmff.mpu_presentation_time_set) {
			lls_sls_alc_monitor->lls_sls_monitor_output_buffer.video_output_buffer_isobmff.mpu_presentation_time = alc_packet->ext_route_presentation_ntp_timestamp;
			compute_ntp64_to_seconds_microseconds(lls_sls_alc_monitor->lls_sls_monitor_output_buffer.video_output_buffer_isobmff.mpu_presentation_time, &lls_sls_alc_monitor->lls_sls_monitor_output_buffer.video_output_buffer_isobmff.mpu_presentation_time_s, &lls_sls_alc_monitor->lls_sls_monitor_output_buffer.video_output_buffer_isobmff.mpu_presentation_time_us);
			lls_sls_alc_monitor->lls_sls_monitor_output_buffer.video_output_buffer_isobmff.mpu_presentation_time_set = true;

		}
	}

	//we may have short audio/video packets, so allow our buffer accumulate and then flush independently after we have written our initbox
    uint32_t audio_toi = lls_sls_alc_monitor->last_closed_audio_toi;
    uint32_t video_toi = lls_sls_alc_monitor->last_closed_video_toi;
    
	audio_fragment_file_name = alc_packet_dump_to_object_get_filename_tsi_toi(udp_flow, lls_sls_alc_monitor->audio_tsi, audio_toi);
	video_fragment_file_name = alc_packet_dump_to_object_get_filename_tsi_toi(udp_flow, lls_sls_alc_monitor->video_tsi, video_toi);

	if(!lls_sls_alc_monitor->lls_sls_monitor_output_buffer.has_written_init_box) {
		audio_init_file_name = alc_packet_dump_to_object_get_filename_tsi_toi(udp_flow, lls_sls_alc_monitor->audio_tsi, lls_sls_alc_monitor->audio_toi_init);
		video_init_file_name = alc_packet_dump_to_object_get_filename_tsi_toi(udp_flow, lls_sls_alc_monitor->video_tsi, lls_sls_alc_monitor->video_toi_init);

		audio_init_payload = alc_get_payload_from_filename(audio_init_file_name);
		video_init_payload = alc_get_payload_from_filename(video_init_file_name);

		audio_fragment_payload = alc_get_payload_from_filename(audio_fragment_file_name);
		video_fragment_payload = alc_get_payload_from_filename(video_fragment_file_name);

		if(audio_init_payload && video_init_payload &&
			audio_fragment_payload && video_fragment_payload) {

			__ALC_UTILS_DEBUG("alc_recon_file_buffer_struct_monitor_fragment_with_init_box - audio: %s, video: %s", audio_init_file_name, video_init_file_name);

			lls_sls_monitor_output_buffer_copy_audio_init_block(&lls_sls_alc_monitor->lls_sls_monitor_output_buffer, audio_init_payload);
			lls_sls_monitor_output_buffer_copy_video_init_block(&lls_sls_alc_monitor->lls_sls_monitor_output_buffer, video_init_payload);
			lls_sls_monitor_output_buffer_copy_audio_fragment_block(&lls_sls_alc_monitor->lls_sls_monitor_output_buffer, audio_fragment_payload);
			lls_sls_monitor_output_buffer_copy_video_fragment_block(&lls_sls_alc_monitor->lls_sls_monitor_output_buffer, video_fragment_payload);
			lls_sls_alc_monitor->lls_sls_monitor_output_buffer.has_written_init_box = true;
			lls_sls_alc_monitor->lls_sls_monitor_output_buffer.should_flush_output_buffer = true;
	        lls_sls_alc_monitor->last_closed_audio_toi = 0;
	        lls_sls_alc_monitor->last_closed_audio_toi = 0;

			lls_sls_alc_monitor->last_pending_flushed_audio_toi = 0;
			lls_sls_alc_monitor->last_pending_flushed_video_toi = 0;

	        lls_sls_alc_monitor->last_completed_flushed_audio_toi = audio_toi;
	        lls_sls_alc_monitor->last_completed_flushed_video_toi = video_toi;


		} else {
			__ALC_UTILS_ERROR("missing init/moof payloads, audio init: %s (%p), audio moof: %s (%p), video init: %s (%p), video moof: %s (%p)",
					audio_init_file_name,
					audio_init_payload,
					audio_fragment_file_name,
					audio_fragment_payload,
					video_init_file_name,
					video_init_payload,
					video_fragment_file_name,
					video_fragment_payload);

			goto cleanup;
		}
	} else {

		//TODO - determine if we should prepend the most recent init box?
		//append audio if we have an audio frame
		if(audio_toi && audio_fragment_file_name) {
			audio_fragment_payload = alc_get_payload_from_filename(audio_fragment_file_name);
			if(audio_fragment_payload) {
				lls_sls_monitor_output_buffer_merge_alc_fragment_block(&lls_sls_alc_monitor->lls_sls_monitor_output_buffer.audio_output_buffer_isobmff, audio_fragment_payload);
				lls_sls_alc_monitor->last_closed_audio_toi = 0;
				lls_sls_alc_monitor->last_pending_flushed_audio_toi = audio_toi;
				__ALC_UTILS_DEBUG("alc_recon_file_buffer_struct_monitor_fragment_with_init_box - pushing audio fragment: %d, file: %s", audio_toi, audio_fragment_file_name);
			} else {
				__ALC_UTILS_ERROR("alc_recon_file_buffer_struct_monitor_fragment_with_init_box - missing audio fragment: %d, file: %s", audio_toi, audio_fragment_file_name);
			}
		}

		//append video if we have a video frame
		if(video_toi && video_fragment_file_name) {
			video_fragment_payload = alc_get_payload_from_filename(video_fragment_file_name);
			if(video_fragment_payload) {
				lls_sls_monitor_output_buffer_merge_alc_fragment_block(&lls_sls_alc_monitor->lls_sls_monitor_output_buffer.video_output_buffer_isobmff, video_fragment_payload);

				lls_sls_alc_monitor->last_closed_video_toi = 0;
				lls_sls_alc_monitor->last_pending_flushed_video_toi = video_toi;

				__ALC_UTILS_DEBUG("alc_recon_file_buffer_struct_monitor_fragment_with_init_box - pushing video fragment: %d, file: %s", video_toi, video_fragment_file_name);
			} else {
				__ALC_UTILS_ERROR("alc_recon_file_buffer_struct_monitor_fragment_with_init_box - missing video fragment: %d, file: %s", video_toi, video_fragment_file_name);
			}
		}

		if(lls_sls_alc_monitor->last_pending_flushed_audio_toi && lls_sls_alc_monitor->last_pending_flushed_video_toi) {
			lls_sls_alc_monitor->lls_sls_monitor_output_buffer.should_flush_output_buffer = true;
			__ALC_UTILS_DEBUG("alc_recon_file_buffer_struct_monitor_fragment_with_init_box - setting should_flush output buffer for: audio fragment: %d, video fragment: %d",
					lls_sls_alc_monitor->last_pending_flushed_audio_toi, lls_sls_alc_monitor->last_pending_flushed_video_toi);



			lls_sls_alc_monitor->last_completed_flushed_audio_toi = lls_sls_alc_monitor->last_pending_flushed_audio_toi;
			lls_sls_alc_monitor->last_completed_flushed_video_toi = lls_sls_alc_monitor->last_pending_flushed_video_toi;

			lls_sls_alc_monitor->last_closed_audio_toi = 0;
			lls_sls_alc_monitor->last_pending_flushed_audio_toi = 0;
			lls_sls_alc_monitor->last_closed_video_toi = 0;
			lls_sls_alc_monitor->last_pending_flushed_video_toi = 0;
		}
	}

cleanup:
	freesafe(audio_init_file_name);
	freesafe(video_init_file_name);
	freesafe(audio_fragment_file_name);
	freesafe(video_fragment_file_name);
	block_Destroy(&audio_fragment_payload);
	block_Destroy(&video_fragment_payload);
	block_Destroy(&audio_init_payload);
	block_Destroy(&video_init_payload);

	return;
}

/*
 * atsc3_alc_persist_route_ext_attributes_per_lls_sls_alc_monitor_essence
 * keep track of our current TSI/TOI's start_offset attribute for ALC flows that only provide the EXT_FTI value at the first
 * packet of the TOI flow
 *
 * additionally, set the close_object flag if our current alc packet start_offset + transfer_len will be greater than the
 * persisted EXT_FTI object transfer len in lls_sls_alc_monitor->last_..._toi_length (...: video, audio, text)
 *
 * TODO: jjustman-2020-02-28:
 *      - remove tight coupling from video/audio media essences
 *      - add in support for generic TSI flows in the lls_sls_alc_monitor route attribute tracking model (e.g. collections-c map)
 *
 * - validate that alc_packet->use_start_offset is the correct attribute to key for EXT_FTI
 *
 * jjustman-2020-03-12 - NOTE - a more robust implementation is in atsc3_alc_rx.c
 * this code path will only handle alc->use_start_offset, as atsc3_alc_rx logic that handles both start_offset and sbn_esi
 *
 * ***NOTE***: atsc3_alc_packet_check_monitor_flow_for_toi_wraparound_discontinuity MUST BE CALLED BEFORE
 *          atsc3_alc_persist_route_ext_attributes_per_lls_sls_alc_monitor_essence IN FLOW,
 *          OTHERWISE lls_sls_alc_monitor->last_..._toi will be overwritten and the discontinuity WILL NOT BE DETECTED!
 */

#define __ATSC3_ALC_UTILS_CHECK_CLOSE_FLAG_ON_TOI_LENGTH_PERSIST__
//jjustman-2020-03-25 - workaround for digicap packager that is only emitting EXT_FTI on the very first packet of the TOI, and no close object flag

void atsc3_alc_persist_route_ext_attributes_per_lls_sls_alc_monitor_essence(alc_packet_t* alc_packet, lls_sls_alc_monitor_t* lls_sls_alc_monitor) {
    if(lls_sls_alc_monitor && lls_sls_alc_monitor->video_tsi && lls_sls_alc_monitor->audio_tsi) {
        uint32_t tsi = alc_packet->def_lct_hdr->tsi;
        uint32_t toi = alc_packet->def_lct_hdr->toi;

        uint32_t toi_length = alc_packet->transfer_len;

        //track our transfer_len if EXT_FTI is only present on the initial ALC packet
        //jjustman-2020-03-12 - do not persist this data for toi_init fragments

        if(toi_length) {
            if(tsi == lls_sls_alc_monitor->video_tsi && lls_sls_alc_monitor->video_toi_init && lls_sls_alc_monitor->video_toi_init != toi) {
                lls_sls_alc_monitor->last_video_toi = toi;
                lls_sls_alc_monitor->last_video_toi_length = toi_length;
                //only output debug message on first ALC packet
                if((alc_packet->use_start_offset && alc_packet->start_offset == 0) || (alc_packet->use_sbn_esi && alc_packet->esi == 0)) {
                    __ALC_UTILS_DEBUG("ALC: tsi: %u, toi: %u, setting last_video_toi: %u, last_video_toi_length: %u", tsi, toi, toi, toi_length);
                }
            } else if (tsi == lls_sls_alc_monitor->audio_tsi && lls_sls_alc_monitor->audio_toi_init && lls_sls_alc_monitor->audio_toi_init != toi) {
                lls_sls_alc_monitor->last_audio_toi = toi;
                lls_sls_alc_monitor->last_audio_toi_length = toi_length;
                if((alc_packet->use_start_offset && alc_packet->start_offset == 0) || (alc_packet->use_sbn_esi && alc_packet->esi == 0)) {
                    __ALC_UTILS_DEBUG("ALC: tsi: %u, toi: %u, setting last_audio_toi: %u, last_audio_toi_length: %u", tsi, toi, toi, toi_length);
                }
            } else if(tsi == lls_sls_alc_monitor->text_tsi && lls_sls_alc_monitor->text_toi_init && lls_sls_alc_monitor->text_toi_init != toi) {
                lls_sls_alc_monitor->last_text_toi = toi;
                lls_sls_alc_monitor->last_text_toi_length = toi_length;

                if((alc_packet->use_start_offset && alc_packet->start_offset == 0) || (alc_packet->use_sbn_esi && alc_packet->esi == 0)) {
                    __ALC_UTILS_DEBUG("ALC: tsi: %u, toi: %u, setting last_text_toi: %u, last_text_toi_length: %u", tsi, toi, toi, toi_length);
                }
            }
        }

        //check if we should set close flag here
        //jjustman-2020-03-12 - NOTE - a more robust implementation is in atsc3_alc_rx.c
        //this code path will only handle alc->use_start_offset, as atsc3_alc_rx logic that handles both start_offset and sbn_esi

#ifdef __ATSC3_ALC_UTILS_CHECK_CLOSE_FLAG_ON_TOI_LENGTH_PERSIST__
        if(alc_packet->use_start_offset) {
            uint32_t alc_start_offset = (alc_packet)->start_offset;
            uint32_t alc_packet_length = (alc_packet)->alc_len;

            if(tsi == lls_sls_alc_monitor->video_tsi && toi == lls_sls_alc_monitor->last_video_toi) {
                __ALC_UTILS_DEBUG("ALC: tsi: %u, toi: %u, checking last_video_toi_length: %u against start_offset: %u, alc_packet_length: %u (total: %u)",
                        tsi, toi,  lls_sls_alc_monitor->last_video_toi_length, alc_start_offset, alc_packet_length, alc_start_offset + alc_packet_length);

                    if(lls_sls_alc_monitor->last_video_toi_length && lls_sls_alc_monitor->last_video_toi_length <= (alc_start_offset + alc_packet_length)) {
                    (alc_packet)->close_object_flag = true;
                        __ALC_UTILS_DEBUG("ALC: tsi: %u, toi: %u, setting video: close_object_flag: true",
                        tsi, toi);
                }
            } else if(tsi == lls_sls_alc_monitor->audio_tsi && toi == lls_sls_alc_monitor->last_audio_toi) {
                __ALC_UTILS_DEBUG("ALC: tsi: %u, toi: %u, checking last_audio_toi_length: %u against start_offset: %u, alc_packet_length: %u (total: %u)",
                        tsi, toi,  lls_sls_alc_monitor->last_audio_toi_length, alc_start_offset, alc_packet_length, alc_start_offset + alc_packet_length);

                if(lls_sls_alc_monitor->last_audio_toi_length && lls_sls_alc_monitor->last_audio_toi_length <= (alc_start_offset + alc_packet_length)) {
                    alc_packet->close_object_flag = true;
                    __ALC_UTILS_DEBUG("ALC: tsi: %u, toi: %u, setting audio: close_object_flag: true",
                        tsi, toi);
                }
            } else if(tsi == lls_sls_alc_monitor->text_tsi && toi == lls_sls_alc_monitor->last_text_toi) {
                __ALC_UTILS_DEBUG("ALC: tsi: %u, toi: %u, checking last_text_toi_length: %u against start_offset: %u, alc_packet_length: %u (total: %u)",
                        tsi, toi,  lls_sls_alc_monitor->last_text_toi_length, alc_start_offset, alc_packet_length, alc_start_offset + alc_packet_length);

                if(lls_sls_alc_monitor->last_text_toi_length && lls_sls_alc_monitor->last_text_toi_length <= (alc_start_offset + alc_packet_length)) {
                    alc_packet->close_object_flag = true;
                    __ALC_UTILS_DEBUG("ALC: tsi: %u, toi: %u, setting text: close_object_flag: true",
                            tsi, toi);
                }
            }
        }
#endif

    }
}

/*
 * atsc3_alc_packet_check_monitor_flow_for_toi_wraparound_discontinuity:
 *
 * check our alc_packet TOI value to determine if we have a value less than our last closed TOI object,
 * signalling a wraparound or loop of our input source (e.g. STLTP or ALP replay or RFcapture replay) and
 * force a re-patch of the MPD on the next MBMS emission.
 *
 * the wrapaound check is limited to only TSI flows containing a/v/stpp media essense id's
 * that are monitored in the lls_sls_alc_monitor, and the TOI_init objects are ignored from this check.
 *
 * if detected, force a rebuild of the mpd with updated availabiltyStartTime and relevant startNumber values for each TSI flow/essence
 * will be checked at the next MBMS emission when the carouseled MPD is written to disk, and patched accordingly in
 * atsc3_route_sls_patch_mpd_availability_start_time_and_start_number *
 *
 * ***NOTE***: atsc3_alc_packet_check_monitor_flow_for_toi_wraparound_discontinuity MUST BE CALLED BEFORE
 *              atsc3_alc_persist_route_ext_attributes_per_lls_sls_alc_monitor_essence IN FLOW,
 *              OTHERWISE lls_sls_alc_monitor->last_..._toi will be overwritten and the discontinuity WILL NOT BE DETECTED!
 */
void atsc3_alc_packet_check_monitor_flow_for_toi_wraparound_discontinuity(alc_packet_t* alc_packet, lls_sls_alc_monitor_t* lls_sls_alc_monitor) {
    if (lls_sls_alc_monitor && lls_sls_alc_monitor->video_tsi && lls_sls_alc_monitor->audio_tsi) {

        uint32_t tsi = alc_packet->def_lct_hdr->tsi;
        uint32_t toi = alc_packet->def_lct_hdr->toi;

        //only process non init toi's, under the assumption they will be less than alc packet size for closed object tracking
        if((alc_packet->use_start_offset && alc_packet->start_offset == 0) || (alc_packet->use_sbn_esi && alc_packet->esi == 0)) {
            __ALC_UTILS_DEBUG("atsc3_alc_packet_check_monitor_flow_for_toi_wraparound_discontinuity: "
                              "enter with lls_sls_alc_monitor->has_discontiguous_toi_flow: %d, checking against tsi: %d, toi: %d, "
                              "last_video_toi: %d, last_audio_toi: %d, last_text_toi: %d, "
                              "video_tsi: %d, video_toi_init: %d, audio_tsi: %d, audio_toi_init: %d, text_tsi: %d, text_toi_init: %d",
                                lls_sls_alc_monitor->has_discontiguous_toi_flow,
                                tsi, toi,
                                lls_sls_alc_monitor->last_video_toi,
                                lls_sls_alc_monitor->last_audio_toi,
                                lls_sls_alc_monitor->last_text_toi,
                                lls_sls_alc_monitor->video_tsi, lls_sls_alc_monitor->video_toi_init,
                                lls_sls_alc_monitor->audio_tsi, lls_sls_alc_monitor->audio_toi_init,
                                lls_sls_alc_monitor->text_tsi, lls_sls_alc_monitor->text_toi_init);
        }

        //don't re-set double-set set our sls_alc_monitor flag for discontigious toi
        //jjustman-2020-03-11 - TODO: mutex lock this parameter during this check

        if(!lls_sls_alc_monitor->has_discontiguous_toi_flow) {
            if ((tsi == lls_sls_alc_monitor->video_tsi && toi != lls_sls_alc_monitor->video_toi_init && lls_sls_alc_monitor->last_video_toi && lls_sls_alc_monitor->last_video_toi > toi) ||
                (tsi == lls_sls_alc_monitor->audio_tsi && toi != lls_sls_alc_monitor->audio_toi_init && lls_sls_alc_monitor->last_audio_toi && lls_sls_alc_monitor->last_audio_toi > toi) ||
                (tsi == lls_sls_alc_monitor->text_tsi  && toi != lls_sls_alc_monitor->text_toi_init  && lls_sls_alc_monitor->last_text_toi  && lls_sls_alc_monitor->last_text_toi > toi)) {

                __ALC_UTILS_INFO("atsc3_alc_packet_check_monitor_flow_for_toi_wraparound_discontinuity: has discontigious re-wrap of TOI flow(s), "
                                 "tsi: %d, toi: %d, last_video_toi: %d, last_audio_toi: %d, last_text_toi: %d",
                                 tsi, toi, lls_sls_alc_monitor->last_video_toi, lls_sls_alc_monitor->last_audio_toi, lls_sls_alc_monitor->last_text_toi);

                //force a rebuild of the mpd with updated availabiltyStartTime and relevant startNumber values for each TSI flow/essense
                //will be checked at the next MBMS emission when the carouseled MPD is written to disk, and patched accordingly in
                //atsc3_route_sls_patch_mpd_availability_start_time_and_start_number

                lls_sls_alc_monitor->has_discontiguous_toi_flow = true;
                if (lls_sls_alc_monitor->last_mpd_payload) {
                    block_Destroy(&lls_sls_alc_monitor->last_mpd_payload);
                }
            }
        }
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
#define VIDEO_BIT   (0x1)
#define AUDIO_BIT   (0x2)
int INIT_BOX_DONE = 0;
int _MEDIA_DUMP = 0;

void dump_media_from_recover_file(udp_flow_t* udp_flow, alc_packet_t* alc_packet, lls_sls_alc_monitor_t* lls_sls_alc_monitor)
{
    if (!_MEDIA_DUMP) {
        __ALC_UTILS_DEBUG("[%s]Disable to dump media!!", __FUNCTION__);
    }

    __ALC_UTILS_DEBUG("[%s] %u, %u, %d", __FILE__, alc_packet->def_lct_hdr->tsi, 
        alc_packet->def_lct_hdr->toi, alc_packet->close_object_flag);

    //check this alc packet is media (video/audio) packet?
    if ((0 == alc_packet->def_lct_hdr->tsi) || /* signaling packet */
        (0 == alc_packet->close_object_flag) || /* not last alc packet of video/audio data */
         0 == ((alc_packet->def_lct_hdr->tsi == lls_sls_alc_monitor->video_tsi) || 
         (alc_packet->def_lct_hdr->tsi == lls_sls_alc_monitor->audio_tsi)))
    {
        __ALC_UTILS_DEBUG("Not media (video/audio) packet!!");
        return;
    }

    //check init box is write done?
    //[note] re-written init box seems ok in playback
    if ((lls_sls_alc_monitor->video_tsi == alc_packet->def_lct_hdr->tsi) &&
        (lls_sls_alc_monitor->video_toi_init == alc_packet->def_lct_hdr->toi)) {
        if (VIDEO_BIT & INIT_BOX_DONE) {
            __ALC_UTILS_DEBUG("Video init box (packet) has been writen before~");
            return;
        } else {
            INIT_BOX_DONE |= VIDEO_BIT;
        }
    }

    if ((lls_sls_alc_monitor->audio_tsi == alc_packet->def_lct_hdr->tsi) &&
        (lls_sls_alc_monitor->audio_toi_init == alc_packet->def_lct_hdr->toi)) {
        if (AUDIO_BIT & INIT_BOX_DONE) {
            __ALC_UTILS_DEBUG("Audio init box (packet) has been writen before~");
            return;
        } else {
            INIT_BOX_DONE |= AUDIO_BIT;
        }
    }

    char* in_file_name = alc_packet_dump_to_object_get_temporary_recovering_filename(udp_flow, alc_packet);
    char out_file_name[256] = {0};

    if (alc_packet->def_lct_hdr->tsi == lls_sls_alc_monitor->video_tsi) {
        snprintf(out_file_name, 255, "%s%u.mp4", __ALC_DUMP_OUTPUT_PATH__, alc_packet->def_lct_hdr->tsi);
    } else if (alc_packet->def_lct_hdr->tsi == lls_sls_alc_monitor->audio_tsi) {
        snprintf(out_file_name, 255, "%s%u.mp4", __ALC_DUMP_OUTPUT_PATH__, alc_packet->def_lct_hdr->tsi);
    }

    //open output file, with "a" mode
    FILE* out_file = fopen(out_file_name, "a");
    if (NULL == out_file) {
        __ALC_UTILS_ERROR("unable to open output file: %s", out_file_name);
        return;
    }

    //write media fragment from alc packet
    if (access(in_file_name, F_OK) == -1) {
        __ALC_UTILS_ERROR("unable to open input file: %s", in_file_name);
        return;
    }

    struct stat st;
    stat(in_file_name, &st);

    uint8_t* init_payload = (uint8_t*)calloc(st.st_size, sizeof(uint8_t));
    FILE* init_file = fopen(in_file_name, "r");
    if (!init_file || st.st_size == 0) {
        __ALC_UTILS_ERROR("unable to open init file: %s", in_file_name);
        return;
    }

    fread(init_payload, st.st_size, 1, init_file);
    fclose(init_file);

    fwrite(init_payload, st.st_size, 1, out_file);
    fclose(out_file);
    
cleanup:
    if (in_file_name) {
        free(in_file_name);
        in_file_name = NULL;
    }

    if (init_payload) {
        free(init_payload);
        init_payload = NULL;
    }
    
    return;
}

void dump_media_from_alc_packet(udp_flow_t* udp_flow, alc_packet_t* alc_packet, lls_sls_alc_monitor_t* lls_sls_alc_monitor)
{
    if (!_MEDIA_DUMP) {
        __ALC_UTILS_DEBUG("[%s]Disable to dump media!!", __FUNCTION__);
    }
    
    __ALC_UTILS_DEBUG("[%s] %u, %u, %d", __FILE__, alc_packet->def_lct_hdr->tsi, 
        alc_packet->def_lct_hdr->toi, alc_packet->close_object_flag);

    //check this alc packet is media (video/audio) packet?
    if ((0 == alc_packet->def_lct_hdr->tsi) || /* signaling packet */
         0 == ((alc_packet->def_lct_hdr->tsi == lls_sls_alc_monitor->video_tsi) || 
         (alc_packet->def_lct_hdr->tsi == lls_sls_alc_monitor->audio_tsi)))
    {
        __ALC_UTILS_DEBUG("Not media (video/audio) packet!!");
        return;
    }

    //check init box is write done?
    //[note] re-written init box seems ok in playback
    if ((lls_sls_alc_monitor->video_tsi == alc_packet->def_lct_hdr->tsi) &&
        (lls_sls_alc_monitor->video_toi_init == alc_packet->def_lct_hdr->toi)) {
        if (VIDEO_BIT & INIT_BOX_DONE) {
            __ALC_UTILS_DEBUG("Video init box (packet) has been writen before~");
            return;
        } else {
            INIT_BOX_DONE |= VIDEO_BIT;
        }
    }

    if ((lls_sls_alc_monitor->audio_tsi == alc_packet->def_lct_hdr->tsi) &&
        (lls_sls_alc_monitor->audio_toi_init == alc_packet->def_lct_hdr->toi)) {
        if (AUDIO_BIT & INIT_BOX_DONE) {
            __ALC_UTILS_DEBUG("Audio init box (packet) has been writen before~");
            return;
        } else {
            INIT_BOX_DONE |= AUDIO_BIT;
        }
    }

    char out_file_name[256] = {0};

    if (alc_packet->def_lct_hdr->tsi == lls_sls_alc_monitor->video_tsi) {
        snprintf(out_file_name, 255, "%s%u.mp4", __ALC_DUMP_OUTPUT_PATH__, alc_packet->def_lct_hdr->tsi);
    } else if (alc_packet->def_lct_hdr->tsi == lls_sls_alc_monitor->audio_tsi) {
        snprintf(out_file_name, 255, "%s%u.mp4", __ALC_DUMP_OUTPUT_PATH__, alc_packet->def_lct_hdr->tsi);
    }

    //open output file, with "a" mode
    FILE* out_file = fopen(out_file_name, "a");
    if (NULL == out_file) {
        __ALC_UTILS_ERROR("unable to open output file: %s", out_file_name);
        return;
    }

    fwrite(alc_packet->alc_payload, alc_packet->alc_len, 1, out_file);
    fclose(out_file);
    
    return;
}

