/** This file is used to implement port for erlang program which can capture packets
 * 	using libpcap and send them to erlang port process (and there by erlang connected
 *  process) for processing. This program uses libpcap so package libpcap-devel must
 *  be installed. The various packet parameters like packet_number, packet size
 *  time when packet was captured etc. also gets sent to erlang port.
 *
 *  @file f013_packet_capture.c
 *  @author Saurabh Barjatiya
 *  @version 1.0
 */

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

#define ADDRESS_SIZE 100
#define INTERFACE_NAME_SIZE 20
#define TIME_LENGTH 30
#define MAX_MAC_ADDRESS_LENGTH 20
#define MAX_NETWORK_LAYER_CODE_LENGTH 5
//#define LOG_FILE "f013_packet_capture.log"
#define LOG_FILE "/dev/null"

int find_local_interface (char *interface_name);
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void convert_to_hexadecimal(unsigned char *source, unsigned char *destination, int length);
void write_null_terminated_value(const u_char *data, int data_length_without_null);


int main(int argc, char *argv[])
{
    char interface_name[INTERFACE_NAME_SIZE];
    int result=0;
    pcap_t *packet_capture_handle;
    char error_message[PCAP_ERRBUF_SIZE];
	struct bpf_program compiled_filter;
	FILE *log_file;

	log_file=fopen(LOG_FILE, "w");
	if(log_file==NULL)
	{
		fprintf(stderr, "Cannot open log file %s for writing as:\n", LOG_FILE);
		perror("");
		exit(EXIT_FAILURE);
	}

	//result=find_local_interface(interface_name);
	strcpy(interface_name, "any");
	result=1;
    if(!result)
    {
		fprintf(log_file, "There is not local interface worth listening. Are you root?\n");
		fclose(log_file);
		exit(EXIT_FAILURE);
    }

    packet_capture_handle = pcap_open_live(
	    	interface_name, 	//interface to open
			65535,			//first n bytes of packet to capture
			0,  			//non-zero means promiscuous
			1000, 			//timeout in ms
			error_message); 	//error_message in case open fails
	if(packet_capture_handle==NULL)
	{
		fprintf(log_file, "Could not open interface %s for live capture. Are you root?\n", interface_name);
		fclose(log_file);
		exit(EXIT_FAILURE);
    }

	if(pcap_compile(packet_capture_handle, &compiled_filter, "", 1, 0) < 0)
	{
		fprintf(log_file, "Unable to compile the packet filter. Check the syntax.\n");
		fclose(log_file);
		exit(EXIT_FAILURE);
	}

	if(pcap_setfilter(packet_capture_handle, &compiled_filter) < 0)
	{
		fprintf(stderr, "Unable to set filter\n");
		fclose(log_file);
		exit(EXIT_FAILURE);
	}
	fprintf(log_file, "Everything went fine till pcap_loop()\n");
	fclose(log_file);

    pcap_loop(packet_capture_handle, //loop on this handle
	    -1, //number of packets to capture, -1 means loop indefinitely
	    packet_handler, //callback function, called once per packet
	    NULL); //u_char which gets passed to packet_handler

    exit(EXIT_SUCCESS);
    return 0;
}


int find_local_interface (char *interface_name)
{
    pcap_if_t *all_device_list;
    pcap_if_t *current_device;
    pcap_addr_t *current_address;
    char error_message[PCAP_ERRBUF_SIZE];
    char ipaddress[ADDRESS_SIZE];
    int found=0;

    /* Retrieve the device list from the local machine */
    if (pcap_findalldevs(&all_device_list, error_message)	== -1)
    {
		fprintf (stderr, "Error in pcap_findall_device_list_ex: %s\n", error_message);
		exit(EXIT_FAILURE);
    }

    /* Print the list */
    for (current_device = all_device_list; current_device != NULL; current_device = current_device->next)
    {
		for(current_address=current_device->addresses; current_address!=NULL; current_address=current_address->next)
		{
			if(current_address->addr->sa_family==AF_INET)
			{
				inet_ntop(current_address->addr->sa_family, &((struct sockaddr_in *)current_address->addr)->sin_addr.s_addr, ipaddress, sizeof(ipaddress));
				if(strcmp(ipaddress, "127.0.0.1")!=0)
				{
		    		//This interface has IPv4 address and this is not loopback. 
		    		//Hence it is worth listening too.
		    		strcpy(interface_name, current_device->name);
		    		found=1;
		    		break;
				}
	    	}
		}
		if(found)
	    	break;
    }

    /* We don't need any more the device list. Free it */
    pcap_freealldevs(all_device_list);

    return found;
}


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	//header->ts.tv_sec has seconds since 1 January 1970, epoch / Linux time
	//header->ts.tv_usec has microsecond offset 
	//header->len has length of complete packet
	//header->caplen has length of captured part of packet
	//pkt_data has header->len bytes of packet data
	unsigned char number[1024];
	uint32_t number_length;
	FILE *log_file;
	static int packet_number=1;
	int characters_read;
	char continue_message[10];

	log_file=fopen(LOG_FILE, "a");

	//Read continue message
	characters_read=read(0, continue_message, 5);
	if(characters_read<5)
	{
		fprintf(log_file, "EOF of input stream detected.\n");
		fclose(log_file);
		exit(EXIT_SUCCESS);
	}

	//Write packet number
	sprintf((char *)number, "%d", packet_number);
	number_length=strlen((char *)number);
	write_null_terminated_value(number, number_length);
	fprintf(log_file, "Wrote %s as packet_number\n", number);

	//Increment packet number
	packet_number++;


	//Write seconds
	sprintf((char *)number, "%d", (int) header->ts.tv_sec);
	number_length=strlen((char *) number);
	write_null_terminated_value(number, number_length);
	fprintf(log_file, "Wrote %s seconds\n", number);

	//Write Micro-seconds
	sprintf((char *) number, "%d", (int) header->ts.tv_usec);
	number_length=strlen((char *) number);
	write_null_terminated_value(number, number_length);
	fprintf(log_file, "Wrote %s microseconds\n", number);

	//Write captured packet length
	sprintf((char *)number, "%d", (int) header->caplen);
	number_length=strlen((char *)number);
	write_null_terminated_value(number, number_length);
	fprintf(log_file, "Wrote %s as length of packetdata\n", number);

	//Write packet_data
	write_null_terminated_value(pkt_data, header->caplen);
	fprintf(log_file, "Wrote %d bytes of packetdata\n", header->caplen);

	fclose(log_file);
}


void write_null_terminated_value(const u_char *data, int data_length_without_null)
{
	uint32_t length_in_network_order;
	char null=0;

	//convert length to network order after adding one for null
	length_in_network_order=htonl(data_length_without_null+1);

	write(1, &length_in_network_order, 4);
	write(1, data, data_length_without_null);
	write(1, &null, 1);
}



