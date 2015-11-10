#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <curl/curl.h>

uintmax_t ts;

void button_press()
{
	CURL *curl = curl_easy_init();
	if(curl) {
		CURLcode res;
		curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1/hue");
		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);
	}
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
	    const u_char *packet)
{
	uintmax_t nts = NULL;
	if (ts == NULL) {
		ts = (uintmax_t)time(NULL);
	}
	else {
		nts = (uintmax_t)time(NULL);
	}
	if (nts == NULL) {
		button_press();
		printf("Jacked a packet with length of [%d]\n", header->len);
		printf("Button pressed\n");
		return;
	}
	if ( nts > ts + 5) {
		button_press();
		printf("Jacked a packet with length of [%d]\n", header->len);
		printf("Button pressed\n");
		ts = nts;
	}
}
int main()
{
	pcap_t *handle;
	char dev[] = "net1";
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	struct pcap_pkthdr header;
	char filter_exp[] = "ether src 74:c2:46:e8:ab:11 and arp";

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle);
	return(0);
}
