##################################################################################
#
# netknuddel.sh 
#
##################################################################################
#
# analyse pcap file and create report
#
##################################################################################
#
# version:      0.6 
# version:      0.7 
# date:	        23.10.2017
# (c) by:       christoph weber 
#
##################################################################################
#
# 0.1           initial version 
# 0.2		some update
# 0.3		referer list
# 0.4		nbns
# 0.5		bug fixing 
# 0.6 		oui-mac + bootp-Hostname
# 0.7           capinfos UTC 
# 
##################################################################################
# 
# tshark -r FILE.pcap -Y "dns.flags.response == 1" -T fields -E separator=\;  -e dns.qry.name -e dns.a |sort | uniq 
#
##################################################################################
#	variables
#
TSHARK=tshark
# 
##################################################################################
#
# check pcap file 
#
##################################################################################
# check if a pcapfile is selected 
# 
PCAPFILE=$1
if [ "$PCAPFILE" == "" ]
then 
	echo "No Filename selected"
	exit 1
fi
#
# read pcap file name  
#
if [ ! -r $PCAPFILE ]
then 
	echo "can not open pcap file: "$PCAPFILE
	exit 1
fi
#
# check file format 
#
$TSHARK -r $PCAPFILE -c 1 >>/dev/null
RC=$?
if [ "$RC" != "0" ]
then 
	echo "the File :"$PCAPFILE" ist not a readable Fileformat"
	echo -n "Filetpye: "
	file $PCAPFILE
	exit 1
fi
##################################################################################
#
# netknuddel message
#
##################################################################################
nk_msg(){
        TITEL=$1
        TITEL2=$2
        echo "#############################################################################" 
        echo "   "$TITEL 
        echo "   "$TITEL2 
        echo "#############################################################################"
        }
#
#
##################################################################################
#
# netknuddel capinfo
#
##################################################################################
#
nk_capinfo()
	{
	nk_msg "Pcap Filesummary" "capinfos"
	capinfos  $PCAPFILE
	}
#
nk_captimeinfo()
	{
	nk_msg "File Stat/End Time" "Filedate"
	capinfos -a -e $PCAPFILE
	nk_msg "File Stat/End Time" "UTC"
	TZ=UTC capinfos -a -e $PCAPFILE
        }
	
##################################################################################
#
# netknuddel display User Agent Summary / all types of seen Useragents 
#
##################################################################################
#
nk_http_user_agent()
	{
	nk_msg "User Agent" "Summary"
	$TSHARK -r $PCAPFILE -Y http.request -T fields -e http.user_agent | sort -u 
	}
#
##################################################################################
#
# netknuddel display User Agent Summary / all types of seen Useragents vi sourec ip
#
##################################################################################
#
nk_http_user_ip_agent()
	{
	nk_msg "User Agent" "src ip / browsertype"
	$TSHARK -r $PCAPFILE -Y http.request -T fields -e ip.src -e http.user_agent  | sort -u 
	}
#
##################################################################################
#
# netknuddel display User Agent / and count of seen UA
#
##################################################################################
#
nk_http_user_cnt_agent()
	{
	nk_msg "User Agent" "cnt / browsertype"
	$TSHARK -r $PCAPFILE -Y http.request -T fields  -e http.user_agent | sort | uniq -c | sort -n
	}
#
##################################################################################
#
# netknuddel get requrests
#
##################################################################################
#
ü
nk_http_get_requests()
	{
	nk_msg "get requests" "src/dst-ip host uri"
	$TSHARK -r $PCAPFILE  -Y http.request -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri
	}
#
##################################################################################
#
# netknuddel get full request
#
##################################################################################
#
nk_http_full_request()
	{
	nk_msg "get requests" "full uri"
	$TSHARK -r $PCAPFILE  -Y http.request -T fields -e http.request.full_uri
	}
#
##################################################################################
#
# netknuddel host get-request referer
#
##################################################################################
#
nk_http_full_request_referer()
	{
	nk_msg "host get requests referer" "host http.request http.refere"
	$TSHARK -r $PCAPFILE  -Y http.request -T fields -e http.host -e http.request.full_uri -e http.referer
	}
#
##################################################################################
#
# netknuddel get hosts 
#
##################################################################################
#
nk_http_host()
	{
	nk_msg "get requests" "uniq host"
	$TSHARK -r $PCAPFILE  -Y http.request -T fields -e http.host | sort -u 
	}
#
##################################################################################
#
# netknuddel GET Requests
#
##################################################################################
#
nk_http_get_met()
	{
	nk_msg "GET Methode" "src/dst ip methode full uri"
	$TSHARK -r $PCAPFILE -Y "http.request.method == GET" -T fields -e ip.src -e ip.dst -e http.request.method -e http.request.full_uri 
	}
#
##################################################################################
#
# netknuddel  NOT GET Requests
#
##################################################################################
#
nk_http_notget_met()
	{
	nk_msg "NOT GET Methode" "src/dst ip methode full uri"
	$TSHARK -r $PCAPFILE -Y "http.request.method != GET" -T fields -e ip.src -e ip.dst -e http.request.method -e http.request.full_uri 
	}
#
##################################################################################
#
# netknuddel  http Respose 200
#
##################################################################################
#
nk_http_response200()
	{
	nk_msg "HTTP Response 200" "src ip,dst ip,code,phrase"
	$TSHARK -r $PCAPFILE -Y "http.response.code == 200" -T fields  -e ip.src -e ip.dst -e http.response.code -e http.response.phrase
	}
#
##################################################################################
#
# netknuddel  http Respose NOT  200
#
##################################################################################
#
nk_http_responsenot200()
	{
	nk_msg "HTTP Response NOT  200" "src ip,dst ip,code,phrase"
	$TSHARK -r $PCAPFILE -Y "http.response.code == 200" -T fields  -e ip.src -e ip.dst -e http.response.code -e http.response.phrase
	}
#
##################################################################################
#
# netknuddel  http Respose code content length + type
#
##################################################################################
#
nk_http_response_short()
	{
	nk_msg "HTTP Response Type + Content " "src ip,dst ip,code,content length,content type"
	$TSHARK -r $PCAPFILE -Y "http.server" -T fields -e ip.src -e ip.dst -e http.response.code -e http.content_length -e http.content_type
	}
#
#
##################################################################################
#
# netknuddel  Web Report 
#
##################################################################################
#
nk_http_ultimate()
	{
	nk_msg "Ultimative WEB Report" "All Usable Infos"
	$TSHARK -r $PCAPFILE -Y 'http' -S -V -l -T fields -e ip.src -e ip.src_host -e ip.dst -e ip.dst_host -e http.accept -e http.accept_encoding -e http.accept_language -e http.authbasic -e http.authorization -e http.cache_control -e http.connection -e http.content_encoding -e http.content_length -e http.content_length_header -e http.content_type -e http.cookie -e http.date -e http.host -e http.last_modified -e http.location -e http.notification -e http.proxy_authenticate -e http.proxy_authorization -e http.proxy_connect_host -e http.proxy_connect_port -e http.referer -e http.request -e http.request.full_uri -e http.request.method -e http.request.uri -e http.request.version -e http.response -e http.response.code -e http.response.phrase -e http.sec_websocket_accept -e http.sec_websocket_extensions -e http.sec_websocket_key -e http.sec_websocket_protocol -e http.sec_websocket_version -e http.server -e http.set_cookie -e http.transfer_encoding -e http.upgrade -e http.user_agent -e http.www_authenticate -e http.x_forwarded_for -E header=y -Eseparator=, -Equote=d
	}
#
##################################################################################
#
# netknuddel  DNS Summary
#
##################################################################################
#
nk_dns_all()
	{
	nk_msg "DNS" " DNS All"
	$TSHARK -r $PCAPFILE -Y "dns" -T text
	}
#
##################################################################################
#
# netknuddel  DNS NXDOMAIN or SERVFAIL
#
##################################################################################
#
nk_dns_nx_sf()
	{
	nk_msg "DNS" "NXDOMAIN or SERVFAIL"
	$TSHARK -r $PCAPFILE -T fields -e dns.qry.name -e dns.flags.rcode -Y "dns.qry.name contains drush and dns.flags.response eq 1 and dns.flags.rcode != 0"
	}
#
#
##################################################################################
#
# netknuddel  nbns name + src ip
#
##################################################################################
#
nk_nbns_name_ip()
	{
	nk_msg "NBNS" "NBNS Name and IP"
	$TSHARK -r $PCAPFILE -T fields -Y nbns -T fields -e nbns.name -e ip.src | sort -u
	}
#
#
##################################################################################
#
# netknuddel  Vendeor OUI / MAC Address
#
##################################################################################
#
nk_oui_mac()
	{
	nk_msg "MAC Address " " OUI MAC"
	$TSHARK -lr $PCAPFILE -o gui.column.format:"rhs","%rhs","uhs","%uhs" | sort | uniq
	}
# 
#
##################################################################################
#
# netknuddel  mac / source ip / hostname based on DHCP 
#
##################################################################################
#
nk_bootp_hostname()
	{
	nk_msg "bootp Infos" "SRC-MAC / IP / Hostname"
	$TSHARK -lr $PCAPFILE -Y "bootp.option.type == 53" -Y "bootp.option.dhcp == 8" -T fields -e eth.src -e ip.src -e bootp.option.hostname
	}
##################################################################################
#
# netknuddel main
#
##################################################################################
#
nk_msg "Netknuddel Report" $PCAPFILE
nk_capinfo
nk_captimeinfo
nk_http_user_agent
nk_http_user_ip_agent
nk_http_user_cnt_agent
nk_http_get_requests
nk_http_full_request
nk_http_full_request_referer
nk_http_host
nk_http_get_met
nk_http_notget_met
#nk_http_responsenot200
#nk_http_responsenotnot200
nk_http_response_short
nk_http_ultimate
nk_dns_all
nk_dns_nx_sf
nk_nbns_name_ip
nk_oui_mac
nk_bootp_hostname
