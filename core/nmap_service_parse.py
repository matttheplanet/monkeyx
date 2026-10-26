#!/usr/bin/python3
import os
import re
from sys import argv

from bs4 import BeautifulSoup


# A legitimate nmap service `name` is a short token — "http", "ssh",
# "ms-wbt-server", "ssl/https", "netbios-ssn". A corrupt nmap XML can leak NSE
# script output (e.g. the multi-line vulners CVE blob) INTO the service `name`
# attribute — then `name` carries tabs/newlines/URLs and runs to thousands of
# chars. That garbage otherwise flows straight into scan.db's ports.service
# column and the report's ports table. Reject anything that isn't a plausible
# service token; product/version/banner still populate from their own attrs, so
# the useful fingerprint ("Samba smbd 4.19.5-Ubuntu") is preserved.
_SERVICE_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+/-]{0,39}$')


def clean_service_name(name):
	"""Return `name` if it is a plausible nmap service token, else ''."""
	name = (name or "").strip()
	if not name or not _SERVICE_NAME_RE.match(name):
		return ""
	return name


# reads an xml file and returns a beautiful soup object for parsing
def read_xmlfile(filename):
	"""Parse an nmap XML file into a BeautifulSoup tree.

	Raises ValueError on a missing/unreadable/malformed file. It must NOT call
	exit()/sys.exit(): the callers (ax_nmap_tcp / ax_nmap_udp) wrap this in
	`except Exception` to degrade gracefully, but SystemExit is a BaseException
	that slips past that handler and kills the ENTIRE scan — so one corrupt XML
	from one host aborts the whole engagement. Raising a normal exception lets
	the caller log-and-continue.
	"""
	try:
		with open(filename, 'r', encoding="utf-8", errors="replace") as xml:
			content = xml.read()
	except OSError as e:
		raise ValueError(f"Could not open nmap XML {filename}: {e}") from e
	# Strip the DOCTYPE (INCLUDING any internal subset `[ ... ]` that carries
	# <!ENTITY ...> declarations) before parsing, so a hostile banner embedded in
	# the XML can't trigger entity expansion (billion-laughs) or external-entity
	# resolution via the lxml backend. The internal subset contains its own '>'
	# chars, so a naive `<!DOCTYPE...>` match would stop short and leave orphaned
	# markup — match the optional `[...]` block explicitly.
	content = re.sub(r'<!DOCTYPE[^>\[]*(\[[^\]]*\])?\s*>', '', content,
	                 count=1, flags=re.DOTALL | re.IGNORECASE)
	# Belt-and-suspenders: drop any stray ENTITY declarations left outside a DOCTYPE.
	content = re.sub(r'<!ENTITY[^>]*>', '', content, flags=re.IGNORECASE)
	try:
		return BeautifulSoup(content, "xml")
	except Exception as e:
		raise ValueError(f"Could not parse nmap XML {filename}: {e}") from e


# writes web urls to outfile
def write_gowit_file(urls, prefix, module_id):
	"""Write URLs to file with prefix and module identifier.
	
	Args:
		urls: List of URLs to write
		prefix: Output prefix (e.g., "/output/2026-03-02")
		module_id: Module identifier (e.g., "baseline", "tcpfull", "udp")
	"""
	if len(urls) < 1:
		return
	with open(f"{prefix}-{module_id}-weburls.txt", 'w', encoding="utf-8") as outfile:
		for url in urls:
			outfile.write(f"{url}\n")


# general function to write a new list of parsed services
def output_services(services, filename):
	# don't write an empty list
	if len(services) < 1:
		return
	with open(f"{filename}", 'w', encoding="utf-8") as outfile:
		for service in services:
			outfile.write(f"{service}\n")


# general function to append to a list of parsed services
def append_services(services, filename):
	# don't write an empty list
	if len(services) < 1:
		return
	sockets_already_in_file = list()
	try:
		with open(f"{filename}", 'r', encoding="utf-8") as outfile:
			for socket in outfile:
				sockets_already_in_file.append(socket)
		with open(f"{filename}", 'a', encoding="utf-8") as outfile:
			for service in services:
				if service not in sockets_already_in_file:
					outfile.write(f"{service}\n")
	except FileNotFoundError:
		output_services(services, filename)


# extract hostnames from a host element (returns deduped, lowercased list)
def extract_hostnames(host):
	"""Pull all <hostname> entries from a host element, return as a sorted list.

	Returns an empty list if no hostnames are present.
	"""
	names = set()
	for hn in host.find_all("hostname"):
		name = (hn.get("name") or "").strip().lower()
		if name:
			names.add(name)
	return sorted(names)


# constructs gowitness/nuclei urls and returns unique HTTP(s) formatted urls.
# Each candidate is a tuple: (ip, port, hostnames_list)
# URLs are emitted for the IP AND each hostname, so vhost-routed sites get hit.
def sort_gowitness_urls(http_candidates, https_candidates):
	final_candidates = set()
	for ip, port, hostnames in http_candidates:
		port = str(port).strip()
		ip = ip.strip().lower()
		hosts_to_emit = [ip] + [h.strip().lower() for h in hostnames if h.strip()]
		for host in hosts_to_emit:
			if port == '80':
				final_candidates.add(f'http://{host}')
			else:
				final_candidates.add(f'http://{host}:{port}')
	for ip, port, hostnames in https_candidates:
		port = str(port).strip()
		ip = ip.strip().lower()
		hosts_to_emit = [ip] + [h.strip().lower() for h in hostnames if h.strip()]
		for host in hosts_to_emit:
			if port == '443':
				final_candidates.add(f'https://{host}')
			else:
				final_candidates.add(f'https://{host}:{port}')
	return(final_candidates)


# takes an nmap XML file and outputs files for relevant TCP services when identified
def nmap_to_tcphosts(nmapfile, prefix, module_id):
	"""Parse TCP nmap results and create module-specific output files.
	
	Args:
		nmapfile: Path to nmap XML file
		prefix: Output prefix (e.g., "/output/2026-03-02")
		module_id: Module identifier (e.g., "baseline", "tcpfull")
	"""
	print(f"Parsing TCP services from {nmapfile}")
	http_candidates = list()
	https_candidates = list()
	unidentified_candidates = list()
	tcpwrapped_services = list()
	ssh_services = list()
	msrdp_services = list()
	ssl_services = set()
	ftp_services = list()
	mail_services = list()
	nfs_services = list()
	database_services = list()
	smb_netbios_services = list()
	alive_hosts = set()
	xml = read_xmlfile(nmapfile)

	# iterate through all hosts in nmap file
	for host in xml.find_all("host"):
		ip = host.address['addr']
		hostnames = extract_hostnames(host)
		# iterate through each open port on a host
		for ports in host.find_all("ports"):
			for port in ports.find_all("port"):
				if port.state["state"] != "open":
					continue
				alive_hosts.add(ip)
				portid = port['portid']
				socket = f"{ip}:{portid}"
				if port.service != None:
					# print(port)
					if port.service["name"] == 'tcpwrapped':
						# print(f"tcpwrapped found: {socket}")
						tcpwrapped_services.append(socket)
					elif 'http' in port.service['name']:
						# print(socket, port.service, type(port.service))
						if port.service['name'] == 'https':
							https_candidates.append((ip, portid, hostnames))
							ssl_services.add(socket)
						elif port.service.has_attr("tunnel"):
							if "ssl" in port.service['tunnel']:
								https_candidates.append((ip, portid, hostnames))
								ssl_services.add(socket)
						else:
							http_candidates.append((ip, portid, hostnames))
					elif port.service['name'] == "ssh":
						ssh_services.append(socket)
					elif port.service['name'] == "ms-wbt-server":
						msrdp_services.append(socket)
						ssl_services.add(socket)
					elif port.service['name'] == "ftp":
						ftp_services.append(socket)
					elif port.service['name'] == "smtp":
						mail_services.append(socket)
					elif port.service['name'] == "imap":
						mail_services.append(socket)
					elif port.service['name'] == "pop3":
						mail_services.append(socket)
					elif port.service['name'] == "nfs":
						nfs_services.append(socket)
					elif port.service['name'] == "microsoft-ds" or port.service['name'] == "netbios-ssn":
						smb_netbios_services.append(socket)
					elif "sql" in port.service['name']:
						database_services.append(socket)
					elif grep_http(port.service):
						unidentified_candidates.append(socket)
					# catch all for any service using SSL for encryption
					if port.service.has_attr("tunnel"):
						if "ssl" in port.service['tunnel']:
							ssl_services.add(socket)
				# else:
				# 	print(f"serviceless open port found: {socket}")

	urls = sort_gowitness_urls(http_candidates, https_candidates)
	write_gowit_file(urls, prefix, module_id)
	output_services(tcpwrapped_services, f"{prefix}-{module_id}-tcpwrapped.txt")
	output_services(unidentified_candidates, f"{prefix}-{module_id}-unchecked-http-candidates.txt")
	output_services(ssh_services, f"{prefix}-{module_id}-ssh-hosts.txt")
	output_services(msrdp_services, f"{prefix}-{module_id}-msrdp-hosts.txt")
	output_services(ssl_services, f"{prefix}-{module_id}-sslscan-hosts.txt")
	output_services(ftp_services, f"{prefix}-{module_id}-ftp-hosts.txt")
	output_services(mail_services, f"{prefix}-{module_id}-mail-hosts.txt")
	output_services(nfs_services, f"{prefix}-{module_id}-nfs-hosts.txt")
	output_services(smb_netbios_services, f"{prefix}-{module_id}-smb-netbios-hosts.txt")
	output_services(alive_hosts, f"{prefix}-{module_id}-alive-hosts.txt")
	output_services(database_services, f"{prefix}-{module_id}-database-hosts.txt")


# takes an nmap XML file and outputs files for relevant UDP services when identified
def nmap_to_udphosts(nmapfile, prefix, module_id):
	"""Parse UDP nmap results and create module-specific output files.
	
	Args:
		nmapfile: Path to nmap XML file
		prefix: Output prefix (e.g., "/output/2026-03-02")
		module_id: Module identifier (e.g., "udp")
	"""
	print(f"Parsing UDP services from {nmapfile}")
	http_candidates = list()
	https_candidates = list()
	unidentified_candidates = list()
	tcpwrapped_services = list()
	msrdp_services = list()
	ssl_services = set()
	mail_services = list()
	snmp_services = list()
	ike_services = list()
	nfs_services = list()
	alive_hosts = set()
	xml = read_xmlfile(nmapfile)

	# iterate through all hosts in nmap file
	for host in xml.find_all("host"):
		ip = host.address['addr']
		hostnames = extract_hostnames(host)
		# iterate through each open port on a host
		for ports in host.find_all("ports"):
			for port in ports.find_all("port"):
				if port.state["state"] != "open":
					continue
				alive_hosts.add(ip)
				portid = port['portid']
				socket = f"{ip}:{portid}"
				if port.service != None:
					# print(port)
					if port.service["name"] == 'tcpwrapped':
						# print(f"tcpwrapped found: {socket}")
						tcpwrapped_services.append(socket)
					elif 'http' in port.service['name']:
						# print(socket, port.service, type(port.service))
						if port.service['name'] == 'https':
							https_candidates.append((ip, portid, hostnames))
							ssl_services.add(socket)
						elif port.service.has_attr("tunnel"):
							if "ssl" in port.service['tunnel']:
								https_candidates.append((ip, portid, hostnames))
								ssl_services.add(socket)
						else:
							http_candidates.append((ip, portid, hostnames))
					elif port.service['name'] == "ms-wbt-server":
						msrdp_services.append(socket)
					elif port.service['name'] == "smtp":
						mail_services.append(socket)
					elif port.service['name'] == "imap":
						mail_services.append(socket)
					elif port.service['name'] == "pop3":
						mail_services.append(socket)
					elif port.service['name'] == "snmp":
						snmp_services.append(socket)
					elif port.service['name'] == "isakmp":
						ike_services.append(socket)
					elif port.service['name'] == "nfs":
						nfs_services.append(socket)
					elif grep_http(port.service):
						unidentified_candidates.append(socket)
					# This will probably never exist with UDP services but we'll add it anyway!
					if port.service.has_attr("tunnel"):
						if "ssl" in port.service['tunnel']:
							ssl_services.add(socket)
				# else:
				# 	print(f"serviceless open port found: {socket}")

	urls = sort_gowitness_urls(http_candidates, https_candidates)
	write_gowit_file(urls, prefix, module_id)
	output_services(tcpwrapped_services, f"{prefix}-{module_id}-tcpwrapped.txt")
	output_services(unidentified_candidates, f"{prefix}-{module_id}-unchecked-http-candidates.txt")
	output_services(msrdp_services, f"{prefix}-{module_id}-msrdp-hosts.txt")
	output_services(ssl_services, f"{prefix}-{module_id}-sslscan-hosts.txt")
	output_services(mail_services, f"{prefix}-{module_id}-mail-hosts.txt")
	output_services(snmp_services, f"{prefix}-{module_id}-snmp-hosts.txt")
	output_services(nfs_services, f"{prefix}-{module_id}-nfs-hosts.txt")
	output_services(ike_services, f"{prefix}-{module_id}-ike-hosts.txt")
	output_services(alive_hosts, f"{prefix}-{module_id}-alive-hosts.txt")
			
### function to simulate the grep command we're using when the http service isn't explicitly defined
### can help pick up potential SSL-protected services, API endpoints, proxies, etc.
def grep_http(service):
	keywords = ['http', 'tls', 'ssl']
	for keyword in keywords:
		for key in service.attrs:
			if keyword in service[key].lower():
				return True
	return False


def main():
	if len(argv) != 2:
		print("Usage: ./parsers.py {filename}\n")
		exit(1)
	filename = argv[1]
	prefix = os.path.splitext(filename)[0]
	if "tcp" in filename.lower():
		nmap_to_tcphosts(filename, prefix, "standalone")
	elif "udp" in filename.lower():
		nmap_to_udphosts(filename, prefix, "standalone")
	else:
		print("Could not determine if nmap file contains tcp or udp results based off filename.")
		exit(1)



if __name__ == "__main__":
	main()
