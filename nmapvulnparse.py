import re
import argparse

# Komut satırı argümanlarını tanımlama
parser = argparse.ArgumentParser(description="Parse Nmap output to extract IIS, SQL, MySQL, and PostgreSQL versions, ports, and IP addresses, along with OS info, message signing, SSL certificate info, and Terminal Services info.")
parser.add_argument("filename", help="Path to the Nmap output file")
args = parser.parse_args()

# Nmap çıktısını dosyadan okuma
with open(args.filename, "r") as file:
    nmap_output = file.readlines()

# HTTP/SSL, SQL, OS bilgileri, Message Signing, SSL sertifikası ve Terminal Services için altı ayrı liste tanımlayın
http_hosts_info = []
sql_hosts_info = []
os_info = []
message_signing_info = []
ssl_ports_info = []
terminal_services_info = []
smb_signing_not_required_hosts = []
current_ip = None
current_ports = {}

# Satır satır işleme
for i, line in enumerate(nmap_output):
    # Satırın başındaki boşlukları ve '|' karakterini kaldır
    line_stripped = line.lstrip(' |')

    # IP adresini bul
    ip_match = re.match(r"Nmap scan report for (?:.+ )?\(?(\d+\.\d+\.\d+\.\d+)\)?", line_stripped)
    if ip_match:
        current_ip = ip_match.group(1)
        current_ports = {}  # Yeni bir IP bulunduğunda portları sıfırla
        continue

    # HTTP/SSL ve SQL servislerini bulma
    port_match_http = re.match(
        r"(\d+)/tcp\s+open\s+(?:ssl/)?http.*?Microsoft (?:IIS|HTTPAPI) (httpd \d+\.\d+)", 
        line_stripped
    )
    if port_match_http:
        port = port_match_http.group(1)
        service_version = port_match_http.group(2)
        current_ports[port] = f"Microsoft {service_version}"
        http_hosts_info.append({
            "IP:Port": f"{current_ip}:{port}",
            "Service Version": f"Microsoft {service_version}"
        })
        continue

    # SQL Server bilgilerini sadece yıl bilgisi ile bulma
    sql_match = re.match(r"(\d+)/tcp\s+open\s+.*?(Microsoft SQL Server).*?(\d{4})", line_stripped)
    if sql_match:
        port = sql_match.group(1)
        sql_type = sql_match.group(2)
        sql_year = sql_match.group(3)
        current_ports[port] = f"{sql_type} {sql_year}"
        sql_hosts_info.append({
            "IP:Port": f"{current_ip}:{port}",
            "Service Version": f"{sql_type} {sql_year}"
        })
        continue

    # http-server-header satırında Microsoft IIS sürüm bilgisi arama
    port_http_match = re.match(r"(\d+)/tcp\s+open\s+(?:ssl/)?http", line_stripped)
    if port_http_match:
        port = port_http_match.group(1)
        if port not in current_ports and i + 1 < len(nmap_output):
            next_line = nmap_output[i + 1].lstrip(' |')
            header_match = re.search(r"Microsoft-IIS/(\d+\.\d+)", next_line)
            if header_match:
                iis_version = header_match.group(1)
                current_ports[port] = f"Microsoft IIS {iis_version}"
                http_hosts_info.append({
                    "IP:Port": f"{current_ip}:{port}",
                    "Service Version": f"Microsoft IIS {iis_version}"
                })

    # OS bilgilerini bul ve ekle
    os_match = re.search(r"Service Info: OS(?:s)?: ([^\;]+);", line_stripped)
    if os_match and current_ip:
        os_version = os_match.group(1)
        if not any(host['IP'] == current_ip for host in os_info):
            os_info.append({
                "IP": current_ip,
                "OS": os_version
            })

    # "Message signing enabled but not required" ifadesini bul ve ekle
    if "Message signing enabled but not required" in line_stripped and current_ip:
        ip_port = f"{current_ip}:{port}"
        if not any(host['IP:Port'] == ip_port for host in message_signing_info):
            message_signing_info.append({
                "IP:Port": ip_port,
                "Message Signing": "Message signing enabled but not required"
            })

        # 445 portunu bulmaya çalış
        port_445_open = any(re.match(r"445/tcp\s+open", nmap_output[j].lstrip(' |')) for j in range(i))
        # 139 portunu bulmaya çalış
        port_139_open = any(re.match(r"139/tcp\s+open", nmap_output[j].lstrip(' |')) for j in range(i))

        # Port 445 açıksa, IP:445 ekle
        if port_445_open:
            smb_signing_not_required_hosts.append(f"{current_ip}:445")
        # Aksi halde, Port 139 açıksa, IP:139 ekle
        elif port_139_open:
            smb_signing_not_required_hosts.append(f"{current_ip}:139")

    # SSL sertifikası bilgisi içeren portları bulmak için yukarıya doğru kontrol yap
    if "ssl-cert" in line_stripped and current_ip:
        # ssl-cert ifadesinin bulunduğu satırdan yukarıya doğru bakarak en yakın açık portu bul
        for j in range(i - 1, -1, -1):
            previous_line = nmap_output[j].lstrip(' |')

            # Port kontrolü yapıyoruz
            port_match = re.match(r"(\d+)/tcp\s+open", previous_line)
            if port_match:
                ssl_port = port_match.group(1)

                # IP ve portu birleştirip listeye ekleme kontrolü yapıyoruz
                ip_port = f"{current_ip}:{ssl_port}"

                # Aynı IP ve portun tekrar eklenmemesi için kontrol
                if ip_port not in ssl_ports_info:
                    ssl_ports_info.append(ip_port)
                break

    # Terminal Services (3389/tcp) açık olanları bul
    if re.match(r"3389/tcp\s+open", line_stripped) and current_ip:
        ip_port = f"{current_ip}:3389"
        terminal_services_info.append(ip_port)

# Sonuçları yazdırma
print("HTTP/SSL Server Information:")
for host in http_hosts_info:
    print(f"IP:Port: {host['IP:Port']}, Service Version: {host['Service Version']}")

print("\nSQL Server Information:")
for host in sql_hosts_info:
    print(f"IP:Port: {host['IP:Port']}, Service Version: {host['Service Version']}")

print("\nOperating System Information:")
for host in os_info:
    print(f"IP: {host['IP']}, OS: {host['OS']}")

print("\nHosts with Message Signing Enabled but Not Required:")
for host in message_signing_info:
    print(f"IP:Port: {host['IP:Port']}, {host['Message Signing']}")

print("\nSMB Signing Not Required Hosts:")
for ip_port in smb_signing_not_required_hosts:
    print(ip_port)

print("\nPorts with SSL Certificate Information:")
for ip_port in ssl_ports_info:
    print(f"{ip_port}")

print("\nHosts with Terminal Services:")
for ip_port in terminal_services_info:
    print(f"{ip_port}")
