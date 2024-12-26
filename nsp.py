import re
import argparse
from datetime import datetime

# Komut satırı argümanlarını tanımlama
parser = argparse.ArgumentParser(description="Parse Nmap output to extract IP and port information with vulnerable TLS/SSL versions/ciphers and weak signature algorithms.")
parser.add_argument("filename", help="Path to the Nmap output file")
args = parser.parse_args()

# Dosyadan nmap çıktısını okuma
with open(args.filename, "r") as file:
    nmap_output = file.readlines()

# Anahtar kelimeler
vulnerable_tls_versions = ["TLSv1.0", "TLSv1.1"]
vulnerable_ssl_versions = ["SSLv2", "SSLv3"]
vulnerable_ciphers = {"DES": False, "3DES": False, "RC4": False}

# Çıktı depolamak için listeler
output_results = []
vulnerable_hosts = []  # TLSv1.0 veya TLSv1.1 içeren hostlar
vulnerable_ssl_hosts = []  # SSLv2 veya SSLv3 içeren hostlar
sweet32_vulnerable_hosts = []  # SWEET32 etkisindeki DES/3DES içeren hostlar
rc4_vulnerable_hosts = []  # RC4 etkisindeki hostlar
poodle_vulnerable_hosts = []  # POODLE etkisindeki SSLv3 CBC içeren hostlar
weak_signature_hosts = []  # Weak Signature Algorithm içeren hostlar
expired_cert_hosts = []  # Süresi dolmuş SSL sertifikası olan hostlar
anonymous_cipher_hosts = []  # Anonim şifreleme içeren hostlar

# İşlem için değişkenler
current_ip = None
current_port_status = None
current_tls_version = None
current_ssl_version = None
found_vulnerable_tls = False
found_vulnerable_ssl = False
found_vulnerable_cipher = False
found_poodle_vulnerability = False
found_weak_signature = False
cert_expired = False
found_anonymous_cipher = False

for line in nmap_output:
    # IP adresini bul
    ip_match = re.match(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", line)
    if ip_match:
        # Önceki IP için bilgileri kaydet
        if current_ip and current_port_status:
            is_secure = not (found_vulnerable_tls or found_vulnerable_ssl or found_vulnerable_cipher or found_weak_signature or found_poodle_vulnerability or cert_expired or found_anonymous_cipher)
            ip_output = f"{current_ip}:{current_port_status.split()[0]}"
            if is_secure and "open" in current_port_status:
                ip_output += " (güvenli)"
            output_results.append(ip_output)

            # Güvenlik risklerine göre ilgili listeye ekleme
            if found_vulnerable_tls:
                vulnerable_hosts.append(ip_output)
            if found_vulnerable_ssl:
                vulnerable_ssl_hosts.append(ip_output)
            if found_vulnerable_cipher:
                if vulnerable_ciphers["DES"] or vulnerable_ciphers["3DES"]:
                    sweet32_vulnerable_hosts.append(ip_output)
                if vulnerable_ciphers["RC4"]:
                    rc4_vulnerable_hosts.append(ip_output)
            if found_poodle_vulnerability:
                poodle_vulnerable_hosts.append(ip_output)
            if found_weak_signature:
                weak_signature_hosts.append(ip_output)
            if cert_expired:
                expired_cert_hosts.append(ip_output)
            if found_anonymous_cipher:
                anonymous_cipher_hosts.append(ip_output)

        # Yeni IP için değişkenleri sıfırla
        current_ip = ip_match.group(1)
        current_port_status = None
        current_tls_version = None
        current_ssl_version = None
        found_vulnerable_tls = False
        found_vulnerable_ssl = False
        found_vulnerable_cipher = False
        found_poodle_vulnerability = False
        found_weak_signature = False
        cert_expired = False
        found_anonymous_cipher = False
        vulnerable_ciphers = {key: False for key in vulnerable_ciphers}
        continue

    # Açık, filtered veya closed portları bul
    port_status_match = re.match(r"(\d+)/tcp\s+(open|filtered|closed)", line)
    if port_status_match:
        port = port_status_match.group(1)
        port_status = port_status_match.group(2)
        current_port_status = f"{port} {port_status}"
        continue

    # TLS ve SSL versiyonları kontrol etme
    tls_version_match = re.match(r"\|\s+(TLSv\d\.\d):", line)
    ssl_version_match = re.match(r"\|\s+(SSLv2|SSLv3):", line)
    if tls_version_match:
        current_tls_version = tls_version_match.group(1)
        if current_tls_version in vulnerable_tls_versions:
            found_vulnerable_tls = True
    elif ssl_version_match:
        current_ssl_version = ssl_version_match.group(1)
        if current_ssl_version in vulnerable_ssl_versions:
            found_vulnerable_ssl = True
            if current_ssl_version == "SSLv3":
                found_poodle_vulnerability = any("CBC" in line for line in nmap_output)

    # POODLE için CBC içeren SSLv3 algoritmaları kontrol etme
    if current_ssl_version == "SSLv3" and "CBC" in line:
        found_poodle_vulnerability = True

    # Anonim şifreleme algoritmalarını kontrol etme
    if "anon" in line:
        found_anonymous_cipher = True

    # Cipher algoritmaları kontrol etme
    if (current_tls_version or current_ssl_version) and any(cipher in line for cipher in vulnerable_ciphers.keys()):
        if not any(exclude in line for exclude in ["SWEET32", "deprecated by RFC"]):
            found_vulnerable_cipher = True
            for cipher in vulnerable_ciphers.keys():
                if cipher in line:
                    vulnerable_ciphers[cipher] = True

    # Weak Signature Algorithm kontrol etme
    if "Signature Algorithm: sha1WithRSAEncryption" in line:
        found_weak_signature = True

    # Expired SSL Sertifikası kontrol etme
    cert_expiry_match = re.search(r"Not valid after:\s+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
    if cert_expiry_match:
        expiry_date = datetime.strptime(cert_expiry_match.group(1), "%Y-%m-%dT%H:%M:%S")
        if expiry_date < datetime.now():
            cert_expired = True

# Son IP için bilgileri kaydet
if current_ip and current_port_status:
    is_secure = not (found_vulnerable_tls or found_vulnerable_ssl or found_vulnerable_cipher or found_weak_signature or found_poodle_vulnerability or cert_expired or found_anonymous_cipher)
    ip_output = f"{current_ip}:{current_port_status.split()[0]}"
    if is_secure and "open" in current_port_status:
        ip_output += " (güvenli)"
    output_results.append(ip_output)

    # Güvenlik risklerine göre ilgili listeye ekleme
    if found_vulnerable_tls:
        vulnerable_hosts.append(ip_output)
    if found_vulnerable_ssl:
        vulnerable_ssl_hosts.append(ip_output)
    if found_vulnerable_cipher:
        if vulnerable_ciphers["DES"] or vulnerable_ciphers["3DES"]:
            sweet32_vulnerable_hosts.append(ip_output)
        if vulnerable_ciphers["RC4"]:
            rc4_vulnerable_hosts.append(ip_output)
    if found_poodle_vulnerability:
        poodle_vulnerable_hosts.append(ip_output)
    if found_weak_signature:
        weak_signature_hosts.append(ip_output)
    if cert_expired:
        expired_cert_hosts.append(ip_output)
    if found_anonymous_cipher:
        anonymous_cipher_hosts.append(ip_output)

# Sonuçları yazdırma
print("Hosts and Ports:")
for result in output_results:
    print(f"{result}")

# TLS 1.0 ve 1.1 olan hostları listele
if vulnerable_hosts:
    print("\nHosts with TLSv1.0 or TLSv1.1:")
    for host in vulnerable_hosts:
        print(f"{host}")

# SSLv2 ve SSLv3 olan hostları listele
if vulnerable_ssl_hosts:
    print("\nVulnerable SSL Hosts (SSLv2, SSLv3):")
    for host in vulnerable_ssl_hosts:
        print(f"{host}")

# SWEET32 zafiyeti olan hostları listele
if sweet32_vulnerable_hosts:
    print("\nSWEET32 Vulnerables:")
    for host in sweet32_vulnerable_hosts:
        print(f"{host}")

# RC4 zafiyeti olan hostları listele
if rc4_vulnerable_hosts:
    print("\nRC4 Vulnerables:")
    for host in rc4_vulnerable_hosts:
        print(f"{host}")

# POODLE zafiyeti olan hostları listele
if poodle_vulnerable_hosts:
    print("\nPOODLE Vulnerable Hosts:")
    for host in poodle_vulnerable_hosts:
        print(f"{host}")

# Expired SSL Sertifikası içeren hostları listele
if expired_cert_hosts:
    print("\nExpired SSL Certificate Hosts:")
    for host in expired_cert_hosts:
        print(f"{host}")

# Anonymous Cipher içeren hostları listele
if anonymous_cipher_hosts:
    print("\nAnonymous Cipher Hosts:")
    for host in anonymous_cipher_hosts:
        print(f"{host}")

# Weak Signature Algorithm içeren hostları listele
if weak_signature_hosts:
    print("\nWeak Signature Algorithm Hosts:")
    for host in weak_signature_hosts:
        print(f"{host}")
