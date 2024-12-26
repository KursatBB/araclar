#!/bin/bash
# Bu araç hostname mismatch ve self-signed sertifikaları kontrol edip bir araya getirerek cant trustedları cantrust.txt altına atar.
# Sertifika geçerlilik süresi geçmiş sertifikaları kontrol edip expire.txt içerisine atar.
# sertifika algoritması md2 md4 md5 ve sha1 algoritmalarından biri mi kontrol edip öylerse weak_alg.txt içerisine atar.

# Kontrol edilecek dosya
if [ -z "$1" ]; then
    echo "Kullanım: $0 <domain_file>"
    exit 1
fi

DOMAIN_FILE="$1"

# Güvenilir sertifika otoriteleri
TRUSTED_ISSUERS=("Let's Encrypt" "DigiCert" "GlobalSign" "Comodo" "Symantec" "TUGRA")

# Zayıf algoritmalar
WEAK_ALGORITHMS=("md2" "md4" "md5" "sha1" "sha1WithRSAEncryption")

# Çıktı dosyaları
WEAK_ALG_FILE="weak_alg.txt"
EXPIRED_FILE="expired.txt"
CAN_TRUST_FILE="cantrust.txt"
ALL_OUTPUT_FILE="all_output.txt"

# Eski dosyaları temizle
> "$WEAK_ALG_FILE"
> "$EXPIRED_FILE"
> "$CAN_TRUST_FILE"
> "$ALL_OUTPUT_FILE"

# Dosyayı okuyarak her bir domain:port için işlem yap
while IFS= read -r line; do
    DOMAIN_PORT=$line
    DOMAIN=$(echo "$DOMAIN_PORT" | cut -d':' -f1)
    PORT=$(echo "$DOMAIN_PORT" | cut -d':' -f2)

    {
        echo "Taranan Host : $DOMAIN:$PORT"
        
        # Sertifika bilgilerini ve doğrulama hatalarını çek
        CERT_INFO=$(timeout 5 openssl s_client -connect $DOMAIN:$PORT -servername $DOMAIN </dev/null 2>&1)
        CERT=$(echo "$CERT_INFO" | openssl x509 -noout -issuer -subject -ext subjectAltName)

        if [[ "$CERT_INFO" == *"verify error"* ]]; then
            echo "$CERT_INFO" | grep "verify error"
            if [[ "$CERT_INFO" == *"self signed"* || "$CERT_INFO" == *"hostname mismatch"* ]]; then
                echo "$DOMAIN_PORT" >> "$CAN_TRUST_FILE"
            fi
            if [[ "$CERT_INFO" == *"certificate has expired"* ]]; then
                echo "$DOMAIN_PORT" >> "$EXPIRED_FILE"
            fi
        fi

        if [[ -z "$CERT" ]]; then
            echo "Sertifika alınamadı veya site HTTPS kullanmıyor: $DOMAIN:$PORT"
            echo ""
            continue
        fi

        # Sertifika algoritmasını kontrol et
        CERT_ALGORITHM=$(echo "$CERT_INFO" | grep -oP "Signature Algorithm: \K.*")

        echo "Signature Algorithm: $CERT_ALGORITHM"

        for WEAK_ALG in "${WEAK_ALGORITHMS[@]}"; do
            if [[ "$CERT_ALGORITHM" == *"$WEAK_ALG"* ]]; then
                echo "$DOMAIN_PORT" >> "$WEAK_ALG_FILE"
            fi
        done

        # Sertifika bilgilerini ekrana ve all_output dosyasına yaz
        echo "$CERT"

        # İssuer bilgilerini kontrol et
        ISSUER=$(echo "$CERT" | grep 'issuer=' | sed 's/issuer=//')

        TRUSTED=false
        for TRUSTED_ISSUER in "${TRUSTED_ISSUERS[@]}"; do
            if [[ "$ISSUER" == *"$TRUSTED_ISSUER"* ]]; then
                TRUSTED=true
                break
            fi
        done

        if [ "$TRUSTED" = false ]; then
            echo "Uyarı: Sertifika güvenilmeyen bir otorite tarafından verilmiş: $ISSUER"
            echo "$DOMAIN_PORT" >> "$CAN_TRUST_FILE"
        elif [ "$ISSUER" = false ]; then
            echo "Sertifika güvenilir bir otorite tarafından verilmiş: $ISSUER"
        fi

        # Self-signed sertifika kontrolü
        if [[ "$CERT_INFO" == *"self-signed"* ]]; then
            echo "Uyarı: Sertifika self-signed: $DOMAIN:$PORT"
            echo "$DOMAIN_PORT" >> "$CAN_TRUST_FILE"
        fi

        echo ""
    } | tee -a "$ALL_OUTPUT_FILE"

done < "$DOMAIN_FILE"
