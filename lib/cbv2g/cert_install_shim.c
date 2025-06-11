#include "cbv2g/cert_install_shim.h"
#include "cbv2g/iso_2/iso2_msgDefDatatypes.h"
#include "cbv2g/iso_2/iso2_msgDefEncoder.h"
#include "cbv2g/iso_2/iso2_msgDefDecoder.h"
#include "cbv2g/common/exi_bitstream.h"
#include "cbv2g/common/exi_header.h"
#include "cbv2g/common/exi_basetypes.h"
#include "cJSON.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Helper function to convert base64 to binary
static int base64_to_binary(const char* base64, uint8_t** binary, size_t* binary_len) {
    size_t base64_len = strlen(base64);
    *binary_len = (base64_len * 3) / 4;
    if (base64[base64_len - 1] == '=') (*binary_len)--;
    if (base64[base64_len - 2] == '=') (*binary_len)--;

    *binary = (uint8_t*)malloc(*binary_len);
    if (!*binary) return -1;

    // Base64 decoding table
    static const int8_t b64_lookup[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 00-0F */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 10-1F */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  /* 20-2F */
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,  /* 30-3F */
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  /* 40-4F */
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  /* 50-5F */
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  /* 60-6F */
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  /* 70-7F */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 80-8F */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 90-9F */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* A0-AF */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* B0-BF */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* C0-CF */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* D0-DF */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* E0-EF */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1   /* F0-FF */
    };

    for (size_t i = 0, j = 0; i < base64_len; i += 4, j += 3) {
        uint32_t sextet_a = b64_lookup[(unsigned char)base64[i]];
        uint32_t sextet_b = b64_lookup[(unsigned char)base64[i + 1]];
        uint32_t sextet_c = b64_lookup[(unsigned char)base64[i + 2]];
        uint32_t sextet_d = b64_lookup[(unsigned char)base64[i + 3]];

        if (sextet_a == -1 || sextet_b == -1 || 
            (sextet_c == -1 && base64[i + 2] != '=') || 
            (sextet_d == -1 && base64[i + 3] != '=')) {
            free(*binary);
            *binary = NULL;
            return -1;
        }

        uint32_t triple = (sextet_a << 18) | (sextet_b << 12) |
                         ((sextet_c == -1 ? 0 : sextet_c) << 6) |
                         (sextet_d == -1 ? 0 : sextet_d);

        if (j < *binary_len) (*binary)[j] = (triple >> 16) & 0xFF;
        if (j + 1 < *binary_len) (*binary)[j + 1] = (triple >> 8) & 0xFF;
        if (j + 2 < *binary_len) (*binary)[j + 2] = triple & 0xFF;
    }

    return 0;
}

// Helper function to convert binary to base64
static char* binary_to_base64(const uint8_t* binary, size_t binary_len) {
    const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t base64_len = ((binary_len + 2) / 3) * 4;
    char* base64 = (char*)malloc(base64_len + 1);
    if (!base64) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < binary_len; i += 3, j += 4) {
        uint32_t octet_a = i < binary_len ? binary[i] : 0;
        uint32_t octet_b = i + 1 < binary_len ? binary[i + 1] : 0;
        uint32_t octet_c = i + 2 < binary_len ? binary[i + 2] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        base64[j] = base64_chars[(triple >> 18) & 0x3F];
        base64[j + 1] = base64_chars[(triple >> 12) & 0x3F];
        base64[j + 2] = base64_chars[(triple >> 6) & 0x3F];
        base64[j + 3] = base64_chars[triple & 0x3F];
    }

    // Add padding
    size_t padding = (3 - (binary_len % 3)) % 3;
    for (i = 0; i < padding; i++) {
        base64[base64_len - 1 - i] = '=';
    }

    base64[base64_len] = '\0';
    return base64;
}

// Helper function to convert double to exi_signed_t
static void double_to_exi_signed(double value, exi_signed_t* exi_signed) {
    int64_t int_value = (int64_t)value;
    exi_basetypes_convert_64_to_signed(exi_signed, int_value);
}

// Helper function to convert exi_signed_t to double
static double exi_signed_to_double(const exi_signed_t* exi_signed) {
    int64_t int_value;
    exi_basetypes_convert_64_from_signed(exi_signed, &int_value);
    return (double)int_value;
}

int iso2_certificate_installation_req_encode_json_to_exi(const char* json_str, uint8_t** exi_buffer, size_t* exi_size) {
    printf("DEBUG: iso2_certificate_installation_req_encode_json_to_exi called with json_str=%p, exi_buffer=%p, exi_size=%p\n", (void*)json_str, (void*)exi_buffer, (void*)exi_size);
    fflush(stdout);
    if (!json_str || !exi_buffer || !exi_size) {
        printf("DEBUG: Error: NULL pointer passed\n");
        fflush(stdout);
        return -1;
    }

    // Parse JSON
    printf("DEBUG: Parsing JSON\n");
    fflush(stdout);
    cJSON* root = cJSON_Parse(json_str);
    if (!root) {
        printf("DEBUG: Error: Failed to parse JSON\n");
        fflush(stdout);
        return -2;
    }

    // Create EXI document
    printf("DEBUG: Creating EXI document\n");
    fflush(stdout);
    struct iso2_exiDocument exi_doc;
    memset(&exi_doc, 0, sizeof(exi_doc));

    // Initialize the V2G message and Body and CertificateInstallationReq
    init_iso2_V2G_Message(&exi_doc.V2G_Message);
    init_iso2_BodyType(&exi_doc.V2G_Message.Body);
    init_iso2_CertificateInstallationReqType(&exi_doc.V2G_Message.Body.CertificateInstallationReq);
    exi_doc.V2G_Message.Body.CertificateInstallationReq_isUsed = 1;

    // Get SessionID from JSON
    printf("DEBUG: Getting SessionID from JSON\n");
    fflush(stdout);
    cJSON* session_id = cJSON_GetObjectItem(root, "SessionID");
    if (session_id && session_id->valuestring) {
        size_t len = strlen(session_id->valuestring);
        exi_doc.V2G_Message.Header.SessionID.bytesLen = iso2_sessionIDType_BYTES_SIZE; // Always 8
        memset(exi_doc.V2G_Message.Header.SessionID.bytes, 0, iso2_sessionIDType_BYTES_SIZE); // Zero out
        memcpy(exi_doc.V2G_Message.Header.SessionID.bytes, session_id->valuestring, len > iso2_sessionIDType_BYTES_SIZE ? iso2_sessionIDType_BYTES_SIZE : len); // Copy up to 8
        printf("DEBUG: session_id && valuestring-exi_doc.V2G_Message.Header.SessionID.bytesLen = %u\n", exi_doc.V2G_Message.Header.SessionID.bytesLen);

    } else {
        exi_doc.V2G_Message.Header.SessionID.bytesLen = iso2_sessionIDType_BYTES_SIZE;
        memset(exi_doc.V2G_Message.Header.SessionID.bytes, 0, iso2_sessionIDType_BYTES_SIZE);
        printf("DEBUG: esle - exi_doc.V2G_Message.Header.SessionID.bytesLen = %u\n", exi_doc.V2G_Message.Header.SessionID.bytesLen);
    }

    // Get Id from JSON
    printf("DEBUG: Getting Id from JSON\n");
    fflush(stdout);
    cJSON* id = cJSON_GetObjectItem(root, "Id");
    if (id && id->valuestring) {
        size_t len = strlen(id->valuestring);
        exi_doc.V2G_Message.Body.CertificateInstallationReq.Id.charactersLen = (uint16_t)len;
        memcpy(exi_doc.V2G_Message.Body.CertificateInstallationReq.Id.characters, id->valuestring, len);
    }

    // Get OEMProvisioningCert from JSON
    printf("DEBUG: Getting OEMProvisioningCert from JSON\n");
    fflush(stdout);
    cJSON* oem_cert = cJSON_GetObjectItem(root, "OEMProvisioningCert");
    if (oem_cert && oem_cert->valuestring) {
        uint8_t* binary_cert;
        size_t cert_len;
        if (base64_to_binary(oem_cert->valuestring, &binary_cert, &cert_len) == 0) {
            exi_doc.V2G_Message.Body.CertificateInstallationReq.OEMProvisioningCert.bytesLen = (uint16_t)cert_len;
            memcpy(exi_doc.V2G_Message.Body.CertificateInstallationReq.OEMProvisioningCert.bytes, binary_cert, cert_len);
            free(binary_cert);
        }
    }

    // Get ListOfRootCertificateIDs from JSON
    printf("DEBUG: Getting ListOfRootCertificateIDs from JSON\n");
    fflush(stdout);
    cJSON* root_certs = cJSON_GetObjectItem(root, "ListOfRootCertificateIDs");
    if (root_certs && cJSON_IsArray(root_certs)) {
        int array_size = cJSON_GetArraySize(root_certs);
        exi_doc.V2G_Message.Body.CertificateInstallationReq.ListOfRootCertificateIDs.RootCertificateID.arrayLen = array_size;
        for (int i = 0; i < array_size; i++) {
            cJSON* cert = cJSON_GetArrayItem(root_certs, i);
            if (cert) {
                cJSON* issuer = cJSON_GetObjectItem(cert, "X509IssuerName");
                cJSON* serial = cJSON_GetObjectItem(cert, "X509SerialNumber");
                if (issuer && issuer->valuestring) {
                    size_t len = strlen(issuer->valuestring);
                    exi_doc.V2G_Message.Body.CertificateInstallationReq.ListOfRootCertificateIDs.RootCertificateID.array[i].X509IssuerName.charactersLen = (uint16_t)len;
                    memcpy(exi_doc.V2G_Message.Body.CertificateInstallationReq.ListOfRootCertificateIDs.RootCertificateID.array[i].X509IssuerName.characters, issuer->valuestring, len);
                }
                if (serial && serial->valuedouble) {
                    double_to_exi_signed(serial->valuedouble, &exi_doc.V2G_Message.Body.CertificateInstallationReq.ListOfRootCertificateIDs.RootCertificateID.array[i].X509SerialNumber);
                }
            }
        }
    }

    // Print exi_doc contents before encoding
    printf("DEBUG: exi_doc.V2G_Message.Header.SessionID.bytesLen = %u\n", exi_doc.V2G_Message.Header.SessionID.bytesLen);
    printf("DEBUG: exi_doc.V2G_Message.Header.SessionID.bytes = ");
    for (int i = 0; i < exi_doc.V2G_Message.Header.SessionID.bytesLen; ++i) {
        printf("%02X ", (unsigned char)exi_doc.V2G_Message.Header.SessionID.bytes[i]);
    }
    printf("\n");
    printf("DEBUG: exi_doc.V2G_Message.Body.CertificateInstallationReq_isUsed = %d\n", exi_doc.V2G_Message.Body.CertificateInstallationReq_isUsed);
    printf("DEBUG: exi_doc.V2G_Message.Body.CertificateInstallationReq.Id.charactersLen = %u\n", exi_doc.V2G_Message.Body.CertificateInstallationReq.Id.charactersLen);
    printf("DEBUG: exi_doc.V2G_Message.Body.CertificateInstallationReq.Id.characters = ");
    for (int i = 0; i < exi_doc.V2G_Message.Body.CertificateInstallationReq.Id.charactersLen; ++i) {
        printf("%c", exi_doc.V2G_Message.Body.CertificateInstallationReq.Id.characters[i]);
    }
    printf("\n");
    printf("DEBUG: exi_doc.V2G_Message.Body.CertificateInstallationReq.OEMProvisioningCert.bytesLen = %u\n", exi_doc.V2G_Message.Body.CertificateInstallationReq.OEMProvisioningCert.bytesLen);
    printf("DEBUG: exi_doc.V2G_Message.Body.CertificateInstallationReq.ListOfRootCertificateIDs.RootCertificateID.arrayLen = %u\n", exi_doc.V2G_Message.Body.CertificateInstallationReq.ListOfRootCertificateIDs.RootCertificateID.arrayLen);
    fflush(stdout);

    // Calculate required buffer size
    size_t required_size = 0;
    // Add size for header
    required_size += 1; // EXI header
    // Add size for session ID
    required_size += 8; // SessionID is 8 bytes
    // Add size for certificate installation request
    required_size += 26; // Id length
    required_size += 708; // OEMProvisioningCert length
    required_size += 2; // ListOfRootCertificateIDs array length
    // Add some padding for safety
    required_size += 100;

    printf("DEBUG: Required buffer size: %zu\n", required_size);

    // Allocate buffer if needed
    if (*exi_size == 0 || *exi_buffer == NULL) {
        printf("DEBUG: Allocating new buffer of size %zu\n", required_size);
        *exi_buffer = (uint8_t*)malloc(required_size);
        if (*exi_buffer == NULL) {
            printf("DEBUG: Failed to allocate buffer\n");
            return -1;
        }
        *exi_size = required_size;
    } else if (*exi_size < required_size) {
        printf("DEBUG: Reallocating buffer from %zu to %zu\n", *exi_size, required_size);
        uint8_t* new_buffer = (uint8_t*)realloc(*exi_buffer, required_size);
        if (new_buffer == NULL) {
            printf("DEBUG: Failed to reallocate buffer\n");
            return -1;
        }
        *exi_buffer = new_buffer;
        *exi_size = required_size;
    }

    // Initialize bitstream
    printf("DEBUG: About to initialize bitstream\n");
    printf("DEBUG: exi_buffer size: %zu\n", *exi_size);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, *exi_buffer, *exi_size, 0, NULL);
    printf("DEBUG: Bitstream initialized successfully\n");
    printf("DEBUG: stream.data_size: %zu\n", stream.data_size);
    printf("DEBUG: stream.byte_pos: %zu\n", stream.byte_pos);

    // Encode to EXI
    printf("DEBUG: About to encode to EXI\n");
    int err = encode_iso2_exiDocument(&stream, &exi_doc);
    if (err != 0) {
        printf("DEBUG: Failed to encode to EXI with error code: %d\n", err);
        printf("DEBUG: Final stream.byte_pos: %zu\n", stream.byte_pos);
        printf("DEBUG: Final stream.bit_count: %u\n", stream.bit_count);
        return err;
    }
    printf("DEBUG: EXI encoding completed successfully\n");

    // Get the actual size of the encoded data
    printf("DEBUG: About to get encoded size\n");
    *exi_size = exi_bitstream_get_length(&stream);
    printf("DEBUG: Final encoded size: %zu\n", *exi_size);

    // Cleanup
    cJSON_Delete(root);
    printf("DEBUG: iso2_certificate_installation_req_encode_json_to_exi finished successfully\n");
    fflush(stdout);
    return 0;
}

int iso2_certificate_installation_req_decode_exi_to_json(const uint8_t* exi_buffer, size_t exi_size, char** json_str) {
    if (!exi_buffer || !json_str) {
        return -1;
    }

    // Initialize bitstream
    exi_bitstream_t stream;
    stream.data = (uint8_t*)exi_buffer;
    stream.data_size = exi_size;
    stream.byte_pos = 0;
    stream.bit_count = 0;
    stream._init_called = 0;
    stream._flag_byte_pos = 0;
    stream.status_callback = NULL;

    // Decode EXI
    struct iso2_exiDocument exi_doc;
    memset(&exi_doc, 0, sizeof(exi_doc));
    
    int errn = decode_iso2_exiDocument(&stream, &exi_doc);
    if (errn != 0) {
        return -2;
    }

    // Create JSON
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return -3;
    }

    // Add CertificateInstallationReq fields
    if (exi_doc.V2G_Message.Body.CertificateInstallationReq_isUsed) {
        struct iso2_CertificateInstallationReqType* cert_req = &exi_doc.V2G_Message.Body.CertificateInstallationReq;

        // Add SessionID
        if (exi_doc.V2G_Message.Header.SessionID.bytesLen > 0) {
            char session_id[iso2_sessionIDType_BYTES_SIZE + 1];
            memcpy(session_id, exi_doc.V2G_Message.Header.SessionID.bytes, 
                   exi_doc.V2G_Message.Header.SessionID.bytesLen);
            session_id[exi_doc.V2G_Message.Header.SessionID.bytesLen] = '\0';
            cJSON_AddStringToObject(root, "SessionID", session_id);
        }

        // Add Id
        if (cert_req->Id.charactersLen > 0) {
            char id[iso2_Id_CHARACTER_SIZE + 1];
            memcpy(id, cert_req->Id.characters, cert_req->Id.charactersLen);
            id[cert_req->Id.charactersLen] = '\0';
            cJSON_AddStringToObject(root, "Id", id);
        }

        // Add OEMProvisioningCert
        if (cert_req->OEMProvisioningCert.bytesLen > 0) {
            char* base64_cert = binary_to_base64(cert_req->OEMProvisioningCert.bytes, 
                                               cert_req->OEMProvisioningCert.bytesLen);
            if (base64_cert) {
                cJSON_AddStringToObject(root, "OEMProvisioningCert", base64_cert);
                free(base64_cert);
            }
        }

        // Add ListOfRootCertificateIDs
        if (cert_req->ListOfRootCertificateIDs.RootCertificateID.arrayLen > 0) {
            cJSON* root_certs = cJSON_CreateArray();
            if (root_certs) {
                cJSON_AddItemToObject(root, "ListOfRootCertificateIDs", root_certs);

                for (int i = 0; i < cert_req->ListOfRootCertificateIDs.RootCertificateID.arrayLen; i++) {
                    cJSON* cert = cJSON_CreateObject();
                    if (cert) {
                        cJSON_AddItemToArray(root_certs, cert);

                        if (cert_req->ListOfRootCertificateIDs.RootCertificateID.array[i].X509IssuerName.charactersLen > 0) {
                            char issuer[iso2_X509IssuerName_CHARACTER_SIZE + 1];
                            memcpy(issuer, 
                                   cert_req->ListOfRootCertificateIDs.RootCertificateID.array[i].X509IssuerName.characters,
                                   cert_req->ListOfRootCertificateIDs.RootCertificateID.array[i].X509IssuerName.charactersLen);
                            issuer[cert_req->ListOfRootCertificateIDs.RootCertificateID.array[i].X509IssuerName.charactersLen] = '\0';
                            cJSON_AddStringToObject(cert, "X509IssuerName", issuer);
                        }

                        double serial_value = exi_signed_to_double(&cert_req->ListOfRootCertificateIDs.RootCertificateID.array[i].X509SerialNumber);
                        cJSON_AddNumberToObject(cert, "X509SerialNumber", serial_value);
                    }
                }
            }
        }
    }

    // Convert to string
    *json_str = cJSON_Print(root);
    if (!*json_str) {
        cJSON_Delete(root);
        return -4;
    }

    // Cleanup
    cJSON_Delete(root);
    return 0;
}

void iso2_certificate_installation_req_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// ISO-2 Certificate Installation Response stubs
int iso2_certificate_installation_res_encode_json_to_exi(const char* json_str, uint8_t** exi_buffer, size_t* exi_size) {
    printf("DEBUG: iso2_certificate_installation_res_encode_json_to_exi called with json_str=%p, exi_buffer=%p, exi_size=%p\n", (void*)json_str, (void*)exi_buffer, (void*)exi_size);
    fflush(stdout);
    if (!json_str || !exi_buffer || !exi_size) {
        printf("DEBUG: Error: NULL pointer passed\n");
        fflush(stdout);
        return -1;
    }

    // Parse JSON
    printf("DEBUG: Parsing JSON\n");
    fflush(stdout);
    cJSON* root = cJSON_Parse(json_str);
    if (!root) {
        printf("DEBUG: Error: Failed to parse JSON\n");
        fflush(stdout);
        return -2;
    }

    // Create EXI document
    printf("DEBUG: Creating EXI document\n");
    fflush(stdout);
    struct iso2_exiDocument exi_doc;
    memset(&exi_doc, 0, sizeof(exi_doc));

    // Initialize the V2G message and Body and CertificateInstallationRes
    init_iso2_V2G_Message(&exi_doc.V2G_Message);
    init_iso2_BodyType(&exi_doc.V2G_Message.Body);
    init_iso2_CertificateInstallationResType(&exi_doc.V2G_Message.Body.CertificateInstallationRes);
    exi_doc.V2G_Message.Body.CertificateInstallationRes_isUsed = 1;

    struct iso2_CertificateInstallationResType* res = &exi_doc.V2G_Message.Body.CertificateInstallationRes;

    // Get ResponseCode from JSON
    printf("DEBUG: Getting ResponseCode from JSON\n");
    fflush(stdout);
    cJSON* response_code = cJSON_GetObjectItem(root, "ResponseCode");
    if (response_code && response_code->valuestring) {
        // Map string to enum
        if (strcmp(response_code->valuestring, "OK") == 0) {
            res->ResponseCode = iso2_responseCodeType_OK;
        } else if (strcmp(response_code->valuestring, "FAILED") == 0) {
            res->ResponseCode = iso2_responseCodeType_FAILED;
        } else if (strcmp(response_code->valuestring, "FAILED_SequenceError") == 0) {
            res->ResponseCode = iso2_responseCodeType_FAILED_SequenceError;
        } else if (strcmp(response_code->valuestring, "FAILED_ServiceIDInvalid") == 0) {
            res->ResponseCode = iso2_responseCodeType_FAILED_ServiceIDInvalid;
        } else if (strcmp(response_code->valuestring, "FAILED_UnknownSession") == 0) {
            res->ResponseCode = iso2_responseCodeType_FAILED_UnknownSession;
        } else {
            // Default to FAILED if unknown response code
            res->ResponseCode = iso2_responseCodeType_FAILED;
        }
    }

    // Get SAProvisioningCertificateChain from JSON
    printf("DEBUG: Getting SAProvisioningCertificateChain from JSON\n");
    fflush(stdout);
    cJSON* sa_chain = cJSON_GetObjectItem(root, "SAProvisioningCertificateChain");
    if (sa_chain) {
        // Get Id
        cJSON* id = cJSON_GetObjectItem(sa_chain, "Id");
        if (id && id->valuestring) {
            size_t len = strlen(id->valuestring);
            if (len < iso2_Id_CHARACTER_SIZE && len <= UINT16_MAX) {
                memcpy(res->SAProvisioningCertificateChain.Id.characters, id->valuestring, len);
                res->SAProvisioningCertificateChain.Id.charactersLen = (uint16_t)len;
                res->SAProvisioningCertificateChain.Id_isUsed = 1;
            }
        }

        // Get Certificate
        cJSON* cert = cJSON_GetObjectItem(sa_chain, "Certificate");
        if (cert && cert->valuestring) {
            size_t len = strlen(cert->valuestring);
            if (len < iso2_certificateType_BYTES_SIZE && len <= UINT16_MAX) {
                memcpy(res->SAProvisioningCertificateChain.Certificate.bytes, cert->valuestring, len);
                res->SAProvisioningCertificateChain.Certificate.bytesLen = (uint16_t)len;
            }
        }

        // Get SubCertificates
        cJSON* sub_certs = cJSON_GetObjectItem(sa_chain, "SubCertificates");
        if (sub_certs && cJSON_IsArray(sub_certs)) {
            int num_sub_certs = cJSON_GetArraySize(sub_certs);
            if (num_sub_certs > 0 && num_sub_certs <= iso2_certificateType_4_ARRAY_SIZE) {
                res->SAProvisioningCertificateChain.SubCertificates.Certificate.arrayLen = (uint16_t)num_sub_certs;
                res->SAProvisioningCertificateChain.SubCertificates_isUsed = 1;
                
                for (int i = 0; i < num_sub_certs; i++) {
                    cJSON* sub_cert = cJSON_GetArrayItem(sub_certs, i);
                    if (sub_cert && sub_cert->valuestring) {
                        size_t len = strlen(sub_cert->valuestring);
                        if (len < iso2_certificateType_BYTES_SIZE && len <= UINT16_MAX) {
                            memcpy(res->SAProvisioningCertificateChain.SubCertificates.Certificate.array[i].bytes, 
                                   sub_cert->valuestring, len);
                            res->SAProvisioningCertificateChain.SubCertificates.Certificate.array[i].bytesLen = (uint16_t)len;
                        }
                    }
                }
            }
        }
    }

    // Get ContractSignatureCertChain from JSON
    printf("DEBUG: Getting ContractSignatureCertChain from JSON\n");
    fflush(stdout);
    cJSON* contract_chain = cJSON_GetObjectItem(root, "ContractSignatureCertChain");
    if (contract_chain) {
        // Get Id
        cJSON* id = cJSON_GetObjectItem(contract_chain, "Id");
        if (id && id->valuestring) {
            size_t len = strlen(id->valuestring);
            if (len < iso2_Id_CHARACTER_SIZE && len <= UINT16_MAX) {
                memcpy(res->ContractSignatureCertChain.Id.characters, id->valuestring, len);
                res->ContractSignatureCertChain.Id.charactersLen = (uint16_t)len;
                res->ContractSignatureCertChain.Id_isUsed = 1;
            }
        }

        // Get Certificate
        cJSON* cert = cJSON_GetObjectItem(contract_chain, "Certificate");
        if (cert && cert->valuestring) {
            size_t len = strlen(cert->valuestring);
            if (len < iso2_certificateType_BYTES_SIZE && len <= UINT16_MAX) {
                memcpy(res->ContractSignatureCertChain.Certificate.bytes, cert->valuestring, len);
                res->ContractSignatureCertChain.Certificate.bytesLen = (uint16_t)len;
            }
        }

        // Get SubCertificates
        cJSON* sub_certs = cJSON_GetObjectItem(contract_chain, "SubCertificates");
        if (sub_certs && cJSON_IsArray(sub_certs)) {
            int num_sub_certs = cJSON_GetArraySize(sub_certs);
            if (num_sub_certs > 0 && num_sub_certs <= iso2_certificateType_4_ARRAY_SIZE) {
                res->ContractSignatureCertChain.SubCertificates.Certificate.arrayLen = (uint16_t)num_sub_certs;
                res->ContractSignatureCertChain.SubCertificates_isUsed = 1;
                
                for (int i = 0; i < num_sub_certs; i++) {
                    cJSON* sub_cert = cJSON_GetArrayItem(sub_certs, i);
                    if (sub_cert && sub_cert->valuestring) {
                        size_t len = strlen(sub_cert->valuestring);
                        if (len < iso2_certificateType_BYTES_SIZE && len <= UINT16_MAX) {
                            memcpy(res->ContractSignatureCertChain.SubCertificates.Certificate.array[i].bytes, 
                                   sub_cert->valuestring, len);
                            res->ContractSignatureCertChain.SubCertificates.Certificate.array[i].bytesLen = (uint16_t)len;
                        }
                    }
                }
            }
        }
    }

    // Get ContractSignatureEncryptedPrivateKey from JSON
    printf("DEBUG: Getting ContractSignatureEncryptedPrivateKey from JSON\n");
    fflush(stdout);
    cJSON* encrypted_key = cJSON_GetObjectItem(root, "ContractSignatureEncryptedPrivateKey");
    if (encrypted_key) {
        // Get Id
        cJSON* id = cJSON_GetObjectItem(encrypted_key, "Id");
        if (id && id->valuestring) {
            size_t len = strlen(id->valuestring);
            if (len < iso2_Id_CHARACTER_SIZE && len <= UINT16_MAX) {
                memcpy(res->ContractSignatureEncryptedPrivateKey.Id.characters, id->valuestring, len);
                res->ContractSignatureEncryptedPrivateKey.Id.charactersLen = (uint16_t)len;
            }
        }

        // Get CONTENT
        cJSON* content = cJSON_GetObjectItem(encrypted_key, "CONTENT");
        if (content && content->valuestring) {
            size_t len = strlen(content->valuestring);
            if (len < iso2_ContractSignatureEncryptedPrivateKeyType_BYTES_SIZE && len <= UINT16_MAX) {
                memcpy(res->ContractSignatureEncryptedPrivateKey.CONTENT.bytes, content->valuestring, len);
                res->ContractSignatureEncryptedPrivateKey.CONTENT.bytesLen = (uint16_t)len;
            }
        }
    }

    // Get DHpublickey from JSON
    printf("DEBUG: Getting DHpublickey from JSON\n");
    fflush(stdout);
    cJSON* dh_pubkey = cJSON_GetObjectItem(root, "DHpublickey");
    if (dh_pubkey) {
        // Get Id
        cJSON* id = cJSON_GetObjectItem(dh_pubkey, "Id");
        if (id && id->valuestring) {
            size_t len = strlen(id->valuestring);
            if (len < iso2_Id_CHARACTER_SIZE && len <= UINT16_MAX) {
                memcpy(res->DHpublickey.Id.characters, id->valuestring, len);
                res->DHpublickey.Id.charactersLen = (uint16_t)len;
            }
        }

        // Get CONTENT
        cJSON* content = cJSON_GetObjectItem(dh_pubkey, "CONTENT");
        if (content && content->valuestring) {
            size_t len = strlen(content->valuestring);
            if (len < iso2_DiffieHellmanPublickeyType_BYTES_SIZE && len <= UINT16_MAX) {
                memcpy(res->DHpublickey.CONTENT.bytes, content->valuestring, len);
                res->DHpublickey.CONTENT.bytesLen = (uint16_t)len;
            }
        }
    }

    // Get eMAID from JSON
    printf("DEBUG: Getting eMAID from JSON\n");
    fflush(stdout);
    cJSON* emaid = cJSON_GetObjectItem(root, "eMAID");
    if (emaid && emaid->valuestring) {
        size_t len = strlen(emaid->valuestring);
        res->eMAID.CONTENT.charactersLen = (uint16_t)len;
        memcpy(res->eMAID.CONTENT.characters, emaid->valuestring, len);
    }

    // Estimate required buffer size based on the response structure
    size_t required_size = 0;
    
    // Base overhead for EXI encoding
    required_size += 100;  // EXI header and basic structure overhead
    
    // Add size for each certificate chain (Id + Certificate + SubCertificates)
    required_size += res->SAProvisioningCertificateChain.Id.charactersLen;
    required_size += res->SAProvisioningCertificateChain.Certificate.bytesLen;
    if (res->SAProvisioningCertificateChain.SubCertificates_isUsed) {
        for (int i = 0; i < res->SAProvisioningCertificateChain.SubCertificates.Certificate.arrayLen; i++) {
            required_size += res->SAProvisioningCertificateChain.SubCertificates.Certificate.array[i].bytesLen;
        }
    }
    
    required_size += res->ContractSignatureCertChain.Id.charactersLen;
    required_size += res->ContractSignatureCertChain.Certificate.bytesLen;
    if (res->ContractSignatureCertChain.SubCertificates_isUsed) {
        for (int i = 0; i < res->ContractSignatureCertChain.SubCertificates.Certificate.arrayLen; i++) {
            required_size += res->ContractSignatureCertChain.SubCertificates.Certificate.array[i].bytesLen;
        }
    }
    
    // Add size for encrypted private key
    required_size += res->ContractSignatureEncryptedPrivateKey.Id.charactersLen;
    required_size += res->ContractSignatureEncryptedPrivateKey.CONTENT.bytesLen;
    
    // Add size for DH public key
    required_size += res->DHpublickey.Id.charactersLen;
    required_size += res->DHpublickey.CONTENT.bytesLen;
    
    // Add padding for safety
    required_size += 100;

    printf("DEBUG: Required buffer size: %zu\n", required_size);

    // Allocate buffer if needed
    if (*exi_size == 0 || *exi_buffer == NULL) {
        printf("DEBUG: Allocating new buffer of size %zu\n", required_size);
        *exi_buffer = (uint8_t*)malloc(required_size);
        if (*exi_buffer == NULL) {
            printf("DEBUG: Failed to allocate buffer\n");
            cJSON_Delete(root);
            return -1;
        }
        *exi_size = required_size;
    } else if (*exi_size < required_size) {
        printf("DEBUG: Reallocating buffer from %zu to %zu\n", *exi_size, required_size);
        uint8_t* new_buffer = (uint8_t*)realloc(*exi_buffer, required_size);
        if (new_buffer == NULL) {
            printf("DEBUG: Failed to reallocate buffer\n");
            cJSON_Delete(root);
            return -1;
        }
        *exi_buffer = new_buffer;
        *exi_size = required_size;
    }

    // Initialize bitstream
    printf("DEBUG: About to initialize bitstream\n");
    printf("DEBUG: exi_buffer size: %zu\n", *exi_size);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, *exi_buffer, *exi_size, 0, NULL);
    printf("DEBUG: Bitstream initialized successfully\n");
    printf("DEBUG: stream.data_size: %zu\n", stream.data_size);
    printf("DEBUG: stream.byte_pos: %zu\n", stream.byte_pos);

    // Encode to EXI
    printf("DEBUG: About to encode to EXI\n");
    int err = encode_iso2_exiDocument(&stream, &exi_doc);
    if (err != 0) {
        printf("DEBUG: Failed to encode to EXI with error code: %d\n", err);
        printf("DEBUG: Final stream.byte_pos: %zu\n", stream.byte_pos);
        printf("DEBUG: Final stream.bit_count: %u\n", stream.bit_count);
        cJSON_Delete(root);
        return err;
    }
    printf("DEBUG: EXI encoding completed successfully\n");

    // Get the actual size of the encoded data
    printf("DEBUG: About to get encoded size\n");
    *exi_size = exi_bitstream_get_length(&stream);
    printf("DEBUG: Final encoded size: %zu\n", *exi_size);

    // Cleanup
    cJSON_Delete(root);
    printf("DEBUG: iso2_certificate_installation_res_encode_json_to_exi finished successfully\n");
    fflush(stdout);
    return 0;
}

int iso2_certificate_installation_res_decode_exi_to_json(const uint8_t* exi_buffer, size_t exi_size, char** json_str) {
    // TODO: Implement ISO-2 Certificate Installation Response decoding
    return -1;
}

// ISO-20 Certificate Installation Request stubs
int iso20_certificate_installation_req_encode_json_to_exi(const char* json_str, uint8_t** exi_buffer, size_t* exi_size) {
    // TODO: Implement ISO-20 Certificate Installation Request encoding
    return -1;
}

int iso20_certificate_installation_req_decode_exi_to_json(const uint8_t* exi_buffer, size_t exi_size, char** json_str) {
    // TODO: Implement ISO-20 Certificate Installation Request decoding
    return -1;
}

// ISO-20 Certificate Installation Response stubs
int iso20_certificate_installation_res_encode_json_to_exi(const char* json_str, uint8_t** exi_buffer, size_t* exi_size) {
    // TODO: Implement ISO-20 Certificate Installation Response encoding
    return -1;
}

int iso20_certificate_installation_res_decode_exi_to_json(const uint8_t* exi_buffer, size_t exi_size, char** json_str) {
    // TODO: Implement ISO-20 Certificate Installation Response decoding
    return -1;
} 