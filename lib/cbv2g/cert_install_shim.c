#include "cbv2g/cert_install_shim.h"
#include "cbv2g/iso_2/iso2_msgDefDatatypes.h"
#include "cbv2g/iso_2/iso2_msgDefEncoder.h"
#include "cbv2g/iso_2/iso2_msgDefDecoder.h"
#include "cbv2g/iso_20/iso20_CommonMessages_Datatypes.h"
#include "cbv2g/iso_20/iso20_CommonMessages_Encoder.h"
#include "cbv2g/iso_20/iso20_CommonMessages_Decoder.h"
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

// Helper function to convert binary to hex string
static char* binary_to_hex(const uint8_t* binary, size_t binary_len) {
    char* hex = (char*)malloc(binary_len * 2 + 1);
    if (!hex) return NULL;
    
    for (size_t i = 0; i < binary_len; i++) {
        #ifdef _WIN32
        sprintf_s(hex + (i * 2), 3, "%02X", binary[i]);
        #else
        snprintf(hex + (i * 2), 3, "%02X", binary[i]);
        #endif
    }
    hex[binary_len * 2] = '\0';
    return hex;
}

// Helper function to convert hex string to binary
static int hex_to_binary(const char* hex, uint8_t** binary, size_t* binary_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    
    *binary_len = hex_len / 2;
    *binary = (uint8_t*)malloc(*binary_len);
    if (!*binary) return -1;
    
    for (size_t i = 0; i < *binary_len; i++) {
        char hex_byte[3] = {hex[i*2], hex[i*2+1], '\0'};
        char* endptr;
        (*binary)[i] = (uint8_t)strtol(hex_byte, &endptr, 16);
        if (*endptr != '\0') {
            free(*binary);
            *binary = NULL;
            return -1;
        }
    }
    return 0;
}

int iso2_certificate_installation_req_encode_json_to_exi(const char* json_str, uint8_t** exi_buffer, size_t* exi_size) {
    ////printf("DEBUG: iso2_certificate_installation_req_encode_json_to_exi called with json_str=%p, exi_buffer=%p, exi_size=%p\n", (void*)json_str, (void*)exi_buffer, (void*)exi_size);
    ////fflush(stdout);
    if (!json_str || !exi_buffer || !exi_size) {
        ////printf("DEBUG: Error: NULL pointer passed\n");
        ////fflush(stdout);
        return -1;
    }

    // Parse JSON
    ////printf("DEBUG: Parsing JSON\n");
    //fflush(stdout);
    cJSON* root = cJSON_Parse(json_str);
    if (!root) {
        ////printf("DEBUG: Error: Failed to parse JSON\n");
        ////fflush(stdout);
        return -2;
    }

    // Create EXI document
    ////printf("DEBUG: Creating EXI document\n");
    ////fflush(stdout);
    struct iso2_exiDocument exi_doc;
    memset(&exi_doc, 0, sizeof(exi_doc));

    // Initialize the V2G message and Body and CertificateInstallationReq
    init_iso2_V2G_Message(&exi_doc.V2G_Message);
    init_iso2_BodyType(&exi_doc.V2G_Message.Body);
    init_iso2_CertificateInstallationReqType(&exi_doc.V2G_Message.Body.CertificateInstallationReq);
    exi_doc.V2G_Message.Body.CertificateInstallationReq_isUsed = 1;

    // Get SessionID from JSON
    ////printf("DEBUG: Getting SessionID from JSON\n");
    ////fflush(stdout);
    cJSON* session_id = cJSON_GetObjectItem(root, "SessionID");
    if (session_id && session_id->valuestring) {
        uint8_t* binary_session_id;
        size_t session_id_len;
        if (hex_to_binary(session_id->valuestring, &binary_session_id, &session_id_len) == 0) {
            exi_doc.V2G_Message.Header.SessionID.bytesLen = (uint16_t)session_id_len;
            memcpy(exi_doc.V2G_Message.Header.SessionID.bytes, binary_session_id, session_id_len);
            free(binary_session_id);
        } else {
            // Default to zero session ID if hex conversion fails
            exi_doc.V2G_Message.Header.SessionID.bytesLen = iso2_sessionIDType_BYTES_SIZE;
            memset(exi_doc.V2G_Message.Header.SessionID.bytes, 0, iso2_sessionIDType_BYTES_SIZE);
        }
    } else {
        // Default to zero session ID if not provided
        exi_doc.V2G_Message.Header.SessionID.bytesLen = iso2_sessionIDType_BYTES_SIZE;
        memset(exi_doc.V2G_Message.Header.SessionID.bytes, 0, iso2_sessionIDType_BYTES_SIZE);
    }

    // Get Id from JSON
    ////printf("DEBUG: Getting Id from JSON\n");
    ////fflush(stdout);
    cJSON* id = cJSON_GetObjectItem(root, "Id");
    if (id && id->valuestring) {
        size_t len = strlen(id->valuestring);
        exi_doc.V2G_Message.Body.CertificateInstallationReq.Id.charactersLen = (uint16_t)len;
        memcpy(exi_doc.V2G_Message.Body.CertificateInstallationReq.Id.characters, id->valuestring, len);
    }

    // Get OEMProvisioningCert from JSON
    ////printf("DEBUG: Getting OEMProvisioningCert from JSON\n");
    ////fflush(stdout);
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
    ////printf("DEBUG: Getting ListOfRootCertificateIDs from JSON\n");
    ////fflush(stdout);
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
                    int32_t serial_value = (int32_t)serial->valuedouble;
                    exi_basetypes_convert_to_signed(&exi_doc.V2G_Message.Body.CertificateInstallationReq.ListOfRootCertificateIDs.RootCertificateID.array[i].X509SerialNumber,
                                                  serial_value,
                                                  EXI_BASETYPES_UINT32_MAX_OCTETS);
                }
            }
        }
    }

    // Print exi_doc contents before encoding
    ////printf("DEBUG: exi_doc.V2G_Message.Header.SessionID.bytesLen = %u\n", exi_doc.V2G_Message.Header.SessionID.bytesLen);
    ////printf("DEBUG: exi_doc.V2G_Message.Header.SessionID.bytes = ");
    //for (int i = 0; i < exi_doc.V2G_Message.Header.SessionID.bytesLen; ++i) {
    //    printf("%02X ", (unsigned char)exi_doc.V2G_Message.Header.SessionID.bytes[i]);
    //}
    //printf("\n");
    ////printf("DEBUG: exi_doc.V2G_Message.Body.CertificateInstallationReq_isUsed = %d\n", exi_doc.V2G_Message.Body.CertificateInstallationReq_isUsed);
    ////printf("DEBUG: exi_doc.V2G_Message.Body.CertificateInstallationReq.Id.charactersLen = %u\n", exi_doc.V2G_Message.Body.CertificateInstallationReq.Id.charactersLen);
    ////printf("DEBUG: exi_doc.V2G_Message.Body.CertificateInstallationReq.Id.characters = ");
    //for (int i = 0; i < exi_doc.V2G_Message.Body.CertificateInstallationReq.Id.charactersLen; ++i) {
    //    printf("%c", exi_doc.V2G_Message.Body.CertificateInstallationReq.Id.characters[i]);
    //}
    //printf("\n");
    ////printf("DEBUG: exi_doc.V2G_Message.Body.CertificateInstallationReq.OEMProvisioningCert.bytesLen = %u\n", exi_doc.V2G_Message.Body.CertificateInstallationReq.OEMProvisioningCert.bytesLen);
    ////printf("DEBUG: exi_doc.V2G_Message.Body.CertificateInstallationReq.ListOfRootCertificateIDs.RootCertificateID.arrayLen = %u\n", exi_doc.V2G_Message.Body.CertificateInstallationReq.ListOfRootCertificateIDs.RootCertificateID.arrayLen);
    ////fflush(stdout);

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

    ////printf("DEBUG: Required buffer size: %zu\n", required_size);

    // Allocate buffer if needed
    if (*exi_size == 0 || *exi_buffer == NULL) {
        ////printf("DEBUG: Allocating new buffer of size %zu\n", required_size);
        *exi_buffer = (uint8_t*)malloc(required_size);
        if (*exi_buffer == NULL) {
            //printf("DEBUG: Failed to allocate buffer\n");
            return -1;
        }
        *exi_size = required_size;
    } else if (*exi_size < required_size) {
        ////printf("DEBUG: Reallocating buffer from %zu to %zu\n", *exi_size, required_size);
        uint8_t* new_buffer = (uint8_t*)realloc(*exi_buffer, required_size);
        if (new_buffer == NULL) {
            ////printf("DEBUG: Failed to reallocate buffer\n");
            return -1;
        }
        *exi_buffer = new_buffer;
        *exi_size = required_size;
    }

    // Initialize bitstream
    ////printf("DEBUG: About to initialize bitstream\n");
    ////printf("DEBUG: exi_buffer size: %zu\n", *exi_size);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, *exi_buffer, *exi_size, 0, NULL);
    ////printf("DEBUG: Bitstream initialized successfully\n");
    ////printf("DEBUG: stream.data_size: %zu\n", stream.data_size);
    ////printf("DEBUG: stream.byte_pos: %zu\n", stream.byte_pos);

    // Encode to EXI
    ////printf("DEBUG: About to encode to EXI\n");
    int err = encode_iso2_exiDocument(&stream, &exi_doc);
    if (err != 0) {
        ////printf("DEBUG: Failed to encode to EXI with error code: %d\n", err);
        ////printf("DEBUG: Final stream.byte_pos: %zu\n", stream.byte_pos);
        ////printf("DEBUG: Final stream.bit_count: %u\n", stream.bit_count);
        return err;
    }
    ////printf("DEBUG: EXI encoding completed successfully\n");

    // Get the actual size of the encoded data
    ////printf("DEBUG: About to get encoded size\n");
    *exi_size = exi_bitstream_get_length(&stream);
    //printf("DEBUG: Final encoded size: %zu\n", *exi_size);

    // Cleanup
    cJSON_Delete(root);
    //printf("DEBUG: iso2_certificate_installation_req_encode_json_to_exi finished successfully\n");
    //fflush(stdout);
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
        return errn;
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
            char* hex_session_id = binary_to_hex(exi_doc.V2G_Message.Header.SessionID.bytes,
                                               exi_doc.V2G_Message.Header.SessionID.bytesLen);
            if (hex_session_id) {
                cJSON_AddStringToObject(root, "SessionID", hex_session_id);
                free(hex_session_id);
            }
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
    //printf("DEBUG: iso2_certificate_installation_res_encode_json_to_exi called with json_str=%p, exi_buffer=%p, exi_size=%p\n", (void*)json_str, (void*)exi_buffer, (void*)exi_size);
    //fflush(stdout);
    if (!json_str || !exi_buffer || !exi_size) {
        //printf("DEBUG: Error: NULL pointer passed\n");
        //fflush(stdout);
        return -1;
    }

    // Parse JSON
    //printf("DEBUG: Parsing JSON\n");
    //fflush(stdout);
    cJSON* root = cJSON_Parse(json_str);
    if (!root) {
        //printf("DEBUG: Error: Failed to parse JSON\n");
        //fflush(stdout);
        return -2;
    }

    // Create EXI document
    //printf("DEBUG: Creating EXI document\n");
    //fflush(stdout);
    struct iso2_exiDocument exi_doc;
    memset(&exi_doc, 0, sizeof(exi_doc));

    // Initialize the V2G message and Body and CertificateInstallationRes
    init_iso2_V2G_Message(&exi_doc.V2G_Message);
    init_iso2_BodyType(&exi_doc.V2G_Message.Body);
    init_iso2_CertificateInstallationResType(&exi_doc.V2G_Message.Body.CertificateInstallationRes);
    exi_doc.V2G_Message.Body.CertificateInstallationRes_isUsed = 1;

    // Get SessionID from JSON
    //printf("DEBUG: Getting SessionID from JSON\n");
    //fflush(stdout);
    cJSON* session_id = cJSON_GetObjectItem(root, "SessionID");
    if (session_id && session_id->valuestring) {
        size_t len = strlen(session_id->valuestring);
        exi_doc.V2G_Message.Header.SessionID.bytesLen = iso2_sessionIDType_BYTES_SIZE; // Always 8
        memset(exi_doc.V2G_Message.Header.SessionID.bytes, 0, iso2_sessionIDType_BYTES_SIZE); // Zero out
        memcpy(exi_doc.V2G_Message.Header.SessionID.bytes, session_id->valuestring, len > iso2_sessionIDType_BYTES_SIZE ? iso2_sessionIDType_BYTES_SIZE : len); // Copy up to 8
        //printf("DEBUG: session_id && valuestring-exi_doc.V2G_Message.Header.SessionID.bytesLen = %u\n", exi_doc.V2G_Message.Header.SessionID.bytesLen);

    } else {
        exi_doc.V2G_Message.Header.SessionID.bytesLen = iso2_sessionIDType_BYTES_SIZE;
        memset(exi_doc.V2G_Message.Header.SessionID.bytes, 0, iso2_sessionIDType_BYTES_SIZE);
        //printf("DEBUG: esle - exi_doc.V2G_Message.Header.SessionID.bytesLen = %u\n", exi_doc.V2G_Message.Header.SessionID.bytesLen);
    }

    // Get ResponseCode from JSON
    cJSON* response_code = cJSON_GetObjectItem(root, "ResponseCode");
    if (response_code && response_code->valuestring) {
        if (strcmp(response_code->valuestring, "OK") == 0) {
            exi_doc.V2G_Message.Body.CertificateInstallationRes.ResponseCode = iso2_responseCodeType_OK;
        } else if (strcmp(response_code->valuestring, "FAILED") == 0) {
            exi_doc.V2G_Message.Body.CertificateInstallationRes.ResponseCode = iso2_responseCodeType_FAILED;
        } else if (strcmp(response_code->valuestring, "FAILED_SequenceError") == 0) {
            exi_doc.V2G_Message.Body.CertificateInstallationRes.ResponseCode = iso2_responseCodeType_FAILED_SequenceError;
        } else if (strcmp(response_code->valuestring, "FAILED_ServiceIDInvalid") == 0) {
            exi_doc.V2G_Message.Body.CertificateInstallationRes.ResponseCode = iso2_responseCodeType_FAILED_ServiceIDInvalid;
        } else if (strcmp(response_code->valuestring, "FAILED_UnknownSession") == 0) {
            exi_doc.V2G_Message.Body.CertificateInstallationRes.ResponseCode = iso2_responseCodeType_FAILED_UnknownSession;
        } else {
            // Default to FAILED if unknown response code
            exi_doc.V2G_Message.Body.CertificateInstallationRes.ResponseCode = iso2_responseCodeType_FAILED;
        }
    } else {
        // Default to FAILED if no response code provided
        exi_doc.V2G_Message.Body.CertificateInstallationRes.ResponseCode = iso2_responseCodeType_FAILED;
    }

    // Get SAProvisioningCertificateChain from JSON
    cJSON* sa_chain_json = cJSON_GetObjectItem(root, "SAProvisioningCertificateChain");
    if (sa_chain_json) {
        // Get Certificate
        cJSON* cert = cJSON_GetObjectItem(sa_chain_json, "Certificate");
        if (cert && cert->valuestring) {
            uint8_t* binary_cert;
            size_t cert_len;
            if (base64_to_binary(cert->valuestring, &binary_cert, &cert_len) == 0) {
                exi_doc.V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.Certificate.bytesLen = (uint16_t)cert_len;
                memcpy(exi_doc.V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.Certificate.bytes, 
                       binary_cert, cert_len);
                free(binary_cert);
            }
        }

        // Get SubCertificates
        cJSON* sub_certs = cJSON_GetObjectItem(sa_chain_json, "SubCertificates");
        if (sub_certs && cJSON_IsArray(sub_certs)) {
            int array_size = cJSON_GetArraySize(sub_certs);
            exi_doc.V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.SubCertificates.Certificate.arrayLen = array_size;
            exi_doc.V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.SubCertificates_isUsed = 1;

            for (int i = 0; i < array_size; i++) {
                cJSON* sub_cert = cJSON_GetObjectItem(cJSON_GetArrayItem(sub_certs, i), "Certificate");
                if (sub_cert && sub_cert->valuestring) {
                    uint8_t* binary_subcert;
                    size_t subcert_len;
                    if (base64_to_binary(sub_cert->valuestring, &binary_subcert, &subcert_len) == 0) {
                        exi_doc.V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.SubCertificates.Certificate.array[i].bytesLen = (uint16_t)subcert_len;
                        memcpy(exi_doc.V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.SubCertificates.Certificate.array[i].bytes, 
                               binary_subcert, subcert_len);
                        free(binary_subcert);
                    }
                }
            }
        }
    }

    // Get ContractSignatureCertChain from JSON
    cJSON* contract_chain_json = cJSON_GetObjectItem(root, "ContractSignatureCertChain");
    if (contract_chain_json) {
        // Get Certificate
        cJSON* cert = cJSON_GetObjectItem(contract_chain_json, "Certificate");
        if (cert && cert->valuestring) {
            uint8_t* binary_cert;
            size_t cert_len;
            if (base64_to_binary(cert->valuestring, &binary_cert, &cert_len) == 0) {
                exi_doc.V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.Certificate.bytesLen = (uint16_t)cert_len;
                memcpy(exi_doc.V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.Certificate.bytes, 
                       binary_cert, cert_len);
                free(binary_cert);
            }
        }

        // Get SubCertificates
        cJSON* sub_certs = cJSON_GetObjectItem(contract_chain_json, "SubCertificates");
        if (sub_certs && cJSON_IsArray(sub_certs)) {
            int array_size = cJSON_GetArraySize(sub_certs);
            exi_doc.V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.SubCertificates.Certificate.arrayLen = array_size;
            exi_doc.V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.SubCertificates_isUsed = 1;

            for (int i = 0; i < array_size; i++) {
                cJSON* sub_cert = cJSON_GetObjectItem(cJSON_GetArrayItem(sub_certs, i), "Certificate");
                if (sub_cert && sub_cert->valuestring) {
                    uint8_t* binary_subcert;
                    size_t subcert_len;
                    if (base64_to_binary(sub_cert->valuestring, &binary_subcert, &subcert_len) == 0) {
                        exi_doc.V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.SubCertificates.Certificate.array[i].bytesLen = (uint16_t)subcert_len;
                        memcpy(exi_doc.V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.SubCertificates.Certificate.array[i].bytes, 
                               binary_subcert, subcert_len);
                        free(binary_subcert);
                    }
                }
            }
        }
    }

    // Get ContractSignatureEncryptedPrivateKey from JSON
    cJSON* privkey_json = cJSON_GetObjectItem(root, "ContractSignatureEncryptedPrivateKey");
    if (privkey_json) {
        // Get Id
        cJSON* id = cJSON_GetObjectItem(privkey_json, "Id");
        if (id && id->valuestring) {
            size_t len = strlen(id->valuestring);
            exi_doc.V2G_Message.Body.CertificateInstallationRes.ContractSignatureEncryptedPrivateKey.Id.charactersLen = (uint16_t)len;
            memcpy(exi_doc.V2G_Message.Body.CertificateInstallationRes.ContractSignatureEncryptedPrivateKey.Id.characters, 
                   id->valuestring, len);
        }

        // Get Value
        cJSON* value = cJSON_GetObjectItem(privkey_json, "Value");
        if (value && value->valuestring) {
            uint8_t* binary_value;
            size_t value_len;
            if (base64_to_binary(value->valuestring, &binary_value, &value_len) == 0) {
                exi_doc.V2G_Message.Body.CertificateInstallationRes.ContractSignatureEncryptedPrivateKey.CONTENT.bytesLen = (uint16_t)value_len;
                memcpy(exi_doc.V2G_Message.Body.CertificateInstallationRes.ContractSignatureEncryptedPrivateKey.CONTENT.bytes, 
                       binary_value, value_len);
                free(binary_value);
            }
        }
    }

    // Get DHpublickey from JSON
    cJSON* dhkey_json = cJSON_GetObjectItem(root, "DHpublickey");
    if (dhkey_json) {
        // Get Id
        cJSON* id = cJSON_GetObjectItem(dhkey_json, "Id");
        if (id && id->valuestring) {
            size_t len = strlen(id->valuestring);
            exi_doc.V2G_Message.Body.CertificateInstallationRes.DHpublickey.Id.charactersLen = (uint16_t)len;
            memcpy(exi_doc.V2G_Message.Body.CertificateInstallationRes.DHpublickey.Id.characters, 
                   id->valuestring, len);
        }

        // Get Value
        cJSON* value = cJSON_GetObjectItem(dhkey_json, "Value");
        if (value && value->valuestring) {
            uint8_t* binary_value;
            size_t value_len;
            if (base64_to_binary(value->valuestring, &binary_value, &value_len) == 0) {
                exi_doc.V2G_Message.Body.CertificateInstallationRes.DHpublickey.CONTENT.bytesLen = (uint16_t)value_len;
                memcpy(exi_doc.V2G_Message.Body.CertificateInstallationRes.DHpublickey.CONTENT.bytes, 
                       binary_value, value_len);
                free(binary_value);
            }
        }
    }

    // Get eMAID from JSON
    cJSON* emaid_json = cJSON_GetObjectItem(root, "eMAID");
    if (emaid_json) {
        // Get Id
        cJSON* id = cJSON_GetObjectItem(emaid_json, "Id");
        if (id && id->valuestring) {
            size_t len = strlen(id->valuestring);
            exi_doc.V2G_Message.Body.CertificateInstallationRes.eMAID.Id.charactersLen = (uint16_t)len;
            memcpy(exi_doc.V2G_Message.Body.CertificateInstallationRes.eMAID.Id.characters, 
                   id->valuestring, len);
        }

        // Get Value
        cJSON* value = cJSON_GetObjectItem(emaid_json, "Value");
        if (value && value->valuestring) {
            size_t len = strlen(value->valuestring);
            exi_doc.V2G_Message.Body.CertificateInstallationRes.eMAID.CONTENT.charactersLen = (uint16_t)len;
            memcpy(exi_doc.V2G_Message.Body.CertificateInstallationRes.eMAID.CONTENT.characters, 
                   value->valuestring, len);
        }
    }

    // Print exi_doc contents before encoding
    //printf("DEBUG: exi_doc.V2G_Message.Header.SessionID.bytesLen = %u\n", exi_doc.V2G_Message.Header.SessionID.bytesLen);
    //printf("DEBUG: exi_doc.V2G_Message.Header.SessionID.bytes = ");
    for (int i = 0; i < exi_doc.V2G_Message.Header.SessionID.bytesLen; ++i) {
        printf("%02X ", (unsigned char)exi_doc.V2G_Message.Header.SessionID.bytes[i]);
    }
    printf("\n");

    // Calculate required buffer size
    size_t required_size = 0;
    // Add size for header
    required_size += 1; // EXI header
    // Add size for session ID
    required_size += 8; // SessionID is 8 bytes
    // Add size for certificate installation response
    required_size += 1; // ResponseCode (enum value)
    
    // Add size for SAProvisioningCertificateChain
    required_size += sizeof(struct iso2_CertificateChainType);
    
    // Add size for ContractSignatureCertChain
    required_size += sizeof(struct iso2_CertificateChainType);
    
    // Add size for ContractSignatureEncryptedPrivateKey
    required_size += sizeof(struct iso2_ContractSignatureEncryptedPrivateKeyType);
    
    // Add size for DHpublickey
    required_size += sizeof(struct iso2_DiffieHellmanPublickeyType);
    
    // Add size for eMAID
    required_size += sizeof(struct iso2_EMAIDType);
    
    // Add some padding for safety
    required_size += 100;

    //printf("DEBUG: Required buffer size: %zu\n", required_size);

    // Allocate buffer if needed
    if (*exi_size == 0 || *exi_buffer == NULL) {
        //printf("DEBUG: Allocating new buffer of size %zu\n", required_size);
        *exi_buffer = (uint8_t*)malloc(required_size);
        if (*exi_buffer == NULL) {
            //printf("DEBUG: Failed to allocate buffer\n");
            return -1;
        }
        *exi_size = required_size;
    } else if (*exi_size < required_size) {
        //printf("DEBUG: Reallocating buffer from %zu to %zu\n", *exi_size, required_size);
        uint8_t* new_buffer = (uint8_t*)realloc(*exi_buffer, required_size);
        if (new_buffer == NULL) {
            //printf("DEBUG: Failed to reallocate buffer\n");
            return -1;
        }
        *exi_buffer = new_buffer;
        *exi_size = required_size;
    }

    // Initialize bitstream
    //printf("DEBUG: About to initialize bitstream\n");
    //printf("DEBUG: exi_buffer size: %zu\n", *exi_size);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, *exi_buffer, *exi_size, 0, NULL);
    //printf("DEBUG: Bitstream initialized successfully\n");
    //printf("DEBUG: stream.data_size: %zu\n", stream.data_size);
    //printf("DEBUG: stream.byte_pos: %zu\n", stream.byte_pos);

    // Encode to EXI
    //printf("DEBUG: About to encode to EXI\n");
    int err = encode_iso2_exiDocument(&stream, &exi_doc);
    if (err != 0) {
        //printf("DEBUG: Failed to encode to EXI with error code: %d\n", err);
        //printf("DEBUG: Final stream.byte_pos: %zu\n", stream.byte_pos);
        //printf("DEBUG: Final stream.bit_count: %u\n", stream.bit_count);
        return err;
    }
    //printf("DEBUG: EXI encoding completed successfully\n");

    // Get the actual size of the encoded data
    //printf("DEBUG: About to get encoded size\n");
    *exi_size = exi_bitstream_get_length(&stream);
    //printf("DEBUG: Final encoded size: %zu\n", *exi_size);

    // Cleanup
    cJSON_Delete(root);
    //printf("DEBUG: iso2_certificate_installation_res_encode_json_to_exi finished successfully\n");
    //fflush(stdout);
    return 0;
}

int iso2_certificate_installation_res_decode_exi_to_json(const uint8_t* exi_buffer, size_t exi_size, char** json_str) {
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
        return errn;
    }

    // Create JSON
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return -3;
    }

    // Add CertificateInstallationRes fields
    if (exi_doc.V2G_Message.Body.CertificateInstallationRes_isUsed) {
        struct iso2_CertificateInstallationResType* cert_res = &exi_doc.V2G_Message.Body.CertificateInstallationRes;

        // Add SessionID
        if (exi_doc.V2G_Message.Header.SessionID.bytesLen > 0) {
            char* hex_session_id = binary_to_hex(exi_doc.V2G_Message.Header.SessionID.bytes,
                                               exi_doc.V2G_Message.Header.SessionID.bytesLen);
            if (hex_session_id) {
                cJSON_AddStringToObject(root, "SessionID", hex_session_id);
                free(hex_session_id);
            }
        }

        // Add ResponseCode
        const char* response_code_str = NULL;
        switch (cert_res->ResponseCode) {
            case iso2_responseCodeType_OK:
                response_code_str = "OK";
                break;
            case iso2_responseCodeType_FAILED:
                response_code_str = "FAILED";
                break;
            case iso2_responseCodeType_FAILED_SequenceError:
                response_code_str = "FAILED_SequenceError";
                break;
            case iso2_responseCodeType_FAILED_ServiceIDInvalid:
                response_code_str = "FAILED_ServiceIDInvalid";
                break;
            case iso2_responseCodeType_FAILED_UnknownSession:
                response_code_str = "FAILED_UnknownSession";
                break;
            default:
                response_code_str = "FAILED";
                break;
        }
        cJSON_AddStringToObject(root, "ResponseCode", response_code_str);

        // Add SAProvisioningCertificateChain
        if (cert_res->SAProvisioningCertificateChain.Certificate.bytesLen > 0) {
            cJSON* sa_chain = cJSON_CreateObject();
            if (sa_chain) {
                cJSON_AddItemToObject(root, "SAProvisioningCertificateChain", sa_chain);

                // Add Certificate
                char* base64_cert = binary_to_base64(cert_res->SAProvisioningCertificateChain.Certificate.bytes,
                                                   cert_res->SAProvisioningCertificateChain.Certificate.bytesLen);
                if (base64_cert) {
                    cJSON_AddStringToObject(sa_chain, "Certificate", base64_cert);
                    free(base64_cert);
                }

                // Add SubCertificates
                if (cert_res->SAProvisioningCertificateChain.SubCertificates_isUsed &&
                    cert_res->SAProvisioningCertificateChain.SubCertificates.Certificate.arrayLen > 0) {
                    cJSON* sub_certs = cJSON_CreateArray();
                    if (sub_certs) {
                        cJSON_AddItemToObject(sa_chain, "SubCertificates", sub_certs);

                        for (int i = 0; i < cert_res->SAProvisioningCertificateChain.SubCertificates.Certificate.arrayLen; i++) {
                            char* base64_subcert = binary_to_base64(
                                cert_res->SAProvisioningCertificateChain.SubCertificates.Certificate.array[i].bytes,
                                cert_res->SAProvisioningCertificateChain.SubCertificates.Certificate.array[i].bytesLen);
                            if (base64_subcert) {
                                cJSON* cert_obj = cJSON_CreateObject();
                                if (cert_obj) {
                                    cJSON_AddStringToObject(cert_obj, "Certificate", base64_subcert);
                                    cJSON_AddItemToArray(sub_certs, cert_obj);
                                }
                                free(base64_subcert);
                            }
                        }
                    }
                }
            }
        }

        // Add ContractSignatureCertChain
        if (cert_res->ContractSignatureCertChain.Certificate.bytesLen > 0) {
            cJSON* contract_chain = cJSON_CreateObject();
            if (contract_chain) {
                cJSON_AddItemToObject(root, "ContractSignatureCertChain", contract_chain);

                // Add Certificate
                char* base64_cert = binary_to_base64(cert_res->ContractSignatureCertChain.Certificate.bytes,
                                                   cert_res->ContractSignatureCertChain.Certificate.bytesLen);
                if (base64_cert) {
                    cJSON_AddStringToObject(contract_chain, "Certificate", base64_cert);
                    free(base64_cert);
                }

                // Add SubCertificates
                if (cert_res->ContractSignatureCertChain.SubCertificates_isUsed &&
                    cert_res->ContractSignatureCertChain.SubCertificates.Certificate.arrayLen > 0) {
                    cJSON* sub_certs = cJSON_CreateArray();
                    if (sub_certs) {
                        cJSON_AddItemToObject(contract_chain, "SubCertificates", sub_certs);

                        for (int i = 0; i < cert_res->ContractSignatureCertChain.SubCertificates.Certificate.arrayLen; i++) {
                            char* base64_subcert = binary_to_base64(
                                cert_res->ContractSignatureCertChain.SubCertificates.Certificate.array[i].bytes,
                                cert_res->ContractSignatureCertChain.SubCertificates.Certificate.array[i].bytesLen);
                            if (base64_subcert) {
                                cJSON* cert_obj = cJSON_CreateObject();
                                if (cert_obj) {
                                    cJSON_AddStringToObject(cert_obj, "Certificate", base64_subcert);
                                    cJSON_AddItemToArray(sub_certs, cert_obj);
                                }
                                free(base64_subcert);
                            }
                        }
                    }
                }
            }
        }

        // Add ContractSignatureEncryptedPrivateKey
        if (cert_res->ContractSignatureEncryptedPrivateKey.Id.charactersLen > 0) {
            cJSON* privkey = cJSON_CreateObject();
            if (privkey) {
                cJSON_AddItemToObject(root, "ContractSignatureEncryptedPrivateKey", privkey);

                // Add Id
                char id[iso2_Id_CHARACTER_SIZE + 1];
                memcpy(id, cert_res->ContractSignatureEncryptedPrivateKey.Id.characters,
                       cert_res->ContractSignatureEncryptedPrivateKey.Id.charactersLen);
                id[cert_res->ContractSignatureEncryptedPrivateKey.Id.charactersLen] = '\0';
                cJSON_AddStringToObject(privkey, "Id", id);

                // Add CONTENT
                if (cert_res->ContractSignatureEncryptedPrivateKey.CONTENT.bytesLen > 0) {
                    char* base64_content = binary_to_base64(cert_res->ContractSignatureEncryptedPrivateKey.CONTENT.bytes,
                                                          cert_res->ContractSignatureEncryptedPrivateKey.CONTENT.bytesLen);
                    if (base64_content) {
                        cJSON_AddStringToObject(privkey, "Value", base64_content);
                        free(base64_content);
                    }
                }
            }
        }

        // Add DHpublickey
        if (cert_res->DHpublickey.Id.charactersLen > 0) {
            cJSON* dhkey = cJSON_CreateObject();
            if (dhkey) {
                cJSON_AddItemToObject(root, "DHpublickey", dhkey);

                // Add Id
                char id[iso2_Id_CHARACTER_SIZE + 1];
                memcpy(id, cert_res->DHpublickey.Id.characters,
                       cert_res->DHpublickey.Id.charactersLen);
                id[cert_res->DHpublickey.Id.charactersLen] = '\0';
                cJSON_AddStringToObject(dhkey, "Id", id);

                // Add CONTENT
                if (cert_res->DHpublickey.CONTENT.bytesLen > 0) {
                    char* base64_content = binary_to_base64(cert_res->DHpublickey.CONTENT.bytes,
                                                          cert_res->DHpublickey.CONTENT.bytesLen);
                    if (base64_content) {
                        cJSON_AddStringToObject(dhkey, "Value", base64_content);
                        free(base64_content);
                    }
                }
            }
        }

        // Add eMAID
        if (cert_res->eMAID.Id.charactersLen > 0) {
            cJSON* emaid = cJSON_CreateObject();
            if (emaid) {
                cJSON_AddItemToObject(root, "eMAID", emaid);

                // Add Id
                char id[iso2_Id_CHARACTER_SIZE + 1];
                memcpy(id, cert_res->eMAID.Id.characters,
                       cert_res->eMAID.Id.charactersLen);
                id[cert_res->eMAID.Id.charactersLen] = '\0';
                cJSON_AddStringToObject(emaid, "Id", id);

                // Add CONTENT
                if (cert_res->eMAID.CONTENT.charactersLen > 0) {
                    char content[iso2_CONTENT_CHARACTER_SIZE + 1];
                    memcpy(content, cert_res->eMAID.CONTENT.characters,
                           cert_res->eMAID.CONTENT.charactersLen);
                    content[cert_res->eMAID.CONTENT.charactersLen] = '\0';
                    cJSON_AddStringToObject(emaid, "Value", content);
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

// ISO-20 Certificate Installation Request stubs
int iso20_certificate_installation_req_encode_json_to_exi(const char* json_str, uint8_t* exi_buf, size_t exi_buf_size, size_t* exi_buf_len) {
    if (!json_str || !exi_buf || !exi_buf_len) {
        return -1;
    }

    // Parse JSON
    cJSON* json = cJSON_Parse(json_str);
    if (!json) {
        return -2;
    }

    // Initialize EXI document
    struct iso20_exiDocument exi_doc;
    init_iso20_exiDocument(&exi_doc);

    // Set certificate installation request as used
    exi_doc.CertificateInstallationReq_isUsed = 1;

    // Initialize certificate installation request
    init_iso20_CertificateInstallationReqType(&exi_doc.CertificateInstallationReq);

    // Parse header
    cJSON* header = cJSON_GetObjectItem(json, "Header");
    if (header) {
        cJSON* session_id = cJSON_GetObjectItem(header, "SessionID");
        if (session_id && session_id->valuestring) {
            size_t len = strlen(session_id->valuestring);
            if (len <= iso20_sessionIDType_BYTES_SIZE) {
                memcpy(exi_doc.CertificateInstallationReq.Header.SessionID.bytes, session_id->valuestring, len);
                exi_doc.CertificateInstallationReq.Header.SessionID.bytesLen = (uint16_t)len;
            }
        }

        cJSON* timestamp = cJSON_GetObjectItem(header, "TimeStamp");
        if (timestamp && timestamp->valuestring) {
            exi_doc.CertificateInstallationReq.Header.TimeStamp = (uint64_t)atoll(timestamp->valuestring);
        }
    }

    // Parse OEM provisioning certificate chain
    cJSON* oem_cert = cJSON_GetObjectItem(json, "OEMProvisioningCertificateChain");
    if (oem_cert) {
        cJSON* cert = cJSON_GetObjectItem(oem_cert, "Certificate");
        if (cert && cert->valuestring) {
            size_t len = strlen(cert->valuestring);
            if (len <= iso20_certificateType_BYTES_SIZE) {
                memcpy(exi_doc.CertificateInstallationReq.OEMProvisioningCertificateChain.Certificate.bytes, cert->valuestring, len);
                exi_doc.CertificateInstallationReq.OEMProvisioningCertificateChain.Certificate.bytesLen = (uint16_t)len;
            }
        }

        cJSON* sub_certs = cJSON_GetObjectItem(oem_cert, "SubCertificates");
        if (sub_certs && cJSON_IsArray(sub_certs)) {
            cJSON* cert_array = cJSON_GetObjectItem(sub_certs, "Certificate");
            if (cert_array && cJSON_IsArray(cert_array)) {
                int array_size = cJSON_GetArraySize(cert_array);
                if (array_size <= iso20_certificateType_3_ARRAY_SIZE) {
                    exi_doc.CertificateInstallationReq.OEMProvisioningCertificateChain.SubCertificates.Certificate.arrayLen = (uint16_t)array_size;
                    for (int i = 0; i < array_size; i++) {
                        cJSON* cert_item = cJSON_GetArrayItem(cert_array, i);
                        if (cert_item && cert_item->valuestring) {
                            size_t len = strlen(cert_item->valuestring);
                            if (len <= iso20_certificateType_BYTES_SIZE) {
                                memcpy(exi_doc.CertificateInstallationReq.OEMProvisioningCertificateChain.SubCertificates.Certificate.array[i].bytes, 
                                      cert_item->valuestring, len);
                                exi_doc.CertificateInstallationReq.OEMProvisioningCertificateChain.SubCertificates.Certificate.array[i].bytesLen = (uint16_t)len;
                            }
                        }
                    }
                    exi_doc.CertificateInstallationReq.OEMProvisioningCertificateChain.SubCertificates_isUsed = 1;
                }
            }
        }
    }

    // Parse list of root certificate IDs
    cJSON* root_certs = cJSON_GetObjectItem(json, "ListOfRootCertificateIDs");
    if (root_certs) {
        cJSON* cert_array = cJSON_GetObjectItem(root_certs, "RootCertificateID");
        if (cert_array && cJSON_IsArray(cert_array)) {
            int array_size = cJSON_GetArraySize(cert_array);
            if (array_size <= iso20_X509IssuerSerialType_20_ARRAY_SIZE) {
                exi_doc.CertificateInstallationReq.ListOfRootCertificateIDs.RootCertificateID.arrayLen = (uint16_t)array_size;
                for (int i = 0; i < array_size; i++) {
                    cJSON* cert_item = cJSON_GetArrayItem(cert_array, i);
                    if (cert_item) {
                        cJSON* issuer = cJSON_GetObjectItem(cert_item, "X509IssuerName");
                        if (issuer && issuer->valuestring) {
                            size_t len = strlen(issuer->valuestring);
                            if (len <= iso20_X509IssuerName_CHARACTER_SIZE) {
                                memcpy(exi_doc.CertificateInstallationReq.ListOfRootCertificateIDs.RootCertificateID.array[i].X509IssuerName.characters,
                                      issuer->valuestring, len);
                                exi_doc.CertificateInstallationReq.ListOfRootCertificateIDs.RootCertificateID.array[i].X509IssuerName.charactersLen = (uint16_t)len;
                            }
                        }

                        cJSON* serial = cJSON_GetObjectItem(cert_item, "X509SerialNumber");
                        if (serial && serial->valuestring) {
                            int64_t serial_value = atoll(serial->valuestring);
                            exi_basetypes_convert_to_signed(&exi_doc.CertificateInstallationReq.ListOfRootCertificateIDs.RootCertificateID.array[i].X509SerialNumber,
                                                          (int32_t)serial_value,
                                                          EXI_BASETYPES_UINT32_MAX_OCTETS);
                        }
                    }
                }
            }
        }
    }

    // Parse maximum contract certificate chains
    cJSON* max_chains = cJSON_GetObjectItem(json, "MaximumContractCertificateChains");
    if (max_chains && max_chains->valueint >= 0 && max_chains->valueint <= 255) {
        exi_doc.CertificateInstallationReq.MaximumContractCertificateChains = (uint8_t)max_chains->valueint;
    }

    // Parse prioritized EMA IDs
    cJSON* ema_ids = cJSON_GetObjectItem(json, "PrioritizedEMAIDs");
    if (ema_ids) {
        cJSON* ema_array = cJSON_GetObjectItem(ema_ids, "EMAID");
        if (ema_array && cJSON_IsArray(ema_array)) {
            int array_size = cJSON_GetArraySize(ema_array);
            if (array_size <= iso20_identifierType_8_ARRAY_SIZE) {
                exi_doc.CertificateInstallationReq.PrioritizedEMAIDs.EMAID.arrayLen = (uint16_t)array_size;
                for (int i = 0; i < array_size; i++) {
                    cJSON* ema_item = cJSON_GetArrayItem(ema_array, i);
                    if (ema_item && ema_item->valuestring) {
                        size_t len = strlen(ema_item->valuestring);
                        if (len <= iso20_EMAID_CHARACTER_SIZE) {
                            memcpy(exi_doc.CertificateInstallationReq.PrioritizedEMAIDs.EMAID.array[i].characters,
                                  ema_item->valuestring, len);
                            exi_doc.CertificateInstallationReq.PrioritizedEMAIDs.EMAID.array[i].charactersLen = (uint16_t)len;
                        }
                    }
                }
                exi_doc.CertificateInstallationReq.PrioritizedEMAIDs_isUsed = 1;
            }
        }
    }

    // Initialize bitstream
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, exi_buf, exi_buf_size, 0, NULL);

    // Encode to EXI
    int ret = encode_iso20_exiDocument(&stream, &exi_doc);
    if (ret == 0) {
        *exi_buf_len = stream.byte_pos;
    }

    // Cleanup
    cJSON_Delete(json);

    return ret;
}

int iso20_certificate_installation_req_decode_exi_to_json(const uint8_t* exi_buffer, size_t exi_size, char** json_str) {
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
    struct iso20_exiDocument exi_doc;
    memset(&exi_doc, 0, sizeof(exi_doc));
    
    int errn = decode_iso20_exiDocument(&stream, &exi_doc);
    if (errn != 0) {
        return errn;
    }

    // Create JSON
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return -3;
    }

    // Add CertificateInstallationReq fields
    if (exi_doc.CertificateInstallationReq_isUsed) {
        struct iso20_CertificateInstallationReqType* cert_req = &exi_doc.CertificateInstallationReq;

        // Add SessionID
        if (cert_req->Header.SessionID.bytesLen > 0) {
            char* hex_session_id = binary_to_hex(cert_req->Header.SessionID.bytes,
                                               cert_req->Header.SessionID.bytesLen);
            if (hex_session_id) {
                cJSON_AddStringToObject(root, "SessionID", hex_session_id);
                free(hex_session_id);
            }
        }

        // Add TimeStamp
        char timestamp_str[32];
        snprintf(timestamp_str, sizeof(timestamp_str), "%llu", cert_req->Header.TimeStamp);
        cJSON_AddStringToObject(root, "TimeStamp", timestamp_str);

        // Add OEMProvisioningCertificateChain
        cJSON* oem_chain = cJSON_CreateObject();
        if (oem_chain) {
            cJSON_AddItemToObject(root, "OEMProvisioningCertificateChain", oem_chain);

            // Add Id
            if (cert_req->OEMProvisioningCertificateChain.Id.charactersLen > 0) {
                char id[iso20_Id_CHARACTER_SIZE + 1];
                memcpy(id, cert_req->OEMProvisioningCertificateChain.Id.characters, 
                       cert_req->OEMProvisioningCertificateChain.Id.charactersLen);
                id[cert_req->OEMProvisioningCertificateChain.Id.charactersLen] = '\0';
                cJSON_AddStringToObject(oem_chain, "Id", id);
            }

            // Add Certificate
            if (cert_req->OEMProvisioningCertificateChain.Certificate.bytesLen > 0) {
                char* base64_cert = binary_to_base64(cert_req->OEMProvisioningCertificateChain.Certificate.bytes,
                                                   cert_req->OEMProvisioningCertificateChain.Certificate.bytesLen);
                if (base64_cert) {
                    cJSON_AddStringToObject(oem_chain, "Certificate", base64_cert);
                    free(base64_cert);
                }
            }

            // Add SubCertificates
            if (cert_req->OEMProvisioningCertificateChain.SubCertificates.Certificate.arrayLen > 0) {
                cJSON* sub_certs = cJSON_CreateArray();
                if (sub_certs) {
                    cJSON_AddItemToObject(oem_chain, "SubCertificates", sub_certs);

                    for (int i = 0; i < cert_req->OEMProvisioningCertificateChain.SubCertificates.Certificate.arrayLen; i++) {
                        if (cert_req->OEMProvisioningCertificateChain.SubCertificates.Certificate.array[i].bytesLen > 0) {
                            char* base64_subcert = binary_to_base64(
                                cert_req->OEMProvisioningCertificateChain.SubCertificates.Certificate.array[i].bytes,
                                cert_req->OEMProvisioningCertificateChain.SubCertificates.Certificate.array[i].bytesLen);
                            if (base64_subcert) {
                                cJSON* cert_obj = cJSON_CreateObject();
                                if (cert_obj) {
                                    cJSON_AddStringToObject(cert_obj, "Certificate", base64_subcert);
                                    cJSON_AddItemToArray(sub_certs, cert_obj);
                                }
                                free(base64_subcert);
                            }
                        }
                    }
                }
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
                            char issuer[iso20_X509IssuerName_CHARACTER_SIZE + 1];
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

        // Add MaximumContractCertificateChains
        cJSON_AddNumberToObject(root, "MaximumContractCertificateChains", cert_req->MaximumContractCertificateChains);

        // Add PrioritizedEMAIDs if present
        if (cert_req->PrioritizedEMAIDs_isUsed && cert_req->PrioritizedEMAIDs.EMAID.arrayLen > 0) {
            cJSON* emaids = cJSON_CreateArray();
            if (emaids) {
                cJSON_AddItemToObject(root, "PrioritizedEMAIDs", emaids);

                for (int i = 0; i < cert_req->PrioritizedEMAIDs.EMAID.arrayLen; i++) {
                    if (cert_req->PrioritizedEMAIDs.EMAID.array[i].charactersLen > 0) {
                        char emaid[iso20_EMAID_CHARACTER_SIZE + 1];
                        memcpy(emaid,
                               cert_req->PrioritizedEMAIDs.EMAID.array[i].characters,
                               cert_req->PrioritizedEMAIDs.EMAID.array[i].charactersLen);
                        emaid[cert_req->PrioritizedEMAIDs.EMAID.array[i].charactersLen] = '\0';
                        cJSON_AddItemToArray(emaids, cJSON_CreateString(emaid));
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

// ISO-20 Certificate Installation Response stubs
int iso20_certificate_installation_res_encode_json_to_exi(const char* json_str, uint8_t** exi_buffer, size_t* exi_size) {
    if (!json_str || !exi_buffer || !exi_size) {
        return -1;
    }

    // Parse JSON
    cJSON* root = cJSON_Parse(json_str);
    if (!root) {
        return -2;
    }

    // Create EXI document
    struct iso20_exiDocument exi_doc;
    memset(&exi_doc, 0, sizeof(exi_doc));

    // Set certificate installation response as used
    exi_doc.CertificateInstallationRes_isUsed = 1;

    // Initialize certificate installation response
    init_iso20_CertificateInstallationResType(&exi_doc.CertificateInstallationRes);

    // Get SessionID from JSON
    cJSON* session_id = cJSON_GetObjectItem(root, "SessionID");
    if (session_id && session_id->valuestring) {
        size_t len = strlen(session_id->valuestring);
        if (len <= iso20_sessionIDType_BYTES_SIZE) {
            memcpy(exi_doc.CertificateInstallationRes.Header.SessionID.bytes, session_id->valuestring, len);
            exi_doc.CertificateInstallationRes.Header.SessionID.bytesLen = (uint16_t)len;
        }
    }

    // Get TimeStamp from JSON
    cJSON* timestamp = cJSON_GetObjectItem(root, "TimeStamp");
    if (timestamp && timestamp->valuestring) {
        exi_doc.CertificateInstallationRes.Header.TimeStamp = (uint64_t)atoll(timestamp->valuestring);
    }

    // Get ResponseCode from JSON
    cJSON* response_code = cJSON_GetObjectItem(root, "ResponseCode");
    if (response_code && response_code->valuestring) {
        // Convert string response code to enum value
        if (strcmp(response_code->valuestring, "OK") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_OK;
        } else if (strcmp(response_code->valuestring, "OK_CertificateExpiresSoon") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_OK_CertificateExpiresSoon;
        } else if (strcmp(response_code->valuestring, "OK_NewSessionEstablished") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_OK_NewSessionEstablished;
        } else if (strcmp(response_code->valuestring, "OK_OldSessionJoined") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_OK_OldSessionJoined;
        } else if (strcmp(response_code->valuestring, "OK_PowerToleranceConfirmed") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_OK_PowerToleranceConfirmed;
        } else if (strcmp(response_code->valuestring, "WARNING_AuthorizationSelectionInvalid") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_WARNING_AuthorizationSelectionInvalid;
        } else if (strcmp(response_code->valuestring, "WARNING_CertificateExpired") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_WARNING_CertificateExpired;
        } else if (strcmp(response_code->valuestring, "WARNING_CertificateNotYetValid") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_WARNING_CertificateNotYetValid;
        } else if (strcmp(response_code->valuestring, "WARNING_CertificateRevoked") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_WARNING_CertificateRevoked;
        } else if (strcmp(response_code->valuestring, "WARNING_CertificateValidationError") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_WARNING_CertificateValidationError;
        } else if (strcmp(response_code->valuestring, "WARNING_ChallengeInvalid") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_WARNING_ChallengeInvalid;
        } else if (strcmp(response_code->valuestring, "WARNING_EIMAuthorizationFailure") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_WARNING_EIMAuthorizationFailure;
        } else if (strcmp(response_code->valuestring, "WARNING_eMSPUnknown") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_WARNING_eMSPUnknown;
        } else if (strcmp(response_code->valuestring, "WARNING_EVPowerProfileViolation") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_WARNING_EVPowerProfileViolation;
        } else if (strcmp(response_code->valuestring, "WARNING_GeneralPnCAuthorizationError") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_WARNING_GeneralPnCAuthorizationError;
        } else if (strcmp(response_code->valuestring, "WARNING_NoCertificateAvailable") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_WARNING_NoCertificateAvailable;
        } else if (strcmp(response_code->valuestring, "WARNING_NoContractMatchingPCIDFound") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_WARNING_NoContractMatchingPCIDFound;
        } else if (strcmp(response_code->valuestring, "WARNING_PowerToleranceNotConfirmed") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_WARNING_PowerToleranceNotConfirmed;
        } else if (strcmp(response_code->valuestring, "WARNING_ScheduleRenegotiationFailed") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_WARNING_ScheduleRenegotiationFailed;
        } else if (strcmp(response_code->valuestring, "WARNING_StandbyNotAllowed") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_WARNING_StandbyNotAllowed;
        } else if (strcmp(response_code->valuestring, "WARNING_WPT") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_WARNING_WPT;
        } else if (strcmp(response_code->valuestring, "FAILED") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED;
        } else if (strcmp(response_code->valuestring, "FAILED_AssociationError") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED_AssociationError;
        } else if (strcmp(response_code->valuestring, "FAILED_ContactorError") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED_ContactorError;
        } else if (strcmp(response_code->valuestring, "FAILED_EVPowerProfileInvalid") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED_EVPowerProfileInvalid;
        } else if (strcmp(response_code->valuestring, "FAILED_EVPowerProfileViolation") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED_EVPowerProfileViolation;
        } else if (strcmp(response_code->valuestring, "FAILED_MeteringSignatureNotValid") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED_MeteringSignatureNotValid;
        } else if (strcmp(response_code->valuestring, "FAILED_NoEnergyTransferServiceSelected") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED_NoEnergyTransferServiceSelected;
        } else if (strcmp(response_code->valuestring, "FAILED_NoServiceRenegotiationSupported") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED_NoServiceRenegotiationSupported;
        } else if (strcmp(response_code->valuestring, "FAILED_PauseNotAllowed") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED_PauseNotAllowed;
        } else if (strcmp(response_code->valuestring, "FAILED_PowerDeliveryNotApplied") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED_PowerDeliveryNotApplied;
        } else if (strcmp(response_code->valuestring, "FAILED_PowerToleranceNotConfirmed") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED_PowerToleranceNotConfirmed;
        } else if (strcmp(response_code->valuestring, "FAILED_ScheduleRenegotiation") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED_ScheduleRenegotiation;
        } else if (strcmp(response_code->valuestring, "FAILED_ScheduleSelectionInvalid") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED_ScheduleSelectionInvalid;
        } else if (strcmp(response_code->valuestring, "FAILED_SequenceError") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED_SequenceError;
        } else if (strcmp(response_code->valuestring, "FAILED_ServiceIDInvalid") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED_ServiceIDInvalid;
        } else if (strcmp(response_code->valuestring, "FAILED_ServiceSelectionInvalid") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED_ServiceSelectionInvalid;
        } else if (strcmp(response_code->valuestring, "FAILED_SignatureError") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED_SignatureError;
        } else if (strcmp(response_code->valuestring, "FAILED_UnknownSession") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED_UnknownSession;
        } else if (strcmp(response_code->valuestring, "FAILED_WrongChargeParameter") == 0) {
            exi_doc.CertificateInstallationRes.ResponseCode = iso20_responseCodeType_FAILED_WrongChargeParameter;
        }
    }

    // Get EVSEProcessing from JSON
    cJSON* evse_processing = cJSON_GetObjectItem(root, "EVSEProcessing");
    if (evse_processing && evse_processing->valuestring) {
        if (strcmp(evse_processing->valuestring, "Finished") == 0) {
            exi_doc.CertificateInstallationRes.EVSEProcessing = iso20_processingType_Finished;
        } else if (strcmp(evse_processing->valuestring, "Ongoing") == 0) {
            exi_doc.CertificateInstallationRes.EVSEProcessing = iso20_processingType_Ongoing;
        } else if (strcmp(evse_processing->valuestring, "Ongoing_WaitingForCustomerInteraction") == 0) {
            exi_doc.CertificateInstallationRes.EVSEProcessing = iso20_processingType_Ongoing_WaitingForCustomerInteraction;
        }
    }

    // Get CPSCertificateChain from JSON
    cJSON* cps_cert = cJSON_GetObjectItem(root, "CPSCertificateChain");
    if (cps_cert) {
        // Get Certificate
        cJSON* cert = cJSON_GetObjectItem(cps_cert, "Certificate");
        if (cert && cert->valuestring) {
            size_t len = strlen(cert->valuestring);
            if (len <= iso20_certificateType_BYTES_SIZE) {
                memcpy(exi_doc.CertificateInstallationRes.CPSCertificateChain.Certificate.bytes, cert->valuestring, len);
                exi_doc.CertificateInstallationRes.CPSCertificateChain.Certificate.bytesLen = (uint16_t)len;
            }
        }

        // Get SubCertificates
        cJSON* sub_certs = cJSON_GetObjectItem(cps_cert, "SubCertificates");
        if (sub_certs && cJSON_IsArray(sub_certs)) {
            int array_len = cJSON_GetArraySize(sub_certs);
            if (array_len > 0 && array_len <= iso20_certificateType_3_ARRAY_SIZE) {
                exi_doc.CertificateInstallationRes.CPSCertificateChain.SubCertificates.Certificate.arrayLen = array_len;
                for (int i = 0; i < array_len; i++) {
                    cJSON* sub_cert = cJSON_GetArrayItem(sub_certs, i);
                    if (sub_cert) {
                        cJSON* cert = cJSON_GetObjectItem(sub_cert, "Certificate");
                        if (cert && cert->valuestring) {
                            size_t len = strlen(cert->valuestring);
                            if (len <= iso20_certificateType_BYTES_SIZE) {
                                memcpy(exi_doc.CertificateInstallationRes.CPSCertificateChain.SubCertificates.Certificate.array[i].bytes, 
                                      cert->valuestring, len);
                                exi_doc.CertificateInstallationRes.CPSCertificateChain.SubCertificates.Certificate.array[i].bytesLen = (uint16_t)len;
                            }
                        }
                    }
                }
            }
        }
    }

    // Get SignedInstallationData from JSON
    cJSON* signed_data = cJSON_GetObjectItem(root, "SignedInstallationData");
    if (signed_data) {
        // Get Id
        cJSON* id = cJSON_GetObjectItem(signed_data, "Id");
        if (id && id->valuestring) {
            size_t len = strlen(id->valuestring);
            if (len <= iso20_Id_CHARACTER_SIZE) {
                memcpy(exi_doc.CertificateInstallationRes.SignedInstallationData.Id.characters, id->valuestring, len);
                exi_doc.CertificateInstallationRes.SignedInstallationData.Id.charactersLen = (uint16_t)len;
            }
        }

        // Get Value
        cJSON* value = cJSON_GetObjectItem(signed_data, "Value");
        if (value && value->valuestring) {
            size_t len = strlen(value->valuestring);
            if (len <= iso20_SignedInstallationDataType_BYTES_SIZE) {
                memcpy(exi_doc.CertificateInstallationRes.SignedInstallationData.CONTENT.bytes, value->valuestring, len);
                exi_doc.CertificateInstallationRes.SignedInstallationData.CONTENT.bytesLen = (uint16_t)len;
            }
        }
    }

    // Get RemainingContractCertificateChains from JSON
    cJSON* remaining_chains = cJSON_GetObjectItem(root, "RemainingContractCertificateChains");
    if (remaining_chains && cJSON_IsNumber(remaining_chains)) {
        exi_doc.CertificateInstallationRes.RemainingContractCertificateChains = (uint8_t)remaining_chains->valueint;
    }

    // Initialize bitstream
    exi_bitstream_t stream;
    stream.data = NULL;
    stream.data_size = 0;
    stream.byte_pos = 0;
    stream.bit_count = 0;
    stream._init_called = 0;
    stream._flag_byte_pos = 0;
    stream.status_callback = NULL;

    // Encode to EXI
    int err = encode_iso20_exiDocument(&stream, &exi_doc);
    if (err != 0) {
        cJSON_Delete(root);
        return err;
    }

    // Get the encoded data
    *exi_size = exi_bitstream_get_length(&stream);
    *exi_buffer = (uint8_t*)malloc(*exi_size);
    if (!*exi_buffer) {
        cJSON_Delete(root);
        return -3;
    }

    memcpy(*exi_buffer, stream.data, *exi_size);

    // Cleanup
    cJSON_Delete(root);
    return 0;
}

int iso20_certificate_installation_res_decode_exi_to_json(const uint8_t* exi_buffer, size_t exi_size, char** json_str) {
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
    struct iso20_exiDocument exi_doc;
    memset(&exi_doc, 0, sizeof(exi_doc));
    
    int errn = decode_iso20_exiDocument(&stream, &exi_doc);
    if (errn != 0) {
        return errn;
    }

    // Create JSON
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return -3;
    }

    // Add CertificateInstallationRes fields
    if (exi_doc.CertificateInstallationRes_isUsed) {
        struct iso20_CertificateInstallationResType* cert_res = &exi_doc.CertificateInstallationRes;

        // Add SessionID
        if (exi_doc.CertificateInstallationRes.Header.SessionID.bytesLen > 0) {
            char* hex_session_id = binary_to_hex(exi_doc.CertificateInstallationRes.Header.SessionID.bytes,
                                               exi_doc.CertificateInstallationRes.Header.SessionID.bytesLen);
            if (hex_session_id) {
                cJSON_AddStringToObject(root, "SessionID", hex_session_id);
                free(hex_session_id);
            }
        }

        // Add TimeStamp
        char timestamp_str[32];
        snprintf(timestamp_str, sizeof(timestamp_str), "%llu", cert_res->Header.TimeStamp);
        cJSON_AddStringToObject(root, "TimeStamp", timestamp_str);

        // Add ResponseCode
        const char* response_code_str = NULL;
        switch (cert_res->ResponseCode) {
            case iso20_responseCodeType_OK:
                response_code_str = "OK";
                break;
            case iso20_responseCodeType_OK_CertificateExpiresSoon:
                response_code_str = "OK_CertificateExpiresSoon";
                break;
            case iso20_responseCodeType_OK_NewSessionEstablished:
                response_code_str = "OK_NewSessionEstablished";
                break;
            case iso20_responseCodeType_OK_OldSessionJoined:
                response_code_str = "OK_OldSessionJoined";
                break;
            case iso20_responseCodeType_OK_PowerToleranceConfirmed:
                response_code_str = "OK_PowerToleranceConfirmed";
                break;
            case iso20_responseCodeType_WARNING_AuthorizationSelectionInvalid:
                response_code_str = "WARNING_AuthorizationSelectionInvalid";
                break;
            case iso20_responseCodeType_WARNING_CertificateExpired:
                response_code_str = "WARNING_CertificateExpired";
                break;
            case iso20_responseCodeType_WARNING_CertificateNotYetValid:
                response_code_str = "WARNING_CertificateNotYetValid";
                break;
            case iso20_responseCodeType_WARNING_CertificateRevoked:
                response_code_str = "WARNING_CertificateRevoked";
                break;
            case iso20_responseCodeType_WARNING_CertificateValidationError:
                response_code_str = "WARNING_CertificateValidationError";
                break;
            case iso20_responseCodeType_WARNING_ChallengeInvalid:
                response_code_str = "WARNING_ChallengeInvalid";
                break;
            case iso20_responseCodeType_WARNING_EIMAuthorizationFailure:
                response_code_str = "WARNING_EIMAuthorizationFailure";
                break;
            case iso20_responseCodeType_WARNING_eMSPUnknown:
                response_code_str = "WARNING_eMSPUnknown";
                break;
            case iso20_responseCodeType_WARNING_EVPowerProfileViolation:
                response_code_str = "WARNING_EVPowerProfileViolation";
                break;
            case iso20_responseCodeType_WARNING_GeneralPnCAuthorizationError:
                response_code_str = "WARNING_GeneralPnCAuthorizationError";
                break;
            case iso20_responseCodeType_WARNING_NoCertificateAvailable:
                response_code_str = "WARNING_NoCertificateAvailable";
                break;
            case iso20_responseCodeType_WARNING_NoContractMatchingPCIDFound:
                response_code_str = "WARNING_NoContractMatchingPCIDFound";
                break;
            case iso20_responseCodeType_WARNING_PowerToleranceNotConfirmed:
                response_code_str = "WARNING_PowerToleranceNotConfirmed";
                break;
            case iso20_responseCodeType_WARNING_ScheduleRenegotiationFailed:
                response_code_str = "WARNING_ScheduleRenegotiationFailed";
                break;
            case iso20_responseCodeType_WARNING_StandbyNotAllowed:
                response_code_str = "WARNING_StandbyNotAllowed";
                break;
            case iso20_responseCodeType_WARNING_WPT:
                response_code_str = "WARNING_WPT";
                break;
            case iso20_responseCodeType_FAILED:
                response_code_str = "FAILED";
                break;
            case iso20_responseCodeType_FAILED_AssociationError:
                response_code_str = "FAILED_AssociationError";
                break;
            case iso20_responseCodeType_FAILED_ContactorError:
                response_code_str = "FAILED_ContactorError";
                break;
            case iso20_responseCodeType_FAILED_EVPowerProfileInvalid:
                response_code_str = "FAILED_EVPowerProfileInvalid";
                break;
            case iso20_responseCodeType_FAILED_EVPowerProfileViolation:
                response_code_str = "FAILED_EVPowerProfileViolation";
                break;
            case iso20_responseCodeType_FAILED_MeteringSignatureNotValid:
                response_code_str = "FAILED_MeteringSignatureNotValid";
                break;
            case iso20_responseCodeType_FAILED_NoEnergyTransferServiceSelected:
                response_code_str = "FAILED_NoEnergyTransferServiceSelected";
                break;
            case iso20_responseCodeType_FAILED_NoServiceRenegotiationSupported:
                response_code_str = "FAILED_NoServiceRenegotiationSupported";
                break;
            case iso20_responseCodeType_FAILED_PauseNotAllowed:
                response_code_str = "FAILED_PauseNotAllowed";
                break;
            case iso20_responseCodeType_FAILED_PowerDeliveryNotApplied:
                response_code_str = "FAILED_PowerDeliveryNotApplied";
                break;
            case iso20_responseCodeType_FAILED_PowerToleranceNotConfirmed:
                response_code_str = "FAILED_PowerToleranceNotConfirmed";
                break;
            case iso20_responseCodeType_FAILED_ScheduleRenegotiation:
                response_code_str = "FAILED_ScheduleRenegotiation";
                break;
            case iso20_responseCodeType_FAILED_ScheduleSelectionInvalid:
                response_code_str = "FAILED_ScheduleSelectionInvalid";
                break;
            case iso20_responseCodeType_FAILED_SequenceError:
                response_code_str = "FAILED_SequenceError";
                break;
            case iso20_responseCodeType_FAILED_ServiceIDInvalid:
                response_code_str = "FAILED_ServiceIDInvalid";
                break;
            case iso20_responseCodeType_FAILED_ServiceSelectionInvalid:
                response_code_str = "FAILED_ServiceSelectionInvalid";
                break;
            case iso20_responseCodeType_FAILED_SignatureError:
                response_code_str = "FAILED_SignatureError";
                break;
            case iso20_responseCodeType_FAILED_UnknownSession:
                response_code_str = "FAILED_UnknownSession";
                break;
            case iso20_responseCodeType_FAILED_WrongChargeParameter:
                response_code_str = "FAILED_WrongChargeParameter";
                break;
            default:
                response_code_str = "FAILED";
                break;
        }
        cJSON_AddStringToObject(root, "ResponseCode", response_code_str);

        // Add CPSCertificateChain
        if (cert_res->CPSCertificateChain.Certificate.bytesLen > 0) {
            cJSON* cps_chain = cJSON_CreateObject();
            if (cps_chain) {
                cJSON_AddItemToObject(root, "CPSCertificateChain", cps_chain);

                // Add Certificate
                char* base64_cert = binary_to_base64(cert_res->CPSCertificateChain.Certificate.bytes,
                                                   cert_res->CPSCertificateChain.Certificate.bytesLen);
                if (base64_cert) {
                    cJSON_AddStringToObject(cps_chain, "Certificate", base64_cert);
                    free(base64_cert);
                }

                // Add SubCertificates
                if (cert_res->CPSCertificateChain.SubCertificates.Certificate.arrayLen > 0) {
                    cJSON* sub_certs = cJSON_CreateArray();
                    if (sub_certs) {
                        cJSON_AddItemToObject(cps_chain, "SubCertificates", sub_certs);

                        for (int i = 0; i < cert_res->CPSCertificateChain.SubCertificates.Certificate.arrayLen; i++) {
                            char* base64_subcert = binary_to_base64(
                                cert_res->CPSCertificateChain.SubCertificates.Certificate.array[i].bytes,
                                cert_res->CPSCertificateChain.SubCertificates.Certificate.array[i].bytesLen);
                            if (base64_subcert) {
                                cJSON* cert_obj = cJSON_CreateObject();
                                if (cert_obj) {
                                    cJSON_AddStringToObject(cert_obj, "Certificate", base64_subcert);
                                    cJSON_AddItemToArray(sub_certs, cert_obj);
                                }
                                free(base64_subcert);
                            }
                        }
                    }
                }
            }
        }

        // Add SignedInstallationData
        cJSON* signed_data = cJSON_CreateObject();
        if (signed_data) {
            cJSON_AddItemToObject(root, "SignedInstallationData", signed_data);

            // Add Id
            if (cert_res->SignedInstallationData.Id.charactersLen > 0) {
                char id[iso20_Id_CHARACTER_SIZE + 1];
                memcpy(id, cert_res->SignedInstallationData.Id.characters,
                       cert_res->SignedInstallationData.Id.charactersLen);
                id[cert_res->SignedInstallationData.Id.charactersLen] = '\0';
                cJSON_AddStringToObject(signed_data, "Id", id);
            }

            // Add CONTENT
            if (cert_res->SignedInstallationData.CONTENT.bytesLen > 0) {
                char* base64_content = binary_to_base64(cert_res->SignedInstallationData.CONTENT.bytes,
                                                      cert_res->SignedInstallationData.CONTENT.bytesLen);
                if (base64_content) {
                    cJSON_AddStringToObject(signed_data, "Value", base64_content);
                    free(base64_content);
                }
            }
        }

        // Add RemainingContractCertificateChains
        cJSON_AddNumberToObject(root, "RemainingContractCertificateChains", cert_res->RemainingContractCertificateChains);
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