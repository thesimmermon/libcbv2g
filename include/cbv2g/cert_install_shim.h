#ifndef CBV2G_CERT_INSTALL_SHIM_H
#define CBV2G_CERT_INSTALL_SHIM_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
    #ifdef CBV2G_JSON_SHIM_EXPORTS
        #define DLL_PUBLIC __declspec(dllexport)
    #else
        #define DLL_PUBLIC __declspec(dllimport)
    #endif
#else
    #define DLL_PUBLIC __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Encodes a JSON string to EXI format for ISO-15118-2 CertificateInstallationReq
 * 
 * @param json_str Input JSON string
 * @param exi_buffer Output buffer for EXI data (will be allocated)
 * @param exi_size Size of the EXI data
 * @return int 0 on success, negative value on error
 */
DLL_PUBLIC int iso2_cert_install_encode_json_to_exi(
    const char* json_str,
    uint8_t** exi_buffer,
    size_t* exi_size
);

/**
 * @brief Decodes EXI data to JSON string for ISO-15118-2 CertificateInstallationReq
 * 
 * @param exi_buffer Input EXI data
 * @param exi_size Size of the EXI data
 * @param json_str Output JSON string (will be allocated)
 * @return int 0 on success, negative value on error
 */
DLL_PUBLIC int iso2_cert_install_decode_exi_to_json(
    const uint8_t* exi_buffer,
    size_t exi_size,
    char** json_str
);

/**
 * @brief Frees memory allocated by the ISO-15118-2 shim functions
 * 
 * @param ptr Pointer to memory to free
 */
DLL_PUBLIC void iso2_cert_install_free(void* ptr);

#ifdef __cplusplus
}
#endif

#endif /* CBV2G_CERT_INSTALL_SHIM_H */ 