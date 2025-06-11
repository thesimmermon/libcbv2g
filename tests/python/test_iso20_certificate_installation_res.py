#!/usr/bin/env python3

import ctypes
import json
import os
import sys
import base64

# Load the shared library
if sys.platform == 'win32':
    lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), '../../build_win_arm64/bin/Release/cbv2g_json_shim.dll'))
else:
    lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), '../../build/lib/libcbv2g_json_shim.so'))

# Define function signatures
lib.iso20_certificate_installation_res_encode_json_to_exi.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)), ctypes.POINTER(ctypes.c_size_t)]
lib.iso20_certificate_installation_res_encode_json_to_exi.restype = ctypes.c_int

lib.iso20_certificate_installation_res_decode_exi_to_json.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_char_p)]
lib.iso20_certificate_installation_res_decode_exi_to_json.restype = ctypes.c_int

lib.iso2_certificate_installation_req_free.argtypes = [ctypes.c_void_p]
lib.iso2_certificate_installation_req_free.restype = None

def test_iso20_certificate_installation_res():
    # Create test data based on CertificateInstallationRes-20.xml
    test_data = {
        "SessionID": "1234567890ABCDEF",
        "TimeStamp": "1677687277",
        "ResponseCode": "OK",
        "EVSEProcessing": "Finished",
        "CPSCertificateChain": {
            "Certificate": "MIIBmDCCAQGgAwIBAgIBATAKBggqhkjOPQQDAjAzMRwwGgYDVQQKDBNDUFMgUHJvdmlzaW9uaW5nIENBMRMwEQYDVQQDDApDUFMgU3ViIENBMB4XDTIzMDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowKzEMMAoGA1UECgwDQ1BTMRswGQYDVQQDDBJDUFMgUHJvdmlzaW9uaW5nIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY30s8rpA+KJ+YcgiYtIEJjaOV0xkiCGZXak3JTt6OcIgC3681KIByqcU7Jg/xkBxDv3O9KgP83KH9IrPNldFQaMjMCEwDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAJ6s6R7zzk6WHEQbK8nQ09u3qfPP2xAZu6VPGVYPbXvKAiBqlxhBvW8QOu1J5ZAYtrV7KxHD7zKJtOEfZkY9Qh5y1Q==",
            "SubCertificates": [
                {
                    "Certificate": "MIIBmDCCAQGgAwIBAgIBATAKBggqhkjOPQQDAjAzMRwwGgYDVQQKDBNDUFMgUHJvdmlzaW9uaW5nIENBMRMwEQYDVQQDDApDUFMgUm9vdCBDQTAeFw0yMzAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMCsxDDAKBgNVBAoMA0NQUzEbMBkGA1UEAwwSQ1BTIFByb3Zpc2lvbmluZyBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIFsO8jWd7O3MXfTY5pKVTxmIgC7X9sCo/FF+IkHuOLhC0fzRKzkg925f7wNhd2VkAwXHdA2VGZwcHBb/VQxA+ejIzAhMA4GA1UdDwEB/wQEAwIHgDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCerOke885OlhxEGyvJ0NPbt6nzz9sQGbulTxlWD217ygIgapcYQb1vEDrtSeWQGLa1eysRw+8yibThH2ZGPUIectU="
                }
            ]
        },
        "SignedInstallationData": {
            "Id": "ID2",
            "ContractCertificateChain": {
                "Certificate": "MIIBmDCCAQGgAwIBAgIBATAKBggqhkjOPQQDAjAzMRwwGgYDVQQKDBNDb250cmFjdCBDZXJ0IENBMRMwEQYDVQQDDApDQyBTdWIgQ0EwHhcNMjMwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjArMQwwCgYDVQQKDANDQ0ExGzAZBgNVBAMMEkNvbnRyYWN0IENlcnQgQ2VydDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIFsO8jWd7O3MXfTY5pKVTxmIgC7X9sCo/FF+IkHuOLhC0fzRKzkg925f7wNhd2VkAwXHdA2VGZwcHBb/VQxA+ejIzAhMA4GA1UdDwEB/wQEAwIHgDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCerOke885OlhxEGyvJ0NPbt6nzz9sQGbulTxlWD217ygIgapcYQb1vEDrtSeWQGLa1eysRw+8yibThH2ZGPUIectU=",
                "SubCertificates": [
                    {
                        "Certificate": "MIIBmDCCAQGgAwIBAgIBATAKBggqhkjOPQQDAjAzMRwwGgYDVQQKDBNDb250cmFjdCBDZXJ0IENBMRMwEQYDVQQDDApDQyBSb290IENBMHgXDTIzMDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowKzEMMAoGA1UECgwDQ0NBMRswGQYDVQQDDBJDb250cmFjdCBDZXJ0IENlcnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASBbDvI1neztxF302OaSlU8ZiIAu1/bAqPxRfiJB7ji4QtH80Ss5IPduX+8DYXdlZAMFx3QNlRmcHBwW/1UMQPnoyMwITAOBgNVHQ8BAf8EBAMCB4AwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAnqzpHvPOTpYcRBsrydDT27ep88/bEBm7pU8ZVg9te8oCIGqXGEG9bxA67UnlkBi2tXsrEcPvMom04R9mRj1CHnLV"
                    },
                    {
                        "Certificate": "MIIBmDCCAQGgAwIBAgIBATAKBggqhkjOPQQDAjAzMRwwGgYDVQQKDBNDb250cmFjdCBDZXJ0IENBMRMwEQYDVQQDDApDQyBSb290IENBMHgXDTIzMDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowKzEMMAoGA1UECgwDQ0NBMRswGQYDVQQDDBJDb250cmFjdCBDZXJ0IFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASBbDvI1neztxF302OaSlU8ZiIAu1/bAqPxRfiJB7ji4QtH80Ss5IPduX+8DYXdlZAMFx3QNlRmcHBwW/1UMQPnoyMwITAOBgNVHQ8BAf8EBAMCB4AwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAnqzpHvPOTpYcRBsrydDT27ep88/bEBm7pU8ZVg9te8oCIGqXGEG9bxA67UnlkBi2tXsrEcPvMom04R9mRj1CHnLV"
                    }
                ]
            },
            "ECDHCurve": "SECP521",
            "DHPublicKey": "MIGlAgEAMIGHAoGBAP//////////yQ/aoiFowjTExmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR7ORbPcIAfLihY78FMfPjAiUAjAjfN4Xm3KOWoWaF2+/TZs0T/OZ8ufJQ",
            "SECP521_EncryptedPrivateKey": "MIHPAgECMIGHAoGBAP//////////yQ/aoiFowjTExmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR7ORbPcIAfLihY78FMfPjAiUAjAjfN4Xm3KOWoWaF"
        },
        "RemainingContractCertificateChains": 2
    }

    # Convert to JSON string
    json_str = json.dumps(test_data).encode('utf-8')

    # Encode JSON to EXI
    exi_buffer = ctypes.POINTER(ctypes.c_uint8)()
    exi_buffer_ptr = ctypes.pointer(exi_buffer)
    exi_size = ctypes.c_size_t()
    result = lib.iso20_certificate_installation_res_encode_json_to_exi(json_str, exi_buffer_ptr, ctypes.byref(exi_size))
    if result != 0:
        print(f"Error encoding JSON to EXI: {result}")
        return False

    # Decode EXI back to JSON
    json_str_out = ctypes.c_char_p()
    result = lib.iso20_certificate_installation_res_decode_exi_to_json(exi_buffer, exi_size, ctypes.byref(json_str_out))
    if result != 0:
        print(f"Error decoding EXI to JSON: {result}")
        lib.iso2_certificate_installation_req_free(exi_buffer)
        return False

    # Parse the decoded JSON
    decoded_data = json.loads(json_str_out.value.decode('utf-8'))

    # Compare the original and decoded data
    if decoded_data == test_data:
        print("Test passed: JSON -> EXI -> JSON round trip successful")
        print("Original:", test_data)
        print("Decoded:", decoded_data)
        success = True
    else:
        print("Test failed: Decoded data does not match original")
        print("Original:", test_data)
        print("Decoded:", decoded_data)
        success = False

    # Cleanup
    lib.iso2_certificate_installation_req_free(exi_buffer)
    lib.iso2_certificate_installation_req_free(json_str_out)

    return success

if __name__ == "__main__":
    if test_iso20_certificate_installation_res():
        sys.exit(0)
    else:
        sys.exit(1) 