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
    lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), '../../build_linux_arm64/lib/cbv2g/libcbv2g_json_shim.so'))

# Define function signatures
lib.iso2_certificate_installation_req_encode_json_to_exi.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)), ctypes.POINTER(ctypes.c_size_t)]
lib.iso2_certificate_installation_req_encode_json_to_exi.restype = ctypes.c_int

lib.iso2_certificate_installation_req_decode_exi_to_json.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_char_p)]
lib.iso2_certificate_installation_req_decode_exi_to_json.restype = ctypes.c_int

lib.iso2_certificate_installation_req_free.argtypes = [ctypes.c_void_p]
lib.iso2_certificate_installation_req_free.restype = None

def test_iso2_certificate_installation_req():
    # Create test data based on CertificateInstallationReq-2.xml
    test_data = {
        "SessionID": "1234567890ABCDEF",  # 16-character hex string

        "Id": "ID1",
        "OEMProvisioningCert": "MIIBmDCCAQGgAwIBAgIBATAKBggqhkjOPQQDAjAzMRwwGgYDVQQKDBNPRU0gUHJvdmlzaW9uaW5nIENBMRMwEQYDVQQDDApPRU0gU3ViIENBMB4XDTIzMDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowKzEMMAoGA1UECgwDT0VNMRswGQYDVQQDDBJPRU0gUHJvdmlzaW9uaW5nIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY30s8rpA+KJ+YcgiYtIEJjaOV0xkiCGZXak3JTt6OcIgC3681KIByqcU7Jg/xkBxDv3O9KgP83KH9IrPNldFQaMjMCEwDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAJ6s6R7zzk6WHEQbK8nQ09u3qfPP2xAZu6VPGVYPbXvKAiBqlxhBvW8QOu1J5ZAYtrV7KxHD7zKJtOEfZkY9Qh5y1Q==",
        "ListOfRootCertificateIDs": [
            {
                "X509IssuerName": "CN=V2G Root CA, O=V2G PKI",
                "X509SerialNumber": 1234567890
            }
        ]
    }

    # Convert to JSON string
    json_str = json.dumps(test_data).encode('utf-8')

    # Encode JSON to EXI
    exi_buffer = ctypes.POINTER(ctypes.c_uint8)()
    exi_buffer_ptr = ctypes.pointer(exi_buffer)
    exi_size = ctypes.c_size_t()
    result = lib.iso2_certificate_installation_req_encode_json_to_exi(json_str, exi_buffer_ptr, ctypes.byref(exi_size))
    if result != 0:
        print(f"Error encoding JSON to EXI: {result}")
        return False

    # Decode EXI back to JSON
    json_str_out = ctypes.c_char_p()
    result = lib.iso2_certificate_installation_req_decode_exi_to_json(exi_buffer, exi_size, ctypes.byref(json_str_out))
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
    if test_iso2_certificate_installation_req():
        sys.exit(0)
    else:
        sys.exit(1) 