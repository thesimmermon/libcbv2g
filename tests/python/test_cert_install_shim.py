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
lib.iso2_cert_install_encode_json_to_exi.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)), ctypes.POINTER(ctypes.c_size_t)]
lib.iso2_cert_install_encode_json_to_exi.restype = ctypes.c_int

lib.iso2_cert_install_decode_exi_to_json.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_char_p)]
lib.iso2_cert_install_decode_exi_to_json.restype = ctypes.c_int

lib.iso2_cert_install_free.argtypes = [ctypes.c_void_p]
lib.iso2_cert_install_free.restype = None

def test_cert_install_shim():
    # Create a sample certificate installation request
    sample_cert = b"-----BEGIN CERTIFICATE-----\nMIIBazCCAROgAwIBAgIUJ9WcC8GmKJhBZk9/CKBO/3cIg5cwDQYJKoZIhvcNAQEL\nBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMDAxMDEwMDAwMDBaFw0yMTAx\nMDEwMDAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw\nHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwXDANBgkqhkiG9w0BAQEF\nAANLADBIAkEA6e4N1X4Kp6GK3YjZwQWCnWj8usnsqGjciB1HavixcDlYa/hI6xw0\nOzmVRluMk6BjE45RZgBfajQ3bG1D2QIDAQABo1MwUTAdBgNVHQ4EFgQU8jXbNATs\nZ6A1z4GIa7YDL1Qntt8wHwYDVR0jBBgwFoAU8jXbNATsZ6A1z4GIa7YDL1Qntt8w\nDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAANBAE1m9p5n8N5uXLFfDt03\nXQYRXrQUzO3c9t3DjYwRJxmBtIZd5tCt53UvnKeHRXLZ5BpDmBZp6MKYz3D8VcUJ\nNnQ=\n-----END CERTIFICATE-----"

    # Create test data
    test_data = {
        "SessionID": "12345678",
        "Id": "CertificateInstallationReq",
        "OEMProvisioningCert": base64.b64encode(sample_cert).decode('utf-8'),
        "ListOfRootCertificateIDs": [
            {
                "X509IssuerName": "CN=Test CA,O=Test Org,C=US",
                "X509SerialNumber": 1234567890
            },
            {
                "X509IssuerName": "CN=Test CA 2,O=Test Org 2,C=US",
                "X509SerialNumber": 9876543210
            }
        ]
    }

    # Convert to JSON string
    json_str = json.dumps(test_data).encode('utf-8')

    # Encode JSON to EXI
    exi_buffer = ctypes.POINTER(ctypes.c_uint8)()
    exi_buffer_ptr = ctypes.pointer(exi_buffer)
    exi_size = ctypes.c_size_t()
    result = lib.iso2_cert_install_encode_json_to_exi(json_str, exi_buffer_ptr, ctypes.byref(exi_size))
    if result != 0:
        print(f"Error encoding JSON to EXI: {result}")
        return False

    # Decode EXI back to JSON
    json_str_out = ctypes.c_char_p()
    result = lib.iso2_cert_install_decode_exi_to_json(exi_buffer, exi_size, ctypes.byref(json_str_out))
    if result != 0:
        print(f"Error decoding EXI to JSON: {result}")
        lib.iso2_cert_install_free(exi_buffer)
        return False

    # Parse the decoded JSON
    decoded_data = json.loads(json_str_out.value.decode('utf-8'))

    # Compare the original and decoded data
    if decoded_data == test_data:
        print("Test passed: JSON -> EXI -> JSON round trip successful")
        success = True
    else:
        print("Test failed: Decoded data does not match original")
        print("Original:", test_data)
        print("Decoded:", decoded_data)
        success = False

    # Cleanup
    lib.iso2_cert_install_free(exi_buffer)
    lib.iso2_cert_install_free(json_str_out)

    return success

if __name__ == "__main__":
    if test_cert_install_shim():
        sys.exit(0)
    else:
        sys.exit(1) 