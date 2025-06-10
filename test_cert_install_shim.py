#!/usr/bin/env python3

import ctypes
import json
import os
import sys
import base64

# Load the shared library
if sys.platform == 'win32':
    dll_path = os.path.join(os.path.dirname(__file__), 'build_win_arm64/bin/Release/cbv2g_json_shim.dll')
    if not os.path.exists(dll_path):
        print(f"Error: Could not find DLL at {dll_path}")
        sys.exit(1)
    try:
        lib = ctypes.CDLL(dll_path)
    except Exception as e:
        print(f"Error loading DLL: {e}")
        sys.exit(1)
else:
    lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'build/lib/libcbv2g_json_shim.so'))

# Define function signatures
lib.iso2_cert_install_encode_json_to_exi.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
    ctypes.POINTER(ctypes.c_size_t)
]
lib.iso2_cert_install_encode_json_to_exi.restype = ctypes.c_int

lib.iso2_cert_install_decode_exi_to_json.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_char_p)
]
lib.iso2_cert_install_decode_exi_to_json.restype = ctypes.c_int

lib.iso2_cert_install_free.argtypes = [ctypes.c_void_p]
lib.iso2_cert_install_free.restype = None

def test_cert_install():
    # Test data
    test_data = {
        "SessionID": "12345",
        "Id": "CERT_INSTALL_001",
        "OEMProvisioningCert": base64.b64encode(b"test_certificate_data").decode('utf-8'),
        "ListOfRootCertificateIDs": [
            {
                "X509IssuerName": "CN=Test CA",
                "X509SerialNumber": 123456
            }
        ]
    }

    # Convert to JSON string
    json_str = json.dumps(test_data).encode('utf-8')

    # Encode JSON to EXI
    exi_buffer = ctypes.POINTER(ctypes.c_uint8)()
    exi_size = ctypes.c_size_t()
    
    result = lib.iso2_cert_install_encode_json_to_exi(
        json_str,
        ctypes.byref(exi_buffer),
        ctypes.byref(exi_size)
    )
    
    if result != 0:
        print(f"Encode failed with error code: {result}")
        return

    print(f"Encoded EXI size: {exi_size.value} bytes")

    # Decode EXI back to JSON
    json_output = ctypes.c_char_p()
    result = lib.iso2_cert_install_decode_exi_to_json(
        exi_buffer,
        exi_size,
        ctypes.byref(json_output)
    )

    if result != 0:
        print(f"Decode failed with error code: {result}")
        lib.iso2_cert_install_free(exi_buffer)
        return

    # Convert output to Python string
    decoded_json = json_output.value.decode('utf-8')
    decoded_data = json.loads(decoded_json)

    # Compare original and decoded data
    print("\nOriginal data:")
    print(json.dumps(test_data, indent=2))
    print("\nDecoded data:")
    print(json.dumps(decoded_data, indent=2))

    # Cleanup
    lib.iso2_cert_install_free(exi_buffer)
    lib.iso2_cert_install_free(json_output)

if __name__ == "__main__":
    test_cert_install() 