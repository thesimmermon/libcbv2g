#!/usr/bin/env python3

import ctypes
import json
import os
import sys
import base64
import argparse

# Load the shared library
if sys.platform == 'win32':
    lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), '../../build_win_arm64/bin/Release/cbv2g_json_shim.dll'))
else:
    lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), '../../build/lib/libcbv2g_json_shim.so'))

# Define function signatures for request
lib.iso2_certificate_installation_req_encode_json_to_exi.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)), ctypes.POINTER(ctypes.c_size_t)]
lib.iso2_certificate_installation_req_encode_json_to_exi.restype = ctypes.c_int

# Define function signatures for response
lib.iso2_certificate_installation_res_encode_json_to_exi.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)), ctypes.POINTER(ctypes.c_size_t)]
lib.iso2_certificate_installation_res_encode_json_to_exi.restype = ctypes.c_int

lib.iso2_certificate_installation_req_free.argtypes = [ctypes.c_void_p]
lib.iso2_certificate_installation_req_free.restype = None

def print_hex_dump(data, length=16):
    """Print a hex dump of the data"""
    print("\nFirst {} bytes of encoded data:".format(length))
    print("Offset  Hex dump                                         ASCII")
    print("------  ----------------------------------------------  ----------------")
    
    for i in range(0, min(length, len(data))):
        if i % 16 == 0:
            if i > 0:
                print()
            print(f"{i:06x}  ", end='')
        
        print(f"{data[i]:02x} ", end='')
        
        if i % 16 == 15:
            print("  ", end='')
            for j in range(i-15, i+1):
                c = data[j]
                print(chr(c) if 32 <= c <= 126 else '.', end='')
    
    # Print any remaining ASCII
    if len(data) % 16 != 0:
        print("  " * (16 - (len(data) % 16)), end='')
        print("  ", end='')
        for j in range((len(data) // 16) * 16, len(data)):
            c = data[j]
            print(chr(c) if 32 <= c <= 126 else '.', end='')
    
    print("\n")

def encode_json_to_exi(json_str, is_request=True):
    """Encode JSON to EXI data"""
    # Allocate output buffer
    exi_buffer = ctypes.POINTER(ctypes.c_uint8)()
    exi_size = ctypes.c_size_t(0)
    
    # Convert JSON string to bytes
    json_bytes = json_str.encode('utf-8')
    
    # Call the appropriate encode function
    if is_request:
        result = lib.iso2_certificate_installation_req_encode_json_to_exi(
            json_bytes,
            ctypes.byref(exi_buffer),
            ctypes.byref(exi_size)
        )
    else:
        result = lib.iso2_certificate_installation_res_encode_json_to_exi(
            json_bytes,
            ctypes.byref(exi_buffer),
            ctypes.byref(exi_size)
        )
    
    if result != 0:
        print(f"Error encoding JSON to EXI: {result}")
        return None
        
    try:
        # Convert to Python bytes
        exi_data = bytes(exi_buffer[:exi_size.value])
        return exi_data
    finally:
        # Free the allocated memory
        lib.iso2_certificate_installation_req_free(exi_buffer)

def main():
    parser = argparse.ArgumentParser(description='Encode JSON to base64 EXI data')
    parser.add_argument('--type', choices=['req', 'res'], default='res',
                      help='Type of message to encode (req=request, res=response)')
    parser.add_argument('input_file', help='File containing JSON data')
    parser.add_argument('--output', '-o', help='Output file for base64 EXI data (default: print to stdout)')
    parser.add_argument('--debug', '-d', action='store_true', help='Show debug information')
    
    args = parser.parse_args()
    
    try:
        # Read JSON from file
        with open(args.input_file, 'r') as f:
            json_str = f.read()
        
        if args.debug:
            print(f"Input JSON length: {len(json_str)} characters")
            print(f"First 100 characters of JSON: {json_str[:100]}...")
        
        # Encode JSON to EXI
        exi_data = encode_json_to_exi(json_str, args.type == 'req')
        
        if exi_data:
            if args.debug:
                print(f"EXI data length: {len(exi_data)} bytes")
                print_hex_dump(exi_data)
            
            # Convert to base64
            base64_data = base64.b64encode(exi_data).decode('ascii')
            
            # Output base64 data
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(base64_data)
            else:
                print(base64_data)
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 