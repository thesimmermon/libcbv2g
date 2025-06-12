#!/usr/bin/env python3

import ctypes
import json
import os
import sys
import base64
from dataclasses import dataclass, asdict
from typing import List, Optional

class DataclassJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, '__dict__'):
            return asdict(obj)
        return super().default(obj)

@dataclass
class RootCertificateID:
    X509IssuerName: str
    X509SerialNumber: int

@dataclass
class CertificateInstallationReq:
    SessionID: str
    Id: str
    OEMProvisioningCert: str
    ListOfRootCertificateIDs: List[RootCertificateID]

@dataclass
class SubCertificate:
    Certificate: str

@dataclass
class CertificateChain:
    Certificate: str
    SubCertificates: List[SubCertificate]

@dataclass
class EncryptedPrivateKey:
    Id: str
    Value: str

@dataclass
class CertificateInstallationRes:
    SessionID: str
    ResponseCode: str
    SAProvisioningCertificateChain: CertificateChain
    ContractSignatureCertChain: CertificateChain
    ContractSignatureEncryptedPrivateKey: EncryptedPrivateKey
    DHpublickey: EncryptedPrivateKey
    eMAID: EncryptedPrivateKey

class Iso2ExiMessage:
    def __init__(self, library_path: Optional[str] = None):
        if library_path is None:
            if sys.platform == 'win32':
                library_path = os.path.join(os.path.dirname(__file__), 'bin/cbv2g_json_shim.dll')
            else:
                library_path = os.path.join(os.path.dirname(__file__), 'bin/libcbv2g_json_shim.so')

        self.lib = ctypes.CDLL(library_path)

        # Define function signatures for request
        self.lib.iso2_certificate_installation_req_encode_json_to_exi.argtypes = [
            ctypes.c_char_p, 
            ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)), 
            ctypes.POINTER(ctypes.c_size_t)
        ]
        self.lib.iso2_certificate_installation_req_encode_json_to_exi.restype = ctypes.c_int

        self.lib.iso2_certificate_installation_req_decode_exi_to_json.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), 
            ctypes.c_size_t, 
            ctypes.POINTER(ctypes.c_char_p)
        ]
        self.lib.iso2_certificate_installation_req_decode_exi_to_json.restype = ctypes.c_int

        # Define function signatures for response
        self.lib.iso2_certificate_installation_res_encode_json_to_exi.argtypes = [
            ctypes.c_char_p, 
            ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)), 
            ctypes.POINTER(ctypes.c_size_t)
        ]
        self.lib.iso2_certificate_installation_res_encode_json_to_exi.restype = ctypes.c_int

        self.lib.iso2_certificate_installation_res_decode_exi_to_json.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), 
            ctypes.c_size_t, 
            ctypes.POINTER(ctypes.c_char_p)
        ]
        self.lib.iso2_certificate_installation_res_decode_exi_to_json.restype = ctypes.c_int

        # Define free function signatures
        self.lib.iso2_certificate_installation_req_free.argtypes = [ctypes.c_void_p]
        self.lib.iso2_certificate_installation_req_free.restype = None

    def _encode_to_exi(self, json_data: dict, encode_func, free_func) -> bytes:
        json_str = json.dumps(json_data, cls=DataclassJSONEncoder).encode('utf-8')
        exi_buffer = ctypes.POINTER(ctypes.c_uint8)()
        exi_buffer_ptr = ctypes.pointer(exi_buffer)
        exi_size = ctypes.c_size_t()

        result = encode_func(json_str, exi_buffer_ptr, ctypes.byref(exi_size))
        if result != 0:
            raise Exception(f"Error encoding to EXI: {result}")

        try:
            # Convert the buffer to bytes
            exi_bytes = bytes(exi_buffer[:exi_size.value])
            return exi_bytes
        finally:
            free_func(exi_buffer)

    def _decode_from_exi(self, exi_bytes: bytes, decode_func, free_func) -> dict:
        exi_buffer = (ctypes.c_uint8 * len(exi_bytes))(*exi_bytes)
        json_str_out = ctypes.c_char_p()

        result = decode_func(exi_buffer, len(exi_bytes), ctypes.byref(json_str_out))
        if result != 0:
            raise Exception(f"Error decoding from EXI: {result}")

        try:
            decoded_json = json.loads(json_str_out.value.decode('utf-8'))
            return decoded_json
        finally:
            free_func(json_str_out)

    def EncodeCertReq(self, request: CertificateInstallationReq) -> bytes:
        """Encode a CertificateInstallationReq object to EXI bytes"""
        return self._encode_to_exi(
            request,
            self.lib.iso2_certificate_installation_req_encode_json_to_exi,
            self.lib.iso2_certificate_installation_req_free
        )

    def EncodeCertRes(self, response: CertificateInstallationRes) -> bytes:
        """Encode a CertificateInstallationRes object to EXI bytes"""
        return self._encode_to_exi(
            response,
            self.lib.iso2_certificate_installation_res_encode_json_to_exi,
            self.lib.iso2_certificate_installation_req_free
        )

    def DecodeCertReq(self, base64_exi: str) -> CertificateInstallationReq:
        """Decode a base64 encoded EXI string to a CertificateInstallationReq object"""
        exi_bytes = base64.b64decode(base64_exi)
        decoded_dict = self._decode_from_exi(
            exi_bytes,
            self.lib.iso2_certificate_installation_req_decode_exi_to_json,
            self.lib.iso2_certificate_installation_req_free
        )
        return CertificateInstallationReq(**decoded_dict)

    def DecodeCertRes(self, base64_exi: str) -> CertificateInstallationRes:
        """Decode a base64 encoded EXI string to a CertificateInstallationRes object"""
        exi_bytes = base64.b64decode(base64_exi)
        decoded_dict = self._decode_from_exi(
            exi_bytes,
            self.lib.iso2_certificate_installation_res_decode_exi_to_json,
            self.lib.iso2_certificate_installation_req_free
        )
        return CertificateInstallationRes(**decoded_dict) 