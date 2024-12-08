from tink import aead, tink_config
import tink
from tink import cleartext_keyset_handle
import json
import os
from io import StringIO

class KeyManagementService:
    def __init__(self, key_file="master_key.json"):
        self.key_file = key_file
        self._init_tink()
        self.aead_primitive = self._load_or_create_key()

    def _init_tink(self):
        try:
            tink_config.register()
            aead.register()
        except Exception as e:
            print(f"Error initializing Tink: {e}")
            raise

    def _load_or_create_key(self):
        try:
            if os.path.exists(self.key_file):
                try:
                    with open(self.key_file, 'r') as f:
                        reader = tink.JsonKeysetReader(f.read())
                        keyset_handle = cleartext_keyset_handle.read(reader)
                except Exception as e:
                    print(f"Error reading existing key file: {e}")
                    print("Generating new key file...")
                    if os.path.exists(self.key_file):
                        os.remove(self.key_file)
                    return self._create_new_key()
            else:
                return self._create_new_key()
            
            return keyset_handle.primitive(aead.Aead)
            
        except Exception as e:
            print(f"Error in key management: {e}")
            raise

    def _create_new_key(self):
        try:
            key_template = aead.aead_key_templates.AES256_GCM
            keyset_handle = tink.new_keyset_handle(key_template)
            
            # Ensure the directory exists
            os.makedirs(os.path.dirname(self.key_file) or '.', exist_ok=True)
            
            # Create string buffer for the keyset
            output = StringIO()
            writer = tink.JsonKeysetWriter(output)
            
            # Write to the buffer using cleartext_keyset_handle
            cleartext_keyset_handle.write(writer, keyset_handle)
            
            # Save the keyset
            with open(self.key_file, 'w') as f:
                f.write(output.getvalue())
            
            return keyset_handle.primitive(aead.Aead)
        except Exception as e:
            print(f"Error creating new key: {e}")
            raise

    def encrypt(self, data: bytes, associated_data: bytes = b'') -> bytes:
        try:
            return self.aead_primitive.encrypt(data, associated_data)
        except Exception as e:
            print(f"Encryption error: {e}")
            raise

    def decrypt(self, encrypted_data: bytes, associated_data: bytes = b'') -> bytes:
        try:
            return self.aead_primitive.decrypt(encrypted_data, associated_data)
        except Exception as e:
            print(f"Decryption error: {e}")
            raise