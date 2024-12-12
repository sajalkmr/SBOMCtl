import copy
from lib4sbom.parser import SBOMParser
import json
import argparse

from petra.lib.models.tree_ops import build_sbom_tree, verify_sameness
from petra.lib.models import MerkleVisitor, EncryptVisitor, DecryptVisitor
from petra.lib.models.parallel_encrypt import ParallelEncryptVisitor, ParallelDecryptVisitor
from petra.lib.util.config import Config

import cpabe

argparser = argparse.ArgumentParser()
# TODO: add args for the config
# TODO: handle defaults etc
argparser.add_argument("-o", "--original-file", type=str, required=True, help="the file to which to write the original SBOM tree")
argparser.add_argument("-r", "--redacted-file", type=str, required=True, help="the file to which to write the redacted SBOM tree")
argparser.add_argument("-d", "--decrypted-file", type=str, required=True, help="the file to which to write the decrypted SBOM tree")
argparser.add_argument("--no-parallel", action='store_true', help="flag indicating whether to parallelize SBOM tree encryption/decryption")
args = argparser.parse_args()

# read in the IP policy config
conf = Config("./config/ip-policy.conf")

sbom_file = conf.get_sbom_files()[0]

pk, mk = cpabe.cpabe_setup()
sk = cpabe.cpabe_keygen(pk, mk, conf.get_cpabe_group('ip-group'))

# Parse SPDX data into a Document object
SBOM_parser = SBOMParser()   
SBOM_parser.parse_file(sbom_file) 

# build sbom tree
sbom=SBOM_parser.sbom
sbom_tree = build_sbom_tree(sbom, conf.get_cpabe_policy('ip-policy'))

print("done constructing tree")

with open(args.original_file, "w+") as f:
        f.write(json.dumps(sbom_tree.to_dict(), indent=4)+'\n')

print("pre-redaction plaintext hash: %s" % sbom_tree.plaintext_hash.hex())

# encrypt node data
if args.no_parallel:
        encrypt_visitor = EncryptVisitor(pk)
        sbom_tree.accept(encrypt_visitor)
else:
        # we default to the parallel encryption
        encrypt_visitor = ParallelEncryptVisitor(pk)
        sbom_tree.accept(encrypt_visitor)
        encrypt_visitor.finalize()

print("done encrypting")

# hash tree nodes
merkle_visitor = MerkleVisitor()
merkle_root_hash = sbom_tree.accept(merkle_visitor)

print("done hashing tree")

print("redacted plaintext hash: %s" % sbom_tree.plaintext_hash.hex())

print("saving redacted tree to disk")

with open(args.redacted_file, "w+") as f:
        f.write(json.dumps(sbom_tree.to_dict(), indent=4)+'\n')

# decrypt node data
decrypted_tree = copy.deepcopy(sbom_tree)
if args.no_parallel:
        decrypt_visitor = DecryptVisitor(sk)
        decrypted_tree.accept(decrypt_visitor)
else:
        # we default to the parallel decryption
        decrypt_visitor = ParallelDecryptVisitor(sk)
        decrypted_tree.accept(decrypt_visitor)
        decrypt_visitor.finalize()

print("done decrypting")

print("decrypted plaintext hash: %s" % decrypted_tree.plaintext_hash.hex())

print("saving decrypted tree to disk")

with open(args.decrypted_file, "w+") as f:
        f.write(json.dumps(decrypted_tree.to_dict(), indent=4)+'\n')

# verify decrypted tree is consistent 
# with original sbom tree
passed = verify_sameness(sbom_tree, decrypted_tree)

print("full tree sameness verification passed? %s" % str(passed))

import unittest
import time
from cpabe import cpabe_setup, cpabe_keygen, cpabe_encrypt, cpabe_decrypt

class TestCPABE(unittest.TestCase):
    def setUp(self):
        # Setup CP-ABE environment before each test
        self.pk, self.mk = cpabe_setup()
        
    def test_basic_key_generation(self):
        """Test key generation with basic attribute set"""
        attributes = ["role::admin", "department::engineering"]
        try:
            sk = cpabe_keygen(self.mk, attributes)
            self.assertIsNotNone(sk)
        except Exception as e:
            self.fail(f"Key generation failed: {str(e)}")

    def test_multiple_attribute_sets(self):
        """Test key generation with different attribute combinations"""
        attribute_sets = [
            ["role::user", "department::hr"],
            ["role::admin", "department::engineering", "level::senior"],
            ["role::manager", "department::sales", "region::west"]
        ]
        for attrs in attribute_sets:
            with self.subTest(attributes=attrs):
                sk = cpabe_keygen(self.mk, attrs)
                self.assertIsNotNone(sk)

    def test_encryption_decryption(self):
        """Test basic encryption and decryption"""
        attributes = ["role::admin", "department::engineering"]
        sk = cpabe_keygen(self.mk, attributes)
        message = b"Hello, CP-ABE!"
        policy = '(role::admin AND department::engineering)'
        
        # Test encryption
        ct = cpabe_encrypt(self.pk, policy, message)
        self.assertIsNotNone(ct)
        
        # Test decryption
        decrypted = cpabe_decrypt(sk, ct)
        self.assertEqual(message, decrypted)

    def test_invalid_policy(self):
        """Test error handling for invalid policies"""
        attributes = ["role::admin"]
        sk = cpabe_keygen(self.mk, attributes)
        message = b"Test message"
        invalid_policies = [
            "(invalid::policy)",  # Unknown attribute
            "AND role::admin",    # Malformed policy
            ""                    # Empty policy
        ]
        
        for policy in invalid_policies:
            with self.subTest(policy=policy):
                with self.assertRaises(Exception):
                    cpabe_encrypt(self.pk, policy, message)

    def test_insufficient_attributes(self):
        """Test decryption with insufficient attributes"""
        sk = cpabe_keygen(self.mk, ["role::user"])
        message = b"Secret message"
        policy = '(role::admin AND department::engineering)'
        
        ct = cpabe_encrypt(self.pk, policy, message)
        with self.assertRaises(Exception):
            cpabe_decrypt(sk, ct)

    def test_performance_benchmark(self):
        """Benchmark encryption/decryption performance with large data"""
        large_message = b"X" * 1000000  # 1MB of data
        attributes = ["role::admin", "department::engineering"]
        sk = cpabe_keygen(self.mk, attributes)
        policy = '(role::admin AND department::engineering)'
        
        # Measure encryption time
        start_time = time.time()
        ct = cpabe_encrypt(self.pk, policy, large_message)
        encryption_time = time.time() - start_time
        
        # Measure decryption time
        start_time = time.time()
        decrypted = cpabe_decrypt(sk, ct)
        decryption_time = time.time() - start_time
        
        print(f"\nPerformance Benchmark Results:")
        print(f"Encryption time for 1MB: {encryption_time:.2f} seconds")
        print(f"Decryption time for 1MB: {decryption_time:.2f} seconds")
        
        self.assertEqual(large_message, decrypted)

if __name__ == '__main__':
    unittest.main()
