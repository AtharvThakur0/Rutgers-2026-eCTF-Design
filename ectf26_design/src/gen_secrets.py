"""
Author: Ben Janis
Date: 2026

This source file is part of an example system for MITRE's 2026 Embedded CTF
(eCTF). This code is being provided only for educational purposes for the 2026 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2026 The MITRE Corporation
"""

import os
import secrets
import argparse
import struct
import json
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization 
from loguru import logger


def gen_secrets(groups: list[int]) -> bytes:
    """Generate the contents secrets file

    This will be passed to the Encoder, ectf26_design.gen_secrets,
    and the build process of the firmware

    NOTE: you should NOT write to secrets files within this function.
    All generated secrets must be contained in the returned bytes
    object.

    ===== NOT USED ======
    :param groups: List of permission groups that will be valid in this
        deployment. 

    :returns: Contents of the secrets file
    """
    
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()


    # save the ECC private key to host
    # in docker, make sure to save to persisitent volume
    with open("host_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() # Or use a password
        ))

    serialized_public = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    aes_key = secrets.token_bytes(32)

    # binary concatentaion, split point for ECC256 is at 65
    # 0-64: serialized_public 65-97: aes_key
    # group id is 32 bits 

    # groups to bytes
    group_list= [] 

    for group in groups:
        group_list.append(struct.pack('>h', group))

    group_bytes = b"".join(group_list)

    output = serialized_public + aes_key + group_bytes 

    return output








def parse_args():
    """Define and parse the command line arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "groups",
        nargs="+",
        type=lambda x: int(x, 0),
        help="Supported group IDs",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    secrets = gen_secrets(args.groups)

    # Print the generated secrets for your own debugging
    # Attackers will NOT have access to the output of this, but feel free to remove

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()

