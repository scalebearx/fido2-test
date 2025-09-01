#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FIDO2 Registration and Authentication Flow

This script demonstrates a complete FIDO2 WebAuthn flow including:
1. Registration (Make Credential)
2. Authentication (Get Assertion)

All important interactions are logged to fido2_flow.log for observation.
"""

import logging
import base64
import os
from datetime import datetime

from fido2.webauthn import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialType,
    PublicKeyCredentialParameters,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement
)
from ctap_keyring_device.ctap_keyring_device import CtapKeyringDevice
from fido2.client import Fido2Client
from fido2 import cose


def setup_logging():
    """Setup logging configuration to write to fido2_flow.log"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('fido2_flow.log', mode='w', encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)


def registration_flow(logger):
    """Execute FIDO2 Registration (Make Credential) Flow"""
    logger.info("=== Starting FIDO2 Registration Flow ===")
    
    # Device setup
    logger.info("Setting up CTAP device...")
    devices = CtapKeyringDevice.list_devices()
    if not devices:
        logger.error("No CTAP devices available")
        return None
    
    device = devices[0]
    logger.info(f"Using device: {device.__class__.__name__}")
    
    origin = 'https://rp.example.com'
    client = Fido2Client(device, origin)
    logger.info(f"FIDO2 Client initialized with origin: {origin}")
    
    # Credential creation parameters
    rp = {
        'id': 'example.com',
        'name': 'Example RP',
        'icon': 'https://example.com/icon.png'
    }
    
    user = {
        'id': 'user@example.com',
        'name': 'Example User',
        'displayName': 'Example User',
        'icon': 'https://example.com/user.png'
    }
    
    challenge = os.urandom(32)  # Generate random challenge
    timeout_ms = 30000
    
    logger.info(f"Registration parameters:")
    logger.info(f"  RP ID: {rp['id']}")
    logger.info(f"  RP Name: {rp['name']}")
    logger.info(f"  User ID: {user['id']}")
    logger.info(f"  User Name: {user['name']}")
    logger.info(f"  Challenge: {base64.b64encode(challenge).decode()}")
    logger.info(f"  Timeout: {timeout_ms}ms")
    
    # Supported algorithms
    pub_key_cred_params = [
        PublicKeyCredentialParameters(
            PublicKeyCredentialType.PUBLIC_KEY, 
            cose.ES256.ALGORITHM
        )
    ]
    logger.info(f"Supported algorithms: {[param.alg for param in pub_key_cred_params]}")
    
    # Create credential request
    options = PublicKeyCredentialCreationOptions(
        rp, user, challenge, pub_key_cred_params, timeout=timeout_ms
    )
    
    logger.info("Executing make_credential...")
    try:
        # Execute the make credential flow
        response = client.make_credential(options)
        
        # Extract credential ID from the response
        credential_id = response.attestation_object.auth_data.credential_data.credential_id
        
        logger.info("Registration successful!")
        logger.info(f"Credential ID: {base64.b64encode(credential_id).decode()}")
        logger.info(f"Client Data: {response.client_data}")
        logger.info(f"Attestation Format: {response.attestation_object.fmt}")
        logger.info(f"AAGUID: {response.attestation_object.auth_data.credential_data.aaguid}")
        
        return {
            'credential_id': credential_id,
            'rp_id': rp['id'],
            'user_id': user['id'],
            'challenge': challenge,
            'response': response
        }
        
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        return None


def authentication_flow(logger, registration_data):
    """Execute FIDO2 Authentication (Get Assertion) Flow"""
    logger.info("=== Starting FIDO2 Authentication Flow ===")
    
    if not registration_data:
        logger.error("No registration data available for authentication")
        return False
    
    # Device setup (same as registration)
    device = CtapKeyringDevice.list_devices()[0]
    origin = 'https://rp.example.com'
    client = Fido2Client(device, origin)
    logger.info(f"FIDO2 Client initialized for authentication")
    
    # Authentication parameters
    challenge = os.urandom(32)  # Generate new challenge for authentication
    rp_id = registration_data['rp_id']
    credential_id = registration_data['credential_id']
    timeout_ms = 30000
    
    logger.info(f"Authentication parameters:")
    logger.info(f"  RP ID: {rp_id}")
    logger.info(f"  Challenge: {base64.b64encode(challenge).decode()}")
    logger.info(f"  Credential ID: {base64.b64encode(credential_id).decode()}")
    logger.info(f"  Timeout: {timeout_ms}ms")
    
    # Allow list with existing credentials
    allow_list = [
        PublicKeyCredentialDescriptor(
            PublicKeyCredentialType.PUBLIC_KEY,
            credential_id
        )
    ]
    logger.info(f"Allow list contains {len(allow_list)} credential(s)")
    
    # Create assertion request
    options = PublicKeyCredentialRequestOptions(
        challenge=challenge,
        rp_id=rp_id,
        allow_credentials=allow_list,
        timeout=timeout_ms,
        user_verification=UserVerificationRequirement.PREFERRED
    )
    
    logger.info("Executing get_assertion...")
    try:
        # Execute the get assertion flow
        response = client.get_assertion(options)
        
        logger.info("Authentication successful!")
        logger.info(f"Client Data: {response._client_data}")
        logger.info(f"Number of assertions: {len(response.get_assertions())}")
        
        # Log assertion details
        assertions = response.get_assertions()
        for i, assertion in enumerate(assertions):
            logger.info(f"Assertion {i+1}:")
            logger.info(f"  Credential ID: {base64.b64encode(assertion.credential['id']).decode()}")
            logger.info(f"  User handle: {assertion.user}")
            logger.info(f"  Signature: {base64.b64encode(assertion.signature).decode()[:64]}...")
        
        return True
        
    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        return False


def main():
    """Main function to run the complete FIDO2 flow"""
    logger = setup_logging()
    
    logger.info(f"FIDO2 Flow Test Started at {datetime.now()}")
    logger.info("=========================================")
    
    # Step 1: Registration
    registration_data = registration_flow(logger)
    
    if registration_data:
        logger.info("Registration completed successfully")
        
        # Step 2: Authentication
        auth_success = authentication_flow(logger, registration_data)
        
        if auth_success:
            logger.info("Authentication completed successfully")
            logger.info("=== FIDO2 Flow Test Completed Successfully ===")
        else:
            logger.error("Authentication failed")
            logger.info("=== FIDO2 Flow Test Failed at Authentication ===")
    else:
        logger.error("Registration failed - skipping authentication")
        logger.info("=== FIDO2 Flow Test Failed at Registration ===")
    
    logger.info(f"FIDO2 Flow Test Ended at {datetime.now()}")


if __name__ == '__main__':
    main()