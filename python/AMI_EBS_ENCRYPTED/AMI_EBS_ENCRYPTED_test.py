# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.

import unittest
from mock import patch, MagicMock
from rdklib import Evaluation, ComplianceType
import rdklibtest

#############

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
RESOURCE_TYPE = 'AWS::::Account'

#############
# Main Code #
#############

MODULE = __import__('AMI_EBS_ENCRYPTED')
RULE = MODULE.AMI_EBS_ENCRYPTED()

CLIENT_FACTORY = MagicMock()

#example for mocking S3 API calls
EC2_CLIENT_MOCK = MagicMock()

def mock_get_client(client_name, *args, **kwargs):
    if client_name == 'ec2':
        return EC2_CLIENT_MOCK
    raise Exception("Attempting to create an unknown client")

@patch.object(CLIENT_FACTORY, 'build_client', MagicMock(side_effect=mock_get_client))
class ComplianceTest(unittest.TestCase):

    non_encrypted_ami_ebs = {
        "Images": [
            {
                "ImageId": "ami-0112c52e7ca89ee2e",
                "BlockDeviceMappings": [
                    {
                        "Ebs": {
                            "Encrypted": False
                        }
                    }
                ]
            }
        ]
    }

    encrypted_ami_ebs = {
        "Images": [
            {
                "ImageId": "ami-08d7261cad6c06507",
                "BlockDeviceMappings": [
                    {
                        "Ebs": {
                            "Encrypted": True
                        }
                    }
                ]
            }
        ]
    }


    def test_compliant_ami(self):
        EC2_CLIENT_MOCK.describe_images.return_value = self.encrypted_ami_ebs
        response = RULE.evaluate_periodic("", CLIENT_FACTORY, "")
        resp_expected = [
            Evaluation(ComplianceType.COMPLIANT, "ami-08d7261cad6c06507", RESOURCE_TYPE)
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_non_compliant_ami(self):
        EC2_CLIENT_MOCK.describe_images.return_value = self.non_encrypted_ami_ebs
        response = RULE.evaluate_periodic("", CLIENT_FACTORY, "")
        resp_expected = [
            Evaluation(ComplianceType.NON_COMPLIANT, "ami-0112c52e7ca89ee2e", RESOURCE_TYPE)
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)
