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

'''
#####################################
##           Gherkin               ##
#####################################
Rule Name:
  AMI_EBS_ENCRYPTED

Description:
  Check EBS-backed AMI are encrypted.

Rationale:
  Encrypting on EBS ensure that no data is written on disk in clear text.

Indicative Severity:
  Medium

Trigger:
  Periodic

Reports on:
  AWS::::Account

Scenarios:
  Scenario: 1
    Given: Verify the AMI target EBS is Encrypted
      And: AMI target EBS is encrypted
     Then: Return COMPLIANT
  Scenario: 2
    Given: Verify the AMI target EBS is not Encrypted
      And: AMI target EBS is not encrypted
     Then: Return NON_COMPLIANT
'''


from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType
DEFAULT_RESOURCE_TYPE = 'AWS::::Account'

class AMI_EBS_ENCRYPTED(ConfigRule):

    def evaluate_periodic(self, event, client_factory, valid_rule_parameters):
        ec2_client = client_factory.build_client('ec2')
        evaluations = []
        amis = ec2_client.describe_images(Owners=["self"])

        for ami in amis.get('Images'):
            block_devices = ami.get('BlockDeviceMappings')
            for block_device in block_devices:
                ebs = block_device.get('Ebs')
                if ebs and ebs['Encrypted']:
                    evaluations.append(
                        Evaluation(
                            ComplianceType.COMPLIANT,
                            ami.get('ImageId'),
                            DEFAULT_RESOURCE_TYPE
                        )
                    )
                else:
                    evaluations.append(
                        Evaluation(
                            ComplianceType.NON_COMPLIANT,
                            ami.get('ImageId'),
                            DEFAULT_RESOURCE_TYPE
                        )
                    )
        return evaluations


################################
# DO NOT MODIFY ANYTHING BELOW #
################################
def lambda_handler(event, context):
    my_rule = AMI_EBS_ENCRYPTED()
    evaluator = Evaluator(my_rule)
    return evaluator.handle(event, context)
