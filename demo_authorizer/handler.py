import os

import jwt


def jwt_auth(event, context):
    """Lambda handler to process the incoming HTTP request Authorization header

    :param event: dict: Dictionary containing the authorization token, http method arn and
    type of authorization
    :param context: dict: Contains context information for the lambda execution environment
    """
    auth_token = event.get('authorizationToken')

    if 'Bearer' in auth_token:
        # If 'Bearer ' is present in the string, we will want to remove it
        # to make sure to be able to properly decode and verify the signature of the 
        # token. This means stripping off the first seven characters which is Bearer
        # and the trailing space before the token itself.
        auth_token = auth_token[7:]

    decoded_token = jwt.decode(auth_token, os.getenv('JWT_SECRET_KEY'))
    # Required to publish a payload formatted in this way in order for AWS to properly
    # parse it and pass the proper event payload as an HTTP event input payload to the 
    # individual lambda
    return {
            "principalId": decoded_token.get('jti'),
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                  {
                    "Action": "execute-api:Invoke",
                    "Effect": "Allow",
                    "Resource": "*"
                  }
                ]
            },
            "context": {
                'user_id': decoded_token.get('user_id')
            }
        }