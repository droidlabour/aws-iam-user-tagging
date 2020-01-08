import logging

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

iam = boto3.client('iam')
s3 = boto3.client('s3')

def lambda_handler(event, context):
    log.info('IAM users tagging: starting...')

    data = client.list_users()
    log.info(data)

    for user in data['Users']:
        username = user['UserName']
        log.info('username %s', username)
        email = get_owner_email(client, username)
        if not email:
            logging.info('Skipping: Email not found for user %s', username)
            continue

        access_keys = client.list_access_keys(UserName=username)['AccessKeyMetadata']
        if len(access_keys) == 1 and key_age(access_keys[0]['CreateDate']) > CREATE_NEW_ACCESS_KEY_AFTER:
            log.info('Creating a new access key')
            x = client.create_access_key(UserName=username)['AccessKey']
            access_key, secret_access_key = x['AccessKeyId'], x['SecretAccessKey']
            body = 'Access Key: ' + access_key + '<br/>' + 'Secret Key: ' + secret_access_key + '<br/>'
            subject = 'New access keys created for user ' + username
            notify(body, subject, email)
        elif len(access_keys) == 2:
            log.info('Screening existing access keys for user %s', username)
            younger_access_key = access_keys[0]
            younger_access_key_age = key_age(younger_access_key['CreateDate'])

            if not is_access_key_ever_used(client, younger_access_key['AccessKeyId']):
                if younger_access_key_age in NEW_ACCESS_KEY_NOTIFY_WINDOW:
                    old_key_expire_timeout = EXPIRE_OLD_ACCESS_KEY_AFTER - younger_access_key_age
                    logging.info('User %s has %s days to use this new key %s', username, old_key_expire_timeout, younger_access_key['AccessKeyId'])
                    body = 'You have ' + str(old_key_expire_timeout) + ' days to use the new access keys.'
                    subject = 'Please use the new access keys for ' + username
                    notify(body, subject, email)

            if younger_access_key_age == EXPIRE_OLD_ACCESS_KEY_AFTER:
                logging.info('Deactivating old key %s for user %s', access_keys[1]['AccessKeyId'], username)
                client.update_access_key(
                    UserName=username,
                    AccessKeyId=access_keys[1]['AccessKeyId'],
                    Status='Inactive'
                )
            elif younger_access_key_age == DELETE_OLD_ACCESS_KEY_AFTER:
                logging.info('Deleting old key %s for user %s', access_keys[1]['AccessKeyId'], username)
                client.delete_access_key(
                    UserName=username,
                    AccessKeyId=access_keys[1]['AccessKeyId']
                )

    log.info('Completed')
    return 0


# if __name__ == "__main__":
#    event = 1
#    context = 1
#    lambda_handler(event, context)
