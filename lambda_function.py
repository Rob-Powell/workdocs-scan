import json
import logging
import urllib3
import boto3
import os
from pathlib import Path
from subprocess import getstatusoutput
logger = logging.getLogger()
logger.setLevel(logging.INFO)
# I only want info from my app not globally
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)

def lambda_handler(event, context):
    # TODO 
    #logger.debug("## ENVIRONMENT VARIABLES")
    #logger.debug(os.environ['PATH'])
    #logger.debug(os.environ['LD_LIBRARY_PATH'])
    #logger.debug(os.listdir("/opt/app/bin"))
    #logger.debug(os.listdir("/opt/app/clamdb"))
    #logger.debug("## ENVIRONMENT VARIABLES END")
    logger.debug(json.dumps(event))
    if (('body' in event) and ('headers' in event)):
        '''
        WorkDocs SNS direct (without cloudtrail) event source
        This part of the code is not currently in use
        '''
        eventBody=json.loads(event['body'])
        if('SubscribeURL' in eventBody and event['headers']['x-amz-sns-message-type'] == "SubscriptionConfirmation"):
            logging.debug("Need to subscribe to SNS now")
            logging.debug(eventBody['SubscribeURL'])
            
            http = urllib3.PoolManager()
            response = http.request("GET", eventBody['SubscribeURL'])
            logging.debug("Response code:")
            logging.debug(response.status)
            logging.debug("SNS Data response:")
            logging.debug(response.data.decode("utf-8"))
            if response.status != 200:
                logging.error("We had an error confirming subscription to SNS")
                return {
                    'statusCode': 500,
                    'body': "We had an error confirming subscription to SNS"
                }
            else:
                logging.info("SNS Subscription Confirmed")
                return {
                    'statusCode': 200,
                    'body': "SNS Subscription Confirmed"
                }
        elif('Message' in eventBody and event['headers']['x-amz-sns-message-type'] == "Notification"):
            logging.debug("SNS event message")
            messageBody = json.loads(eventBody['Message'])
            if(messageBody['action']=="upload_document_version"):
                logging.debug("SNS event upload_document_version")
                client = boto3.client('workdocs')
                response = client.get_document_version(
                    #TODO
                    DocumentId='',
                    VersionId='',
                    Fields='SOURCE',
                    IncludeCustomMetadata=True
                )
                fileURL=response['Metadata']['Source']['ORIGINAL']
                logging.debug(fileURL)
                
                http = urllib3.PoolManager()
                r = http.request('GET', fileURL, preload_content=False)
                path = "/tmp/" + response['Metadata']['Name']
                with open(path, 'wb') as out:
                    while True:
                        data = r.read(4096)
                        if not data:
                            break
                        out.write(data)
                
                r.release_conn()
                my_file = Path(path)
                if my_file.is_file():
                    logging.debug("Downloaded file exists")
                    rc, output = getstatusoutput(['/opt/app/bin/clamscan --database=/opt/app/clamdb', path])
                    logging.debug(output)
                    return {
                            'statusCode': 200,
                            'body': "Processed action upload_document_version"
                    }
                else:
                    logging.error("No file found after attempting download")
            else:
                return {
                    'statusCode': 200,
                    'body': "Event received nothing to do"
                }
    elif(('detail' in event) and ('source' in event)):
        '''
        Cloudtrail event processing via eventbridge
        '''
        logging.debug("Cloudtrail event message")
        if(event['detail']['eventName']=="UpdateDocumentVersion"):
            logging.debug("Cloudtrail event UpdateDocumentVersion")
            client = boto3.client('workdocs')
            getDocResponse = client.get_document_version(
                DocumentId=event['detail']['requestParameters']['DocumentId'],
                VersionId=event['detail']['requestParameters']['VersionId'],
                Fields='SOURCE',
                IncludeCustomMetadata=True
            )
            fileURL=getDocResponse['Metadata']['Source']['ORIGINAL']
            logging.debug(fileURL)
            
            http = urllib3.PoolManager()
            r = http.request('GET', fileURL, preload_content=False)
            path = "/tmp/" + getDocResponse['Metadata']['Name']
            with open(path, 'wb') as out:
                while True:
                    data = r.read(4096)
                    if not data:
                        break
                    out.write(data)
            
            r.release_conn()
            my_file = Path(path)
            if my_file.is_file():
                logging.debug("Downloaded file exists: " + path)
                logging.debug("Scanning File " +  getDocResponse['Metadata']['Name'] + " From User: " + event['detail']['userIdentity']['userName'])
                rc, output = getstatusoutput(['/opt/app/bin/clamscan --no-summary --database=/opt/app/clamdb '+ path])
                logging.debug(output)
                if rc == 0:
                    logging.info("No virus detected - Scaned file " +  getDocResponse['Metadata']['Name'] + " From User: " + event['detail']['userIdentity']['userName'])
                    response = client.create_comment(
                        DocumentId=event['detail']['requestParameters']['DocumentId'],
                        VersionId=event['detail']['requestParameters']['VersionId'],
                        Text="Virus Check OK",
                        Visibility="PRIVATE",
                        NotifyCollaborators=False
                    )
                    return {
                            'statusCode': 200,
                            'body': "Processed action UpdateDocumentVersion"
                    }
                elif rc == 1:
                    logging.info("VIRUS DETECTED - Scaned file " +  getDocResponse['Metadata']['Name'] + " From User: " + event['detail']['userIdentity']['userName'])
                    response = client.create_comment(
                        DocumentId=event['detail']['requestParameters']['DocumentId'],
                        VersionId=event['detail']['requestParameters']['VersionId'],
                        Text="Virus Found in uploaded file " +  getDocResponse['Metadata']['Name'] + " file will be removed",
                        Visibility="PUBLIC",
                        NotifyCollaborators=True
                    )
                    response = client.delete_document(
                        DocumentId=event['detail']['requestParameters']['DocumentId']
                    )
                    logging.info("Deleted suspicious file - Scaned file " +  getDocResponse['Metadata']['Name'] + " From User: " + event['detail']['userIdentity']['userName'])
                    logging.info(output)
                    return {
                            'statusCode': 400,
                            'body': "Virus file detected"
                    }                    
                else:
                    logging.error("Attempted - Scaned file " +  getDocResponse['Metadata']['Name'] + " From User: " + event['detail']['userIdentity']['userName'])
                    return {
                            'statusCode': 500,
                            'body': "Server had an error scanning the file"
                    }   
            else:
                logging.error("No file found after attempting download")
                return {
                        'statusCode': 500,
                        'body': "No file found while attempting download"
                }
        else:
            logging.info(event)
            return {
                'statusCode': 200,
                'body': "Event received nothing to do"
            }        
    else:
        logging.error("Not expecting this error")
        return {
            'statusCode': 500,
            'body': json.dumps(event)
        }