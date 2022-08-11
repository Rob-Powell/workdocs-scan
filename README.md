# Amazon WorkDocs Scan

```
     _                           __      __       _   ___               ___               
    /_\  _ __  __ _ ______ _ _   \ \    / /__ _ _| |_|   \ ___  __ ___ / __| __ __ _ _ _  
   / _ \| '  \/ _` |_ / _ \ ' \   \ \/\/ / _ \ '_| / / |) / _ \/ _(_-< \__ \/ _/ _` | ' \ 
  /_/ \_\_|_|_\__,_/__\___/_||_|   \_/\_/\___/_| |_\_\___/\___/\__/__/ |___/\__\__,_|_||_|
                                                                                          
```

## Demonstration code only should not be considered ready for production use

Hi there! Welcome to Amazon WorkDocs Scan

This is a demonstration project to showcase how WorkDocs can be tied into an 
antivirus product in this case ClamAV.

![workdocs-scan-architecture](workdocs-scan.png?raw=true))

WorkDocs supports 2 primary ways of receving event notifications via its
integrated SNS trigger or as it also logs events via cloud trail an event bridge
attached to that trail.

In this example when someone uploads a file to workdocs or edits a file this
event is captured by WorkDocs as `UpdateDocumentVersion`. To capture this event
the account requires cloud trail to be enabled and capturing all management
events. Once the events are logged you should see them in the cloud trail bucket
with the aforementioned event name. Now to setup an event bridge rule with cloud
trail as the source and the Lambda function as the destionation.

I used the following event bridge event filter to select just the events I was
interested in for this project as below:

```
{
  "source": ["aws.workdocs"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["workdocs.amazonaws.com"],
    "eventName": ["UpdateDocumentVersion"]
  }
}
```

You can see in the tests directory an example event to verify your filter.

The app is split into two containers primarily for ease of development with the 
base-container having clam and associated binaries and the app container having 
python application logic.

Build instructions for the container below - this was built in AWS cloud 9

```
git clone https://github.com/Rob-Powell/workdocs-scan.git
cd base-container/
docker build --no-cache -t workdocs-scan .
cd ..
docker build --no-cache -t workdocs-scan-app .
aws ecr get-login-password --region ap-southeast-2 | docker login --username AWS --password-stdin <your-aws-acc>.dkr.ecr.ap-southeast-2.amazonaws.com
docker tag workdocs-scan-app:latest <your-aws-acc>.dkr.ecr.ap-southeast-2.amazonaws.com/workdocs-scan:latest
docker push <your-aws-acc>.dkr.ecr.ap-southeast-2.amazonaws.com/workdocs-scan:latest
```

Once the image has been uploaded you will need to update your Lambda function to
point at the new image ID.

## Install instructions

1. Create cloud 9 instance
2. Clone Git repo into cloud 9
3. (Optional) Create private code commit if you desire to make changes and save them
4. Create AWS ECR repository
5. Build the container subsituting in your ECR repo as per above shell commands
6. Create lambda function using custom container image that was built the Lambda
will also require 2G memory 2G ephemeral storage and a timeout of 2 minutes this
should give enough capacity to scan files of around 1gb but would be worth monitoring
adjusting for your specific usecase
7. When creating the role for the lambda function it will need access to the 
workdocs instance (you could add a policy like `AmazonWorkDocsFullAccess`)
8. Now create the Amazon EventBridge rule selecting AWS services -> cloudtrail 
-> aws api call via cloud trail as your source ingusing the pattern above and 
the target as your new lambda function

Setup should now be complete and you should be able to test the scanning by 
uploading a file to your workdocs instance - watching for the lambda function 
logs in cloud watching then verify in workdocs by selecting a newly uploaded file
and looking for the private feedback/comment on the file to say "Virus Check OK"

## Todo

* Create codepipeline to maintain image
* Convert to CDK for ease of install
* re-write lambda
* Add security Hub integration
* Optimise docker files these were originally built for a layer but ClamAV was too large
* Investigate arm64 support for cheaper runtime
* Add a scheduled lambda or pipeline to refresh clamDB
* Add option to quarantine items in an s3 bucket rather than just delete them
* Add ability to scan an existing workdocs deployment rather than just new items
* Demo alternative method using built in workdocs SNS instead of cloudtrail
* Create better docs