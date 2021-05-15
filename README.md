# github-secalerts-jira

# Initial Setup
1) Generate Github Token and add permissions to fetch security alerts
2) Generate JIRA API token of user making sure that user should has valid access on JIRA Software board
3) Get AWS credentials such as access keys and token
4) Create DynamoDB table as we will be storing key of JIRA tickets to avoid duplication 

# How it works
python github-secalerts-jira.py --owner <github_owner_name> --repository <repository_name> --token <github_token>
    Script will fetch all the security alerts from the repository and prepare 4 different CSVs based on severity level. GitHub has 4 types of severity for security alerts i.e. CRITICAL, HIGH, MODERATE and LOW.
    After the creation of CSVs, it will create 4 tickets for each severity.
    If user is addressing any alerts in GitHub then on the next run of the script, description in the JIRA ticket/s will be updated on the fly.

# Future work
    Need to address workflow of JIRA tickets resolution

# Codebase can be EASILY converted to lambda function or integrated in JENKINS job.
