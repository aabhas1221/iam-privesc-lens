"""Knowledge base of AWS IAM privilege-escalation techniques.

Each technique is plain data: the actions it needs, what the attacker ends up
controlling, and how to explain, exploit and fix it. The analyzer is generic
and only interprets these fields, so adding a technique means adding an entry
to :data:`_TECHNIQUES` (plus a test).

Requirement semantics
---------------------
``all_of``
    Every listed action must be allowed.
``any_of``
    A list of groups; for each group at least one action must be allowed.

Target semantics
----------------
``admin``
    The technique lets the principal grant itself arbitrary permissions.
``user`` / ``role`` / ``group``
    The technique lets the principal act as (or join) another principal. In
    account mode the analyzer resolves concrete targets: the resource of
    ``target_action`` must cover the target's ARN, and for roles the trust
    policy must allow ``target_service`` (if set) and the role must have an
    instance profile if ``needs_instance_profile`` is set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

__all__ = ["Severity", "Technique", "TECHNIQUES", "get_technique"]

TargetKind = Literal["admin", "user", "role", "group"]


class Severity(str, Enum):
    """Finding severity, ordered from most to least severe."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric rank: higher is more severe."""
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


@dataclass(frozen=True)
class Technique:
    """A single privilege-escalation technique."""

    id: str
    name: str
    severity: Severity
    target: TargetKind
    explanation: str
    steps: tuple[str, ...]
    remediation: str
    references: tuple[str, ...]
    all_of: tuple[str, ...] = ()
    any_of: tuple[tuple[str, ...], ...] = ()
    target_action: str | None = None
    target_service: str | None = None
    needs_instance_profile: bool = False
    writes: Literal["user", "group", "role", "policy"] | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)

    @property
    def required_actions(self) -> tuple[str, ...]:
        """Every action mentioned by the technique (for display)."""
        out = list(self.all_of)
        for group in self.any_of:
            out.append(" | ".join(group))
        return tuple(out)


_RHINO = "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
_IAM_DOCS = "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
_PASSROLE_DOCS = _IAM_DOCS + "id_roles_use_passrole.html"
_PASSROLE_FIX = (
    "Scope iam:PassRole to the specific role ARNs the principal legitimately needs and "
    "add a Condition on iam:PassedToService. Never allow PassRole on '*'. Ensure no "
    "privileged role trusts the service unless strictly required."
)


def _passrole(
    tid: str,
    name: str,
    service_actions: tuple[str, ...],
    service: str,
    explanation: str,
    steps: tuple[str, ...],
    any_of: tuple[tuple[str, ...], ...] = (),
    severity: Severity = Severity.HIGH,
) -> Technique:
    return Technique(
        id=tid,
        name=name,
        severity=severity,
        target="role",
        all_of=("iam:PassRole",) + service_actions,
        any_of=any_of,
        target_action="iam:PassRole",
        target_service=service,
        explanation=explanation,
        steps=steps,
        remediation=_PASSROLE_FIX,
        references=(_RHINO, _PASSROLE_DOCS),
        tags=("passrole",),
    )


_TECHNIQUES: tuple[Technique, ...] = (
    Technique(
        id="IAM-001",
        writes="policy",
        name="Create a new default version of a managed policy",
        severity=Severity.CRITICAL,
        target="admin",
        all_of=("iam:CreatePolicyVersion",),
        explanation=(
            "iam:CreatePolicyVersion with --set-as-default replaces the effective document "
            "of a customer-managed policy. If that policy is attached to the attacker (or to a "
            "principal they control) they can rewrite it to Action '*' / Resource '*'."
        ),
        steps=(
            "aws iam list-attached-user-policies --user-name <me>  # find a customer-managed policy attached to you",
            "aws iam create-policy-version --policy-arn <policy-arn> --policy-document file://admin.json --set-as-default",
            "admin.json grants {\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}; the new version is effective immediately",
        ),
        remediation=(
            "Remove iam:CreatePolicyVersion from non-administrative principals, or restrict its "
            "Resource to policies that are not attached to the principal itself. Alert on "
            "CreatePolicyVersion events with setAsDefault=true in CloudTrail."
        ),
        references=(_RHINO, _IAM_DOCS + "access_policies_managed-versioning.html"),
        tags=("policy-write",),
    ),
    Technique(
        id="IAM-002",
        writes="policy",
        name="Roll back to a more permissive policy version",
        severity=Severity.HIGH,
        target="admin",
        all_of=("iam:SetDefaultPolicyVersion",),
        explanation=(
            "Managed policies keep up to five versions. iam:SetDefaultPolicyVersion lets the "
            "principal activate any stored version; an older, broader version (left over from a "
            "past change) silently becomes effective."
        ),
        steps=(
            "aws iam list-policy-versions --policy-arn <policy-arn>",
            "aws iam get-policy-version --policy-arn <policy-arn> --version-id v1  # inspect older versions",
            "aws iam set-default-policy-version --policy-arn <policy-arn> --version-id v1",
        ),
        remediation=(
            "Restrict iam:SetDefaultPolicyVersion to administrators and delete stale, non-default "
            "policy versions so there is nothing permissive to roll back to."
        ),
        references=(_RHINO,),
        tags=("policy-write",),
    ),
    Technique(
        id="IAM-003",
        writes="user",
        name="Attach a managed policy to a user",
        severity=Severity.CRITICAL,
        target="admin",
        all_of=("iam:AttachUserPolicy",),
        explanation=(
            "iam:AttachUserPolicy allows attaching any managed policy, including the AWS-managed "
            "AdministratorAccess, to a user - typically the attacker's own user."
        ),
        steps=(
            "aws iam attach-user-policy --user-name <me> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            "aws iam list-attached-user-policies --user-name <me>  # confirm; permissions apply on the next call",
        ),
        remediation=(
            "Remove iam:AttachUserPolicy, or constrain it with a Condition on iam:PolicyARN to an "
            "allow-list of low-privilege policies. Enforce permission boundaries for delegated IAM admins."
        ),
        references=(_RHINO, _IAM_DOCS + "access_policies_boundaries.html"),
        tags=("policy-write",),
    ),
    Technique(
        id="IAM-004",
        writes="group",
        name="Attach a managed policy to a group",
        severity=Severity.CRITICAL,
        target="admin",
        all_of=("iam:AttachGroupPolicy",),
        explanation=(
            "If the principal is a member of a group (or can join one), iam:AttachGroupPolicy "
            "lets it attach AdministratorAccess to that group and inherit it."
        ),
        steps=(
            "aws iam list-groups-for-user --user-name <me>",
            "aws iam attach-group-policy --group-name <my-group> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
        ),
        remediation=(
            "Remove iam:AttachGroupPolicy or restrict it with an iam:PolicyARN condition; scope the "
            "Resource to groups the principal is not a member of."
        ),
        references=(_RHINO,),
        tags=("policy-write",),
    ),
    Technique(
        id="IAM-005",
        writes="role",
        name="Attach a managed policy to a role",
        severity=Severity.CRITICAL,
        target="admin",
        all_of=("iam:AttachRolePolicy",),
        explanation=(
            "iam:AttachRolePolicy on the principal's own role (or on any role it can assume) lets "
            "it attach AdministratorAccess and then use that role."
        ),
        steps=(
            "aws iam attach-role-policy --role-name <role-i-use-or-can-assume> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            "aws sts assume-role --role-arn <role-arn> --role-session-name x  # if it is not already your role",
        ),
        remediation=(
            "Remove iam:AttachRolePolicy or constrain it with iam:PolicyARN conditions and a "
            "permission boundary requirement (iam:PermissionsBoundary)."
        ),
        references=(_RHINO,),
        tags=("policy-write",),
    ),
    Technique(
        id="IAM-006",
        writes="user",
        name="Write an inline policy on a user",
        severity=Severity.CRITICAL,
        target="admin",
        all_of=("iam:PutUserPolicy",),
        explanation="iam:PutUserPolicy creates or replaces an inline policy; writing '*:*' onto your own user is instant admin.",
        steps=(
            "aws iam put-user-policy --user-name <me> --policy-name x --policy-document file://admin.json",
        ),
        remediation="Remove iam:PutUserPolicy from non-admins; prefer managed policies with change control.",
        references=(_RHINO,),
        tags=("policy-write",),
    ),
    Technique(
        id="IAM-007",
        writes="group",
        name="Write an inline policy on a group",
        severity=Severity.CRITICAL,
        target="admin",
        all_of=("iam:PutGroupPolicy",),
        explanation="iam:PutGroupPolicy on a group the principal belongs to grants it arbitrary permissions.",
        steps=(
            "aws iam list-groups-for-user --user-name <me>",
            "aws iam put-group-policy --group-name <my-group> --policy-name x --policy-document file://admin.json",
        ),
        remediation="Remove iam:PutGroupPolicy from non-admins, or scope it to groups the principal is not in.",
        references=(_RHINO,),
        tags=("policy-write",),
    ),
    Technique(
        id="IAM-008",
        writes="role",
        name="Write an inline policy on a role",
        severity=Severity.CRITICAL,
        target="admin",
        all_of=("iam:PutRolePolicy",),
        explanation="iam:PutRolePolicy on the principal's own or an assumable role grants arbitrary permissions to that role.",
        steps=(
            "aws iam put-role-policy --role-name <role> --policy-name x --policy-document file://admin.json",
            "aws sts assume-role --role-arn <role-arn> --role-session-name x  # if it is not already your role",
        ),
        remediation="Remove iam:PutRolePolicy from non-admins; require a permissions boundary on delegated role management.",
        references=(_RHINO,),
        tags=("policy-write",),
    ),
    Technique(
        id="IAM-009",
        name="Add yourself to a privileged group",
        severity=Severity.HIGH,
        target="group",
        all_of=("iam:AddUserToGroup",),
        target_action="iam:AddUserToGroup",
        explanation="iam:AddUserToGroup lets the user join any group in the Resource scope and inherit its policies.",
        steps=(
            "aws iam list-groups  # look for admin-like groups",
            "aws iam add-user-to-group --group-name <privileged-group> --user-name <me>",
        ),
        remediation="Scope iam:AddUserToGroup to specific low-privilege group ARNs; manage membership through IaC.",
        references=(_RHINO,),
        tags=("lateral",),
    ),
    Technique(
        id="IAM-010",
        name="Create access keys for another user",
        severity=Severity.HIGH,
        target="user",
        all_of=("iam:CreateAccessKey",),
        target_action="iam:CreateAccessKey",
        explanation=(
            "iam:CreateAccessKey on another user mints long-lived credentials for that user, so the "
            "attacker can act as them (users have at most two keys; one slot must be free)."
        ),
        steps=(
            "aws iam list-access-keys --user-name <victim>",
            "aws iam create-access-key --user-name <victim>",
            "export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...  # now acting as <victim>",
        ),
        remediation=(
            "Restrict iam:CreateAccessKey to the caller's own user: Resource "
            "arn:aws:iam::<acct>:user/${aws:username}."
        ),
        references=(_RHINO,),
        tags=("lateral",),
    ),
    Technique(
        id="IAM-011",
        name="Create a console password for another user",
        severity=Severity.HIGH,
        target="user",
        all_of=("iam:CreateLoginProfile",),
        target_action="iam:CreateLoginProfile",
        explanation="For users without a console password, iam:CreateLoginProfile sets one and grants console access as that user.",
        steps=(
            "aws iam create-login-profile --user-name <victim> --password '<new-password>' --no-password-reset-required",
            "Sign in at https://<acct>.signin.aws.amazon.com/console as <victim>",
        ),
        remediation="Scope iam:CreateLoginProfile to ${aws:username}; require MFA for console users.",
        references=(_RHINO,),
        tags=("lateral",),
    ),
    Technique(
        id="IAM-012",
        name="Reset another user's console password",
        severity=Severity.HIGH,
        target="user",
        all_of=("iam:UpdateLoginProfile",),
        target_action="iam:UpdateLoginProfile",
        explanation="iam:UpdateLoginProfile changes an existing console password, taking over that user's console session.",
        steps=(
            "aws iam update-login-profile --user-name <victim> --password '<new-password>' --no-password-reset-required",
        ),
        remediation="Scope iam:UpdateLoginProfile to ${aws:username}; enforce MFA so a password alone is insufficient.",
        references=(_RHINO,),
        tags=("lateral",),
    ),
    Technique(
        id="IAM-013",
        name="Rewrite a role trust policy and assume it",
        severity=Severity.CRITICAL,
        target="role",
        all_of=("iam:UpdateAssumeRolePolicy", "sts:AssumeRole"),
        target_action="iam:UpdateAssumeRolePolicy",
        explanation=(
            "iam:UpdateAssumeRolePolicy replaces who may assume a role. The attacker adds their own "
            "ARN to the trust policy of a privileged role and assumes it."
        ),
        steps=(
            "aws iam update-assume-role-policy --role-name <privileged-role> --policy-document file://trust-me.json",
            "aws sts assume-role --role-arn <privileged-role-arn> --role-session-name x",
        ),
        remediation=(
            "Treat iam:UpdateAssumeRolePolicy as an admin-only action; alert on it in CloudTrail and "
            "protect privileged roles with an SCP denying trust-policy changes."
        ),
        references=(_RHINO,),
        tags=("lateral",),
    ),
    Technique(
        id="STS-001",
        name="Assume a role that trusts this principal",
        severity=Severity.MEDIUM,
        target="role",
        all_of=("sts:AssumeRole",),
        target_action="sts:AssumeRole",
        explanation=(
            "The role's trust policy admits this principal (directly, via the account root, or via "
            "'*') and the principal may call sts:AssumeRole on it. Whatever the role can do, the "
            "principal can do. Dangerous when the role is more privileged than the caller."
        ),
        steps=(
            "aws sts assume-role --role-arn <role-arn> --role-session-name x",
            "export the returned AccessKeyId / SecretAccessKey / SessionToken and continue as the role",
        ),
        remediation=(
            "Trust specific principal ARNs rather than the account root, scope sts:AssumeRole in "
            "identity policies to the roles actually needed, and add conditions (MFA, source "
            "identity, ExternalId for third parties)."
        ),
        references=(_IAM_DOCS + "id_roles_terms-and-concepts.html",),
        tags=("lateral",),
    ),
    _passrole(
        "PASS-001",
        "PassRole to a new Lambda function and invoke it",
        ("lambda:CreateFunction", "lambda:InvokeFunction"),
        "lambda.amazonaws.com",
        "The attacker creates a Lambda function that runs as a more privileged role and invokes "
        "it; the function code uses the role's credentials to perform any action the role allows.",
        (
            "zip f.zip index.py  # handler calls e.g. iam.attach_user_policy(UserName='<me>', PolicyArn=AdministratorAccess)",
            "aws lambda create-function --function-name x --runtime python3.12 --handler index.handler --zip-file fileb://f.zip --role <privileged-role-arn>",
            "aws lambda invoke --function-name x out.json",
        ),
    ),
    _passrole(
        "PASS-002",
        "PassRole to a new Lambda function triggered by an event source",
        ("lambda:CreateFunction", "lambda:CreateEventSourceMapping"),
        "lambda.amazonaws.com",
        "Without lambda:InvokeFunction the function can still be triggered by an event source "
        "mapping (DynamoDB stream, Kinesis, SQS), executing as the passed role.",
        (
            "aws lambda create-function --function-name x ... --role <privileged-role-arn>",
            "aws lambda create-event-source-mapping --function-name x --event-source-arn <stream-or-queue-arn> --starting-position LATEST",
            "put a record on the stream/queue to trigger execution",
        ),
    ),
    _passrole(
        "PASS-003",
        "PassRole to a new EC2 instance",
        ("ec2:RunInstances",),
        "ec2.amazonaws.com",
        "The attacker launches an instance with an instance profile for a privileged role and "
        "retrieves the role credentials from the instance metadata service (via user data, SSH or SSM).",
        (
            "aws ec2 run-instances --image-id <ami> --instance-type t3.micro --iam-instance-profile Name=<profile-of-privileged-role> --user-data file://exfil.sh",
            "exfil.sh reads http://169.254.169.254/latest/meta-data/iam/security-credentials/<role> (IMDSv2 token first) and sends them out",
        ),
    ),
    _passrole(
        "PASS-004",
        "PassRole to a new CloudFormation stack",
        ("cloudformation:CreateStack",),
        "cloudformation.amazonaws.com",
        "CloudFormation provisions resources using the passed service role, so a template can "
        "create IAM users/policies the attacker could not create directly.",
        (
            "template.yaml defines an AWS::IAM::User with AdministratorAccess and an AWS::IAM::AccessKey output",
            "aws cloudformation create-stack --stack-name x --template-body file://template.yaml --role-arn <privileged-role-arn> --capabilities CAPABILITY_IAM",
            "aws cloudformation describe-stacks --stack-name x  # read the access key from Outputs",
        ),
    ),
    _passrole(
        "PASS-005",
        "PassRole to a new Glue development endpoint",
        ("glue:CreateDevEndpoint",),
        "glue.amazonaws.com",
        "A Glue dev endpoint runs with the passed role and accepts an attacker SSH key; the role "
        "credentials are available from the endpoint.",
        (
            "aws glue create-dev-endpoint --endpoint-name x --role-arn <privileged-role-arn> --public-key file://id_rsa.pub",
            "aws glue get-dev-endpoint --endpoint-name x  # obtain the address, then SSH in and read the role credentials",
        ),
    ),
    _passrole(
        "PASS-006",
        "PassRole to a new Data Pipeline",
        ("datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"),
        "datapipeline.amazonaws.com",
        "A pipeline definition can contain a ShellCommandActivity that runs arbitrary commands "
        "with the passed pipeline/resource role.",
        (
            "aws datapipeline create-pipeline --name x --unique-id x",
            "aws datapipeline put-pipeline-definition --pipeline-id <id> --pipeline-definition file://def.json  # ShellCommandActivity using the privileged role",
            "aws datapipeline activate-pipeline --pipeline-id <id>",
        ),
        any_of=(("datapipeline:ActivatePipeline",),),
    ),
    _passrole(
        "PASS-007",
        "PassRole to a new SageMaker notebook instance",
        ("sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl"),
        "sagemaker.amazonaws.com",
        "The notebook runs with the passed execution role; a presigned URL gives the attacker a "
        "Jupyter terminal holding those credentials.",
        (
            "aws sagemaker create-notebook-instance --notebook-instance-name x --instance-type ml.t3.medium --role-arn <privileged-role-arn>",
            "aws sagemaker create-presigned-notebook-instance-url --notebook-instance-name x",
            "open the URL, start a terminal and use the role credentials",
        ),
    ),
    _passrole(
        "PASS-008",
        "PassRole to a new CodeBuild project",
        ("codebuild:CreateProject", "codebuild:StartBuild"),
        "codebuild.amazonaws.com",
        "A CodeBuild buildspec executes arbitrary commands with the project's service role.",
        (
            "aws codebuild create-project --name x --source type=NO_SOURCE,buildspec=file://buildspec.yml --artifacts type=NO_ARTIFACTS --environment ... --service-role <privileged-role-arn>",
            "aws codebuild start-build --project-name x  # buildspec runs e.g. aws iam attach-user-policy ...",
        ),
    ),
    Technique(
        id="LAM-001",
        name="Overwrite the code of an existing Lambda function",
        severity=Severity.HIGH,
        target="role",
        all_of=("lambda:UpdateFunctionCode",),
        target_service="lambda.amazonaws.com",
        explanation=(
            "lambda:UpdateFunctionCode replaces the code of an existing function. The next "
            "invocation (by its normal trigger) runs attacker code with the function's execution role."
        ),
        steps=(
            "aws lambda list-functions --query 'Functions[].[FunctionName,Role]'",
            "aws lambda update-function-code --function-name <fn-with-privileged-role> --zip-file fileb://payload.zip",
            "wait for (or cause) the next invocation",
        ),
        remediation=(
            "Scope lambda:UpdateFunctionCode to specific function ARNs, enable code signing for "
            "Lambda, and keep execution roles least-privileged."
        ),
        references=(_RHINO, "https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html"),
        tags=("compute",),
    ),
    Technique(
        id="GLU-001",
        name="Hijack an existing Glue development endpoint",
        severity=Severity.HIGH,
        target="role",
        all_of=("glue:UpdateDevEndpoint",),
        target_service="glue.amazonaws.com",
        explanation="glue:UpdateDevEndpoint can add an attacker SSH public key to an existing endpoint and use its role.",
        steps=(
            "aws glue get-dev-endpoints",
            "aws glue update-dev-endpoint --endpoint-name <endpoint> --public-key file://id_rsa.pub",
            "SSH to the endpoint and use its role credentials",
        ),
        remediation="Scope glue:UpdateDevEndpoint to specific endpoints; decommission unused dev endpoints.",
        references=(_RHINO,),
        tags=("compute",),
    ),
    Technique(
        id="SSM-001",
        name="Run commands on EC2 instances through Systems Manager",
        severity=Severity.HIGH,
        target="role",
        any_of=(("ssm:SendCommand", "ssm:StartSession"),),
        target_service="ec2.amazonaws.com",
        needs_instance_profile=True,
        explanation=(
            "ssm:SendCommand / ssm:StartSession give a shell on managed instances. From there the "
            "attacker reads the instance profile credentials from IMDS and acts as that role."
        ),
        steps=(
            "aws ssm describe-instance-information",
            "aws ssm start-session --target <instance-id>  # or: aws ssm send-command --document-name AWS-RunShellScript --targets Key=InstanceIds,Values=<id> --parameters commands='curl ...'",
            "curl the IMDS security-credentials endpoint to obtain the role credentials",
        ),
        remediation=(
            "Scope SSM actions with resource tags (ssm:resourceTag) to non-sensitive instances and "
            "keep instance profile roles least-privileged."
        ),
        references=("https://docs.aws.amazon.com/systems-manager/latest/userguide/getting-started-restrict-access-quickstart.html",),
        tags=("compute",),
    ),
    Technique(
        id="EC2-001",
        name="Push an SSH key with EC2 Instance Connect",
        severity=Severity.HIGH,
        target="role",
        all_of=("ec2-instance-connect:SendSSHPublicKey",),
        target_service="ec2.amazonaws.com",
        needs_instance_profile=True,
        explanation=(
            "ec2-instance-connect:SendSSHPublicKey installs a temporary SSH key on an instance. With "
            "network reachability the attacker logs in and steals the instance profile credentials."
        ),
        steps=(
            "aws ec2-instance-connect send-ssh-public-key --instance-id <id> --instance-os-user ec2-user --ssh-public-key file://id.pub",
            "ssh ec2-user@<instance> and query IMDS for the role credentials",
        ),
        remediation="Scope Instance Connect by instance tag and OS user; keep instance roles least-privileged.",
        references=("https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-set-up.html",),
        tags=("compute",),
    ),
)

TECHNIQUES: dict[str, Technique] = {t.id: t for t in _TECHNIQUES}
"""All known techniques keyed by id."""


def get_technique(technique_id: str) -> Technique:
    """Return a technique by id (case-insensitive).

    Raises:
        KeyError: if no technique has that id.
    """
    return TECHNIQUES[technique_id.upper()]
