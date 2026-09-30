import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as agentcore from 'aws-cdk-lib/aws-bedrockagentcore';

const TARGET = 'github';
const TOOL = 'open_pr';

export class ActsAsUserStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // --- Identity: two humans and the agent's own service credential -------------
    const pool = new cognito.UserPool(this, 'Pool', {
      selfSignUpEnabled: false,
      signInAliases: { username: true },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    const client = pool.addClient('DemoClient', {
      authFlows: { adminUserPassword: true },
      accessTokenValidity: cdk.Duration.hours(1), // the stale-claim demo relies on this window
      generateSecret: false,
    });
    for (const g of ['platform', 'platform-readonly', 'oncall']) {
      new cognito.CfnUserPoolGroup(this, g === 'platform' ? 'PlatformGroup' : `Group-${g}`, { userPoolId: pool.userPoolId, groupName: g });
    }

    // --- The mock target: records the "PR", never talks to GitHub ----------------
    const ledger = new dynamodb.Table(this, 'Ledger', {
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    const fn = new lambda.Function(this, 'OpenPr', {
      runtime: lambda.Runtime.PYTHON_3_13,
      handler: 'open_pr.handler',
      code: lambda.Code.fromAsset('../lambda'),
      environment: { LEDGER: ledger.tableName },
      timeout: cdk.Duration.seconds(10),
    });
    ledger.grantWriteData(fn);

    // --- Gateway execution role (Policy needs these three actions, per the docs) --
    const gwRole = new iam.Role(this, 'GatewayRole', {
      assumedBy: new iam.ServicePrincipal('bedrock-agentcore.amazonaws.com', {
        conditions: {
          StringEquals: { 'aws:SourceAccount': this.account },
          ArnLike: { 'aws:SourceArn': `arn:aws:bedrock-agentcore:${this.region}:${this.account}:*` },
        },
      }),
    });
    fn.grantInvoke(gwRole);
    gwRole.addToPolicy(new iam.PolicyStatement({
      actions: ['bedrock-agentcore:GetPolicyEngine', 'bedrock-agentcore:AuthorizeAction', 'bedrock-agentcore:PartiallyAuthorizeActions'],
      resources: [
        `arn:aws:bedrock-agentcore:${this.region}:${this.account}:policy-engine/*`,
        `arn:aws:bedrock-agentcore:${this.region}:${this.account}:gateway/*`,
      ],
    }));

    const authorizer = {
      customJwtAuthorizer: {
        discoveryUrl: `https://cognito-idp.${this.region}.amazonaws.com/${pool.userPoolId}/.well-known/openid-configuration`,
        allowedClients: [client.userPoolClientId],
      },
    };
    const toolSchema = {
      inlinePayload: [{
        name: TOOL,
        description: 'Open a pull request against a repository',
        inputSchema: {
          type: 'object',
          properties: {
            repo: { type: 'string', description: 'owner/name of the repository' },
            title: { type: 'string', description: 'pull request title' },
            requested_by: { type: 'string', description: 'who asked the agent (informational only, never trusted)' },
          },
          required: ['repo', 'title'],
        },
      }],
    };
    const targetConfiguration = { mcp: { lambda: { lambdaArn: fn.functionArn, toolSchema } } };
    const credentialProviderConfigurations = [{ credentialProviderType: 'GATEWAY_IAM_ROLE' }];

    // --- Gateway 1: OPEN. Same target, no policy engine. The vulnerable baseline. --
    const open = new agentcore.CfnGateway(this, 'OpenGateway', {
      name: 'acts-as-user-open',
      protocolType: 'MCP',
      roleArn: gwRole.roleArn,
      authorizerType: 'CUSTOM_JWT',
      authorizerConfiguration: authorizer,
    });
    const openTarget = new agentcore.CfnGatewayTarget(this, 'OpenTarget', {
      name: TARGET, gatewayIdentifier: open.attrGatewayIdentifier,
      targetConfiguration, credentialProviderConfigurations,
    });

    // --- Gateway 2: GUARDED. Same target, Cedar policy engine in ENFORCE mode. ------
    const engine = new agentcore.CfnPolicyEngine(this, 'Engine', { name: 'acts_as_user_engine' });
    const guarded = new agentcore.CfnGateway(this, 'GuardedGateway', {
      name: 'acts-as-user-guarded',
      protocolType: 'MCP',
      roleArn: gwRole.roleArn,
      authorizerType: 'CUSTOM_JWT',
      authorizerConfiguration: authorizer,
      policyEngineConfiguration: { arn: engine.attrPolicyEngineArn, mode: 'ENFORCE' },
    });
    const guardedTarget = new agentcore.CfnGatewayTarget(this, 'GuardedTarget', {
      name: TARGET, gatewayIdentifier: guarded.attrGatewayIdentifier,
      targetConfiguration, credentialProviderConfigurations,
    });

    // Anyone authenticated may open PRs on the docs repo.
    const docsPolicy = new agentcore.CfnPolicy(this, 'DocsPolicy', {
      name: 'docs_open_to_all_users',
      policyEngineId: engine.attrPolicyEngineId,
      definition: { cedar: { statement: `permit(
  principal is AgentCore::OAuthUser,
  action == AgentCore::Action::"${TARGET}___${TOOL}",
  resource == AgentCore::Gateway::"${guarded.attrGatewayArn}"
) when {
  context.input.repo == "acme/docs"
};` } },
    });
    // Only members of the platform group may open PRs on platform-infra. The groups claim reaches Cedar as the string
    // ["platform","oncall"], so match the QUOTED element. A bare *platform* also matches "platform-readonly" (tested).
    // Any other repo (for example acme/payments) has no permit, so default-deny applies.
    const platformPolicy = new agentcore.CfnPolicy(this, 'PlatformPolicy', {
      name: 'platform_infra_platform_group_only',
      policyEngineId: engine.attrPolicyEngineId,
      definition: { cedar: { statement: `permit(
  principal is AgentCore::OAuthUser,
  action == AgentCore::Action::"${TARGET}___${TOOL}",
  resource == AgentCore::Gateway::"${guarded.attrGatewayArn}"
) when {
  context.input.repo == "acme/platform-infra" &&
  principal.hasTag("cognito:groups") &&
  principal.getTag("cognito:groups") like "*\\"platform\\"*"
};` } },
    });
    // The role's permissions are a separate IAM::Policy resource. Without this, CloudFormation may create
    // the Gateway first and the engine attach fails with "Access denied while calling GetPolicyEngine".
    const rolePolicy = gwRole.node.findChild('DefaultPolicy').node.defaultChild as cdk.CfnResource;
    for (const g of [open, guarded]) g.addResourceDependency(rolePolicy);
    for (const p of [docsPolicy, platformPolicy]) {
      p.addResourceDependency(guarded); p.addResourceDependency(guardedTarget); // policy validation calls the gateway
    }
    void openTarget;

    new cdk.CfnOutput(this, 'Region', { value: this.region });
    new cdk.CfnOutput(this, 'UserPoolId', { value: pool.userPoolId });
    new cdk.CfnOutput(this, 'ClientId', { value: client.userPoolClientId });
    new cdk.CfnOutput(this, 'OpenGatewayUrl', { value: open.attrGatewayUrl });
    new cdk.CfnOutput(this, 'GuardedGatewayUrl', { value: guarded.attrGatewayUrl });
    new cdk.CfnOutput(this, 'LedgerTable', { value: ledger.tableName });
    new cdk.CfnOutput(this, 'FunctionName', { value: fn.functionName });
  }
}
