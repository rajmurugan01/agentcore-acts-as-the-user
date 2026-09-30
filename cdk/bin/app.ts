import * as cdk from 'aws-cdk-lib';
import { ActsAsUserStack } from '../lib/stack';

const app = new cdk.App();
new ActsAsUserStack(app, 'AgentcoreActsAsUser', {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.DEMO_REGION ?? 'us-east-1' },
});
