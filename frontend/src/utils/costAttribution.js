/**
 * Weighted cost attribution for AWS Clarity.
 *
 * Maps AWS Cost Explorer service names to resource types with weights.
 * Weight 0 = resource is free, never attributed costs.
 * Weight > 0 = attributed proportional to weight × resource count.
 *
 * When multiple resources of the same type exist, their weight's total
 * is divided equally among them.
 *
 * Example:
 *   VPC service cost: $32 (from 1 NAT Gateway)
 *   Resources: 1 NAT Gateway (weight 95) + 2 VPCs (weight 0) + 1 IGW (weight 0)
 *   Total weighted units: 95 × 1 = 95
 *   NAT Gateway gets: (95/95) × $32 = $32.00
 *   Each VPC gets: $0.00
 *   IGW gets: $0.00
 */
export const CE_SERVICE_WEIGHTS = {
  "Amazon Elastic Compute Cloud - Compute": {
    ec2_instance: 100,
  },
  "Amazon EC2 - Other": {
    ebs_volume: 55,     // EBS storage is the main EC2-Other cost
    elastic_ip: 35,     // Unattached EIPs cost $0.005/hour
    snapshot: 10,       // Snapshots are cheap but non-zero
  },
  "Amazon Simple Storage Service": {
    s3_bucket: 100,     // Equally split across buckets (best we can do without resource-level CE)
  },
  "Amazon Relational Database Service": {
    rds_instance: 100,
  },
  "Amazon Aurora MySQL": {
    aurora_cluster: 100,
  },
  "Amazon Aurora PostgreSQL": {
    aurora_cluster: 100,
  },
  "AWS Lambda": {
    lambda_function: 100,
  },
  "Amazon DynamoDB": {
    dynamodb_table: 100,
  },
  "Amazon Virtual Private Cloud": {
    nat_gateway: 95,      // NAT Gateways are almost all VPC costs ($0.045/hour)
    vpc: 0,               // VPCs are free
    internet_gateway: 0,  // IGWs are free
    elastic_ip: 5,        // Small contribution from attached EIPs
  },
  "Amazon API Gateway": {
    api_gateway: 100,
  },
  "AWS Secrets Manager": {
    secret: 100,
  },
  "Amazon ElastiCache": {
    elasticache_cluster: 100,
  },
  "Amazon Elastic Container Service": {
    ecs_cluster: 100,
  },
  "Amazon Elastic Kubernetes Service": {
    eks_cluster: 100,
  },
  "Amazon Redshift": {
    redshift_cluster: 100,
  },
  "Amazon Simple Queue Service": {
    sqs_queue: 100,
  },
  "Amazon Simple Notification Service": {
    sns_topic: 100,
  },
  "Amazon CloudWatch": {
    cloudwatch_alarm: 100,
  },
  "AWS CloudFormation": {
    cloudformation_stack: 100,
  },
  "Amazon Elastic Container Registry": {
    ecr_repository: 100,
  },
  "Amazon EventBridge": {
    eventbridge_rule: 100,
  },
  "Elastic Load Balancing": {
    load_balancer: 100,
  },
  "Amazon EC2 Auto Scaling": {
    auto_scaling_group: 100,
  },
};


/**
 * Attribute CE service costs to individual scanned resources.
 *
 * @param {Array} allResources - flat array of all scanned resources, each with .id, .name, .type
 * @param {Object} costData - the costs object from the scan response
 * @returns {Map} resource.id → {
 *   amount: number | null,     // attributed cost in USD, null = no matching CE service
 *   isShared: boolean,         // true = split across multiple resources of this type
 *   sharedCount: number,       // how many resources share this cost
 *   serviceName: string | null // which CE service this cost came from
 * }
 */
export const attributeCosts = (allResources, costData) => {
  const result = new Map();
  const byService = {
    ...(costData?.by_service ?? {}),
    ...(costData?.by_service_global ?? {}),
  };

  if (!allResources?.length || !Object.keys(byService).length) {
    // No resources or no cost data — all resources get null
    allResources?.forEach(r => result.set(r.id, {
      amount: null, isShared: false, sharedCount: 0, serviceName: null,
    }));
    return result;
  }

  // Build a map: resource.id → attributed cost info
  // Pass 1: for each CE service, compute weighted attribution
  const resourceCosts = new Map(); // resource.id → {amount, serviceName}

  Object.entries(byService).forEach(([serviceName, serviceAmount]) => {
    const weights = CE_SERVICE_WEIGHTS[serviceName];
    if (!weights) return; // service not in our mapping — skip

    // Find all scanned resources that match this service (weight > 0 only)
    const eligibleResources = allResources.filter(r => (weights[r.type] ?? 0) > 0);
    if (!eligibleResources.length) return;

    // Calculate total weighted units
    // Weight × count for each resource type
    const typeGroups = {};
    eligibleResources.forEach(r => {
      const w = weights[r.type];
      if (!typeGroups[r.type]) typeGroups[r.type] = { weight: w, resources: [] };
      typeGroups[r.type].resources.push(r);
    });

    const totalWeightedUnits = Object.values(typeGroups).reduce(
      (sum, { weight, resources }) => sum + weight * resources.length,
      0
    );
    if (totalWeightedUnits === 0) return;

    // Distribute cost proportionally
    Object.values(typeGroups).forEach(({ weight, resources }) => {
      const typeShare = (weight * resources.length) / totalWeightedUnits;
      const perResource = (serviceAmount * typeShare) / resources.length;

      resources.forEach(resource => {
        const existing = resourceCosts.get(resource.id);
        resourceCosts.set(resource.id, {
          amount: (existing?.amount ?? 0) + perResource,
          serviceName: existing?.serviceName
            ? `${existing.serviceName}, ${serviceName}`
            : serviceName,
          isShared: resources.length > 1,
          sharedCount: resources.length,
        });
      });
    });
  });

  // Pass 2: apply to all resources
  allResources.forEach(resource => {
    const cost = resourceCosts.get(resource.id);
    if (cost) {
      result.set(resource.id, {
        amount: Math.round(cost.amount * 10000) / 10000, // 4 decimal places
        isShared: cost.isShared,
        sharedCount: cost.sharedCount,
        serviceName: cost.serviceName,
      });
    } else {
      // Resource has no matching CE service or weight is 0 (free resource)
      result.set(resource.id, {
        amount: null,
        isShared: false,
        sharedCount: 0,
        serviceName: null,
      });
    }
  });

  return result;
};
