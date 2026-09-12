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
 * Cost Status Taxonomy:
 * - ACTUAL: Direct resource-level or 1-to-1 exact service mapping.
 * - ESTIMATED: Proportional weighted allocation of service-level totals.
 * - UNALLOCATED: Real AWS service charges that cannot be attributed to discovered resources.
 * - ZERO: Discovered resource with no attributable charge ($0.00).
 *
 * @param {Array} allResources - flat array of all scanned resources, each with .id, .name, .type
 * @param {Object} costData - the costs object from the scan response
 * @returns {Object} {
 *   resourceCostMap: Map(resource.id -> { amount, status, isShared, sharedCount, serviceName, attributionMethod, source }),
 *   reconciliation: { totalAccountCost, directResourceCost, estimatedResourceCost, unallocatedCost, zeroCostResourceCount, unallocatedServices }
 * }
 */
export const attributeCosts = (allResources, costData) => {
  const result = new Map();
  const byService = costData?.by_service ?? {};
  const totalAccountCost = costData?.total_current_month ?? 0;

  const reconciliation = {
    totalAccountCost,
    directResourceCost: 0,
    estimatedResourceCost: 0,
    unallocatedCost: 0,
    zeroCostResourceCount: 0,
    unallocatedServices: [],
  };

  if (!allResources || !allResources.length) {
    Object.entries(byService).forEach(([serviceName, amount]) => {
      reconciliation.unallocatedCost += amount;
      reconciliation.unallocatedServices.push({
        serviceName,
        amount,
        reason: "No discovered resources in scanned region",
      });
    });
    return { resourceCostMap: result, reconciliation };
  }

  const resourceCosts = new Map();
  const allocatedServiceAmounts = {};

  Object.entries(byService).forEach(([serviceName, serviceAmount]) => {
    const weights = CE_SERVICE_WEIGHTS[serviceName];
    if (!weights) {
      reconciliation.unallocatedCost += serviceAmount;
      reconciliation.unallocatedServices.push({
        serviceName,
        amount: serviceAmount,
        reason: "Service not mapped to scanned resource types",
      });
      return;
    }

    const eligibleResources = allResources.filter(r => (weights[r.type] ?? 0) > 0);
    if (!eligibleResources.length) {
      reconciliation.unallocatedCost += serviceAmount;
      reconciliation.unallocatedServices.push({
        serviceName,
        amount: serviceAmount,
        reason: "No matching resources discovered for service in scanned region",
      });
      return;
    }

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

    if (totalWeightedUnits === 0) {
      reconciliation.unallocatedCost += serviceAmount;
      reconciliation.unallocatedServices.push({
        serviceName,
        amount: serviceAmount,
        reason: "Discovered resources for service have zero weighting",
      });
      return;
    }

    let serviceAllocated = 0;
    Object.values(typeGroups).forEach(({ weight, resources }) => {
      const typeShare = (weight * resources.length) / totalWeightedUnits;
      const perResource = (serviceAmount * typeShare) / resources.length;

      const byResource = costData?.by_resource ?? {};

      resources.forEach(resource => {
        const directAmount = byResource[resource.id];
        const hasDirectEvidence = (directAmount !== undefined && directAmount !== null);

        const status = hasDirectEvidence ? "ACTUAL" : "ESTIMATED";
        const resourceAmount = hasDirectEvidence ? directAmount : perResource;

        const existing = resourceCosts.get(resource.id);
        const newAmount = (existing?.amount ?? 0) + resourceAmount;
        serviceAllocated += resourceAmount;

        resourceCosts.set(resource.id, {
          amount: newAmount,
          status: hasDirectEvidence ? "ACTUAL" : "ESTIMATED",
          isShared: !hasDirectEvidence && (resources.length > 1 || eligibleResources.length > 1),
          sharedCount: resources.length,
          serviceName: existing?.serviceName
            ? `${existing.serviceName}, ${serviceName}`
            : serviceName,
          attributionMethod: hasDirectEvidence
            ? "Direct AWS resource-level line item"
            : `Proportional weighted allocation (÷${resources.length})`,
          source: hasDirectEvidence ? "AWS Cost Explorer (Resource-Level)" : "AWS Clarity Defensible Allocation",
        });
      });
    });

    allocatedServiceAmounts[serviceName] = serviceAllocated;
  });

  allResources.forEach(resource => {
    const cost = resourceCosts.get(resource.id);
    if (cost && cost.amount > 0.000001) {
      const roundedAmount = Math.round(cost.amount * 10000) / 10000;
      result.set(resource.id, {
        amount: roundedAmount,
        status: cost.status,
        isShared: cost.isShared,
        sharedCount: cost.sharedCount,
        serviceName: cost.serviceName,
        attributionMethod: cost.attributionMethod,
        source: cost.source,
      });

      if (cost.status === "ACTUAL") {
        reconciliation.directResourceCost += roundedAmount;
      } else {
        reconciliation.estimatedResourceCost += roundedAmount;
      }
    } else {
      result.set(resource.id, {
        amount: 0.0,
        status: "ZERO",
        isShared: false,
        sharedCount: 0,
        serviceName: null,
        attributionMethod: "No attributable AWS charge found for resource",
        source: "AWS Cost Explorer",
      });
      reconciliation.zeroCostResourceCount += 1;
    }
  });

  reconciliation.directResourceCost = Math.round(reconciliation.directResourceCost * 100) / 100;
  reconciliation.estimatedResourceCost = Math.round(reconciliation.estimatedResourceCost * 100) / 100;
  reconciliation.unallocatedCost = Math.round(reconciliation.unallocatedCost * 100) / 100;

  return { resourceCostMap: result, reconciliation };
};

