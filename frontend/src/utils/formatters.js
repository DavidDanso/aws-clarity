const ROLE_ARN_REGEX = /^arn:aws:iam::\d{12}:role\/[\w+=,.@-]+$/;

export function validateRoleArn(arn) {
  return ROLE_ARN_REGEX.test(arn);
}

export function maskAccountId(accountId) {
  if (!accountId || accountId.length < 4) return "****";
  return "****" + accountId.slice(-4);
}

export function formatTimestamp(isoString) {
  if (!isoString) return "";
  const date = new Date(isoString);
  return date.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });
}

export function formatCost(amount) {
  if (amount === null || amount === undefined) return "—";
  if (amount < 0.01) return "< $0.01";
  if (amount >= 1000) return `$${(amount / 1000).toFixed(2)}k`;
  return `$${amount.toFixed(2)}`;
}

/**
 * Attributes CE service-level costs to individual resources.
 *
 * For each scanned resource:
 * - If CE resource-level data exists → use exact amount
 * - If only service-level data exists → divide service cost equally
 *   among all resources of matching types
 *
 * Returns a Map of resource.id → {
 *   amount: number | null,
 *   isExact: boolean,       // true = from CE resource-level, false = shared estimate
 *   sharedCount: number,    // 1 means sole owner of cost, >1 means shared
 *   serviceName: string,    // which CE service this came from
 * }
 */
export const attributeCosts = (allResources, costData, ceServiceToResourceTypes) => {
  const result = new Map();
  const byService = costData?.by_service ?? {};
  const byResource = costData?.by_resource ?? {};
  const resourceLevelEnabled = costData?.resource_level_enabled ?? false;

  // If resource-level CE is enabled — use exact amounts
  if (resourceLevelEnabled && Object.keys(byResource).length > 0) {
    allResources.forEach(resource => {
      const exactCost = byResource[resource.id] ?? byResource[resource.name] ?? null;
      result.set(resource.id, {
        amount: exactCost,
        isExact: true,
        sharedCount: 1,
        serviceName: null,
      });
    });
    return result;
  }

  // Service-level attribution — build reverse map: resource type → service cost
  const typeToServiceCost = new Map();
  Object.entries(ceServiceToResourceTypes).forEach(([serviceName, resourceTypes]) => {
    const serviceCost = byService[serviceName] ?? 0;
    if (serviceCost > 0) {
      resourceTypes.forEach(rType => {
        const existing = typeToServiceCost.get(rType);
        typeToServiceCost.set(rType, {
          cost: (existing?.cost ?? 0) + serviceCost,
          serviceName,
        });
      });
    }
  });

  // Count resources per type that have a matching service cost
  const typeCount = new Map();
  allResources.forEach(resource => {
    if (typeToServiceCost.has(resource.type)) {
      typeCount.set(resource.type, (typeCount.get(resource.type) ?? 0) + 1);
    }
  });

  // Attribute costs to each resource
  allResources.forEach(resource => {
    const serviceData = typeToServiceCost.get(resource.type);
    if (!serviceData || serviceData.cost === 0) {
      result.set(resource.id, { amount: null, isExact: false, sharedCount: 0, serviceName: null });
      return;
    }
    const count = typeCount.get(resource.type) ?? 1;
    result.set(resource.id, {
      amount: serviceData.cost / count,
      isExact: false,
      sharedCount: count,
      serviceName: serviceData.serviceName,
    });
  });

  return result;
};

