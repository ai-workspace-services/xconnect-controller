export interface RenderWranglerResult {
  toml: string;
  hyperdriveConfigured: boolean;
}

export function renderWranglerConfig(
  rawToml: string,
  hyperdriveId?: string,
): RenderWranglerResult;
