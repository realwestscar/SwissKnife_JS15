const DURATION_PATTERN = /^(\d+)(s|m|h|d)$/i;

const UNIT_TO_SECONDS: Record<string, number> = {
  s: 1,
  m: 60,
  h: 60 * 60,
  d: 60 * 60 * 24,
};

export function durationToSeconds(duration: string): number {
  const match = duration.match(DURATION_PATTERN);
  if (!match) {
    throw new Error(`Invalid duration format: ${duration}. Expected formats like 15m, 7d.`);
  }

  const value = Number(match[1]);
  const unit = match[2].toLowerCase();
  return value * UNIT_TO_SECONDS[unit];
}

export function durationToMs(duration: string): number {
  return durationToSeconds(duration) * 1000;
}
