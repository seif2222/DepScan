import { existsSync } from 'node:fs';
import { join } from 'node:path';

export function exists(dir: string): boolean {
  return existsSync(join(dir, 'package.json'));
}
