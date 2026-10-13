import { randomBytes, scryptSync } from 'node:crypto';
let input = '';
for await (const chunk of process.stdin) input += chunk;
const salt = randomBytes(16).toString('hex');
process.stdout.write(`${salt}:${scryptSync(input.trimEnd(), salt, 64).toString('hex')}\n`);
